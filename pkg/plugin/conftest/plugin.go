package conftest

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	conftestContainerName = "conftest"
)

type Config interface {
	GetConftestImageRef() (string, error)
}

type plugin struct {
	idGenerator ext.IDGenerator
	clock       ext.Clock
	config      Config
}

// NewPlugin constructs a new configauditreport.Plugin, which is using an
// official Conftest container image to audit Kubernetes workloads.
func NewPlugin(clock ext.Clock, config Config) configauditreport.Plugin {
	return &plugin{
		idGenerator: ext.NewGoogleUUIDGenerator(),
		clock:       clock,
		config:      config,
	}
}

func (p *plugin) GetScanJobSpec(workload kube.Object, obj client.Object, gvk schema.GroupVersionKind) (corev1.PodSpec, []*corev1.Secret, error) {
	imageRef, err := p.config.GetConftestImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	var secrets []*corev1.Secret

	// TODO This is a workaround to set GVK and serialize to YAML properly
	obj.GetObjectKind().SetGroupVersionKind(gvk)

	workloadAsYAML, err := yaml.Marshal(obj)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.idGenerator.GenerateID(),
		},
		StringData: map[string]string{
			"workload.yaml": string(workloadAsYAML),
		},
	}

	secrets = append(secrets, secret)

	return corev1.PodSpec{
		ServiceAccountName:           starboard.ServiceAccountName,
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		Affinity:                     starboard.LinuxNodeAffinity(),
		Volumes: []corev1.Volume{
			{
				Name: "policies",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "policies",
						},
					},
				},
			},
			{
				Name: secret.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secret.Name,
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     conftestContainerName,
				Image:                    imageRef,
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					// Mount policy files (Rego scripts)
					{
						Name:      "policies",
						MountPath: "/project/policy/kubernetes.rego",
						SubPath:   "kubernetes.rego",
					},
					{
						Name:      "policies",
						MountPath: "/project/policy/uses_image_tag_latest.rego",
						SubPath:   "uses_image_tag_latest.rego",
					},
					{
						Name:      "policies",
						MountPath: "/project/policy/file_system_not_read_only.rego",
						SubPath:   "file_system_not_read_only.rego",
					},
					// Mount workload file
					{
						Name:      secret.Name,
						MountPath: "/project/workload.yaml",
						SubPath:   "workload.yaml",
					},
				},
				Command: []string{"sh"},
				Args: []string{
					"-c",
					"conftest test --output json /project/workload.yaml || true",
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				},
			},
		},
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(1000),
			RunAsGroup: pointer.Int64Ptr(1000),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
	}, secrets, nil

}

func (p *plugin) GetContainerName() string {
	return conftestContainerName
}

const (
	defaultCategory = "Security"
)

func (p *plugin) ParseConfigAuditResult(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error) {
	var checkResults []CheckResult
	err := json.NewDecoder(logsReader).Decode(&checkResults)

	var checks []v1alpha1.Check
	var warningCount, dangerCount int

	for _, cr := range checkResults {

		for i, warning := range cr.Warnings {
			checks = append(checks, v1alpha1.Check{
				ID:       fmt.Sprintf("warning %d", i), // TODO Use policy ID / script ID
				Severity: "WARNING",
				Message:  warning.Message,
				Category: defaultCategory,
			})
			warningCount++
		}

		for i, failure := range cr.Failures {
			checks = append(checks, v1alpha1.Check{
				ID:       fmt.Sprintf("failure %d", i), // TODO Use policy ID / script ID
				Severity: "DANGER",
				Message:  failure.Message,
				Category: defaultCategory,
			})
			dangerCount++
		}
	}

	imageRef, err := p.config.GetConftestImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	return v1alpha1.ConfigAuditResult{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Conftest",
			Vendor:  "Open Policy Agent",
			Version: version,
		},
		Summary: v1alpha1.ConfigAuditSummary{
			PassCount:    0, // TODO This should be a pointer to tell 0 from nil
			WarningCount: warningCount,
			DangerCount:  dangerCount,
		},
		PodChecks:       checks,
		ContainerChecks: map[string][]v1alpha1.Check{},
	}, nil
}
