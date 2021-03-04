# POC: Integration with Conftest

## Starboard CLI

```
kubectl create configmap policies \
  --from-file policy/kubernetes.rego \
  --from-file policy/uses_image_tag_latest.rego \
  --from-file policy/file_system_not_read_only.rego \
  --namespace starboard
```

```
kubectl patch cm starboard -n starboard \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "configAuditReports.scanner": "Conftest"
  }
}
EOF
)"
```

## Starboard Operator

```
kubectl create configmap policies \
  --from-file policy/kubernetes.rego \
  --from-file policy/uses_image_tag_latest.rego \
  --from-file policy/file_system_not_read_only.rego \
  --namespace starboard-operator
```

```
kubectl patch cm starboard -n starboard-operator \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "configAuditReports.scanner": "Conftest"
  }
}
EOF
)"
```
