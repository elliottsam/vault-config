policy "example-policy-1" {
  rules =<<EOF
# Allow to make changes to /example/app1 mount
path "example/app1" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
}

policy "example-policy-2" {
  rules =<<EOF
# Allow to make changes to /example/app2 mount
path "example/app2" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
}
