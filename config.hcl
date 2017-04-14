mounts = [{
  path = "example/app1"
  config = {
    type = "generic"
    description = "Example App 1"
    mountconfig = {
      default_lease_ttl = "20h"
      max_lease_ttl = "768h"
    }
  }
},{
  path = "example/app2"
  config = {
    type = "generic"
    description = "Example App 2"

  }
}]

policies = [{
  name = "example-policy-1"
  rules =<<EOF
# Allow to make changes to /example/app1 mount
path "example/app1" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
},{
  name = "example-policy-2"
  rules =<<EOF
# Allow to make changes to /example/app2 mount
path "example/app2" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
}]

auth = [{
  type = "ldap"
  authconfig = {
    url = "ldap://10.255.0.30"
    binddn = "CN=SamE,CN=Users,DC=test,DC=local"
    bindpass = "z"
    userdn = "CN=Users,DC=test,DC=local"
  }
  users = [{
      name = "same"
      options = {
        policies = "example-policy-1,example-policy-2"
      }
    }
  ]
  mountconfig {
    default_lease_ttl = "1h"
    max_lease_ttl = "24h"
  }
}]