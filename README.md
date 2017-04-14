# Vault Configuration Tool

As a long time user of Vault, there is one thing that I have always found a bit of an issue, Vault feels like a  codifying build configuration. it is possible to do this as documented in this [blog](https://www.hashicorp.com/blog/codifying-vault-policies-and-configuration/). After reading this I decided that method did not meet  my requirements, which were:
- All configuration in one file
- Use HCL to make configuration more readable
- Ability to Encrypt/Decrypt configuration files

Below is an example configuration, that configures some mounts, policies and an LDAP auth backend, this is currently all I have tested this with as this is all I need to configure for my environment.
  

```hcl
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
```

This tool also includes file encryption that will allow you to encrypt the config files if they include sensitive information, this uses AES-256 CFB encryption and HMAC authenticaion from the Golang crypto library. This requires a 32 byte password that can be automatically generated if required