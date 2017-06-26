# Vault Configuration Tool

As a long time user of Vault, there is one thing that I have always found a bit of an issue, Vault feels like a  codifying build configuration. it is possible to do this as documented in this [blog](https://www.hashicorp.com/blog/codifying-vault-policies-and-configuration/). After reading this I decided that method did not meet  my requirements, which were:
- All configuration in one file
- Use HCL to make configuration more readable
- Ability to Encrypt/Decrypt configuration files

###Resources
####Policy
This resource will configure vault policies
#####Argument reference
- `rules` - The policy definition
#####Example Usage
```hcl
policy "example-policy-1" {
  rules =<<EOF
# Allow to make changes to /example/app1 mount
path "example/app1" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
}
```

####Mount
#####Argument Reference
- `path` - Vault path for mount
- `config` - Configuration options for the mount
    - `type` - Type of mount
    - `description` - Description for mount
- `mountconfig` - Mount configuration options
    - `default_lease_ttl` - Default lease TTL for mount
    - `max_lease_ttl` - Max lease TTL for mount
#####Example
```hcl
mount "app1" {
  path = "example/app1"
  config = {
    type = "generic"
    description = "Example App 1"
  }
  mountconfig {
    default_lease_ttl = "20h"
    max_lease_ttl = "768h"
  }
}
```

####Token Role
#####Argument Reference
Name is picked up from the HCL object key
- `options` - A map of configuration options for the token role
#####Example
```hcl
token_role "example_period_token_role" {
  options {
    allowed_policies = "example-policy-1,example-policy-2"
    period = 20
    renewable = true
  }
}
```
####Auth
Currently Auth has support for LDAP and Github
#####Argument Reference
- `ldap` - Configures Ldap auth backend
    - `description` - Description for the backend
    - `authconfig` - Map of options for hte auth backend
    - `user` - Configure user mapping
        - `options` - Map of options for the user, most commonly policy
    - `group` - Configure group mapping
        - `options` - Map of options for the group, most commonly policy
    - `mountconfig` - Lease settings for Ldap backend
        - `default_lease_ttl` - Default lease TTL as time duration
        - `max_lease_ttl` - Max lease TTL as time duration
- `github` - Configures Github backend
    - `description` - Description for the backend
    - `authconfig` - Map of options for hte auth backend
    - `user` - Configure user mapping
        - `options` - Map of options for the user, most commonly policy
    - `teams` - Configure team mapping
        - `options` - Map of options for the group, most commonly policy
    - `mountconfig` - Lease settings for Github backend
        - `default_lease_ttl` - Default lease TTL as time duration
        - `max_lease_ttl` - Max lease TTL as time duration
#####Example
```hcl
auth {
  ldap {
    description = "LDAP Auth backend config"
    authconfig {
      binddn = "CN=SamE,CN=Users,DC=test,DC=local"
      bindpass = "z"
      url = "ldap://10.255.0.30"
      userdn = "CN=Users,DC=test,DC=local"
    }
    group "groupa" {
      options {
        policies = "example-policy-1"
      }
    }
    user "same" {
      options {
        policies = "example-policy-1,example-policy-2"
      }
    }
    mountconfig {
      default_lease_ttl = "1h"
      max_lease_ttl = "24h"
    }
  }
  github {
    authconfig = {
      organization = "testorg"
    }
  }
}
```



Below is a example configuration, that configures some mounts, policies and an LDAP auth backend, this is currently all I have tested this with as this is all I need to configure for my environment.
  
```hcl
mount "app1" {
  path = "example/app1"
  config = {
    type = "generic"
    description = "Example App 1"
  }
  mountconfig {
    default_lease_ttl = "20h"
    max_lease_ttl = "768h"
  }
}

mount "pki" {
  path = "pki"
  config = {
    type = "pki"
    description = "My cool PKI backend"
  }
  mountconfig {
    default_lease_ttl = "768h"
    max_lease_ttl = "768h"
  }
}

mount "app2" {
  path = "example/app2"
  config = {
    type = "generic"
    description = "Example App 2"
  }
  mountconfig {
    default_lease_ttl = "1h"
    max_lease_ttl = "24h"
  }
}


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

token_role "example_period_token_role" {
  options {
    allowed_policies = "example-policy-1,example-policy-2"
    period = 20
    renewable = true
  }
}

auth {
  ldap {
    description = "LDAP Auth backend config"
    authconfig {
      binddn = "CN=SamE,CN=Users,DC=test,DC=local"
      bindpass = "z"
      url = "ldap://10.255.0.30"
      userdn = "CN=Users,DC=test,DC=local"
    }
    group "groupa" {
      options {
        policies = "example-policy-1"
      }
    }
    user "same" {
      options {
        policies = "example-policy-1,example-policy-2"
      }
    }
    mountconfig {
      default_lease_ttl = "1h"
      max_lease_ttl = "24h"
    }
  }
  github {
    authconfig = {
      organization = "testorg"
    }
  }
}
```

This tool also includes file encryption that will allow you to encrypt the config files if they include sensitive information, this uses AES-256 CFB encryption and HMAC authenticaion from the Golang crypto library. This requires a 32 byte password that can be automatically generated if required.