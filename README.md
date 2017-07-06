# Vault Configuration Tool

As a long time user of Vault, there is one thing that I have always found a bit of an issue, Vault configuation is very manual and snowflake like it would be better to codify build configuration. it is possible to do this as documented in this [blog](https://www.hashicorp.com/blog/codifying-vault-policies-and-configuration/). After reading this I decided that method did not meet  my requirements, which were:
- All configuration in one file
- Use HCL to make configuration more readable
- Ability to Encrypt/Decrypt configuration files

Vault configuration for this tool will use the following environment variables
- VC_VAULT_ADDR - Address of Vault server to update
- VC_VAULT_TOKEN - Token for authentication to Vault
- VC_VAULT_SKIP_VERIFY - (Optional) Ignore SSL cert errors

The default Vault variables can also be configured and will be used for getting secret information from an existing Vault server, see template section for more information

### Resources
#### Secret
This resource will add secrets to the vault server
##### Argument reference
- `path` - Path to the secret
- `data` - Map of the data to be stored in the secret
##### Example
```hcl
secret "test" {
  path = "/example/app1/test"
  data {
    value = "test_data"
  }
}
```

### Policy
This resource will configure vault policies
#### Argument reference
- `rules` - The policy definition
##### Example Usage
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

### Mount
#### Argument Reference
- `path` - Vault path for mount
- `config` - Configuration options for the mount
    - `type` - Type of mount
    - `description` - Description for mount
- `mountconfig` - Mount configuration options
    - `default_lease_ttl` - Default lease TTL for mount
    - `max_lease_ttl` - Max lease TTL for mount
##### Example
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

### Token Role
#### Argument Reference
Name is picked up from the HCL object key
- `options` - A map of configuration options for the token role
##### Example
```hcl
token_role "example_period_token_role" {
  options {
    allowed_policies = "example-policy-1,example-policy-2"
    period = 20
    renewable = true
  }
}
```
### Auth
Currently Auth has support for LDAP and Github
#### Argument Reference
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
##### Example
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

### Template engine
This tool supports templating in config files, this will allow substitution and also copying secrets from another Vault server. All interpolation will only be held in memory and will not be written to disk

All variables to be used within templates should be placed in the `vault-config.vc` file and should use the following format
```hcl
foo = "bar"
testkey = "testvar"
```

#### Template functions
There are two template function available
##### Lookup
This will use the variables loaded and interpolate them into a script
e.g.
```hcl
mount "app2" {
  path = "{{ Lookup "foo" }}/app1"
  config {
    type = "generic"
    description = "Example App 1"
    mountconfig {
      default_lease_ttl = "1h"
      max_lease_ttl = "24h"
    }
  }
}
```
With the vars file above will result in the following
```hcl
mount "app2" {
  path = "bar/secret"
  config {
    type = "generic"
    description = "Example App 2"
    mountconfig {
      default_lease_ttl = "1h"
      max_lease_ttl = "24h"
    }
  }
}
```
##### LookupSecret
This will use lookup a secret from your default Vault server and then create that secret in your target Vault server, this takes two parameters. The mounts used by this should exist on the target server already
 - Path of secret to lookup
 - Optional parameter allowing you to change path on target server
 
e.g.
```text
{{ LookupSecret "secret/foo" }}

{{ LookupSecret "secret/bar" "alternate/path/bar" }}
```


This tool also includes file encryption that will allow you to encrypt the config files if they include sensitive information, this uses AES-256 CFB encryption and HMAC authenticaion from the Golang crypto library. This requires a 32 byte password that can be automatically generated if required.