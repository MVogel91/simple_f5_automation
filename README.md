# A simple client for F5 automation
## Current modules
* show_bigips
    Displays all hosts affected by current inventory/hosts
* update_irule
    Creates a backup of named irule as ${irule}_backup and updates iRule to text from given File

## How to use
* define an inventory similar to Ansible in inventory/hosts.yaml; nesting groups is not supported

### Example inventory
```
f5_all:
  hosts:
    bigip-prod-01
    bigip-prod-02
    bigip-qa-01
    bigip-qa-02
f5_prod:
  hosts:
    bigip-prod-01
    bigip-prod-02
f5_qa:
  hosts:
    bigip-qa-01
    bigip-qa-02
```
