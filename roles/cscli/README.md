# lingfish.crowdsec.cscli

Manage CrowdSec with `cscli`. It currently manages centralized allowlists with the
`lingfish.crowdsec.allowlist` module.

Run it on the host running the CrowdSec Local API. `cscli` writes allowlists directly to the CrowdSec
database, so changes only work there.

## Requirements

- CrowdSec 1.6.8 or later on the target host
- Root privileges (`become: true`) to run `cscli`

## Role variables

| Variable | Default | Description |
|---|---|---|
| `cscli_allowlists` | `[]` | Allowlists to manage; each item takes the module's `name`, `description`, `state`, `entries` and `exclusive` options |
| `cscli_allowlists_exclusive` | `true` | Default for each allowlist's `exclusive` option: remove entries that aren't listed |
| `cscli_path` | `cscli` | Name or path of the `cscli` binary |
| `cscli_config` | unset | CrowdSec config file passed to `cscli --config` |

Allowlists that aren't listed in `cscli_allowlists` are left alone.

## Example playbook

```yaml
- name: Manage CrowdSec
  hosts: crowdsec_lapi
  become: true
  roles:
    - role: lingfish.crowdsec.cscli
      vars:
        cscli_allowlists:
          - name: infra
            description: Infrastructure addresses
            entries:
              - value: 203.0.113.0/24
                comment: office
              - value: 192.0.2.50
                comment: pentest
                expiration: 7d
          - name: old
            state: absent
```

See `ansible-doc lingfish.crowdsec.allowlist` for how entries are matched and updated.

## License

GPL-3.0-or-later
