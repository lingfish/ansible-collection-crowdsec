# Ansible Collection: lingfish.crowdsec

[![CI](https://github.com/lingfish/ansible-collection-crowdsec/actions/workflows/ci.yml/badge.svg)](https://github.com/lingfish/ansible-collection-crowdsec/actions/workflows/ci.yml)
[![Ansible Galaxy](https://img.shields.io/badge/galaxy-lingfish.crowdsec-blue.svg)](https://galaxy.ansible.com/ui/repo/published/lingfish/crowdsec/)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](COPYING)

Manage [CrowdSec](https://www.crowdsec.net/) with `cscli`. It currently manages
[centralized allowlists](https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists/).

| Name | Type | Description |
|---|---|---|
| `lingfish.crowdsec.allowlist` | module | Manage a centralized allowlist and its entries |
| `lingfish.crowdsec.cscli` | role | Manage the allowlists in `cscli_allowlists` with the module |

## Requirements

- ansible-core 2.18 or later
- CrowdSec 1.6.8 or later on the target host

**Run on the Local API host.** `cscli` only reads allowlists through the Local API. It writes them
directly to the CrowdSec database, so creating or changing allowlists only works on the machine running
the LAPI. Target that host, or use `delegate_to`.

## Installation

```bash
ansible-galaxy collection install lingfish.crowdsec
```

Or in `requirements.yml`:

```yaml
collections:
  - name: lingfish.crowdsec
```

## Module: `lingfish.crowdsec.allowlist`

```yaml
- name: Allowlist office and monitoring addresses
  lingfish.crowdsec.allowlist:
    name: infra
    description: Infrastructure addresses
    entries:
      - value: 203.0.113.0/24
        comment: office
      - value: 198.51.100.7
        comment: monitoring
      - value: 192.0.2.50
        comment: pentest
        expiration: 7d
```

How it behaves:

- **Exclusive by default.** Entries not in `entries` are removed. Set `exclusive: false` to only add and update.
- **Exact values.** Entries are matched on the exact string, so `192.0.2.1` and `192.0.2.1/32` are different entries.
- **Updates are remove + add.** `cscli` can't change an entry in place, so an entry whose comment or
  expiration differs is removed and added again. It's briefly not allowlisted while that happens.
- **Expirations are relative and set once.** `expiration: 7d` applies when the entry is added. Later runs leave
  the entry alone while it is still valid, and add it again once it has expired.
- **Descriptions can't be changed.** `cscli` has no command for it, so a different `description` on an existing
  allowlist only produces a warning.
- **Console-managed allowlists are read-only.** The module fails rather than change one.
- **Check and diff mode** are fully supported. The `commands` return value lists the `cscli` commands that
  were (or would be) run.

Run `ansible-doc lingfish.crowdsec.allowlist` for the full documentation.

## Role: `lingfish.crowdsec.cscli`

```yaml
- name: Manage CrowdSec
  hosts: crowdsec_lapi
  roles:
    - role: lingfish.crowdsec.cscli
      vars:
        cscli_allowlists:
          - name: infra
            description: Infrastructure addresses
            entries:
              - value: 203.0.113.0/24
                comment: office
          - name: old
            state: absent
```

| Variable | Default | Description |
|---|---|---|
| `cscli_allowlists` | `[]` | Allowlists to manage; each item takes the module's `name`, `description`, `state`, `entries` and `exclusive` options |
| `cscli_allowlists_exclusive` | `true` | Default for each allowlist's `exclusive` option |
| `cscli_path` | `cscli` | Name or path of the `cscli` binary |
| `cscli_config` | unset | CrowdSec config file passed to `cscli --config` |

Allowlists that aren't listed in `cscli_allowlists` are left alone.

## Development

```bash
# Lint
yamllint .
ansible-lint

# Sanity and unit tests (the checkout must be at ansible_collections/lingfish/crowdsec)
ansible-test sanity --venv
ansible-test units --venv

# Integration tests against a CrowdSec container (docker or podman)
tests/integration/run.sh v1.8.2
```

### Releasing

1. Bump `version` in `galaxy.yml` and add a section to `CHANGELOG.md`.
2. Publish a GitHub release tagged `v<version>`. CI checks the tag matches `galaxy.yml`, runs the tests,
   and publishes to Galaxy with the `GALAXY_API_KEY` secret.

## License

GPL-3.0-or-later. See [COPYING](COPYING).
