# AGENTS.md

## Project

Ansible collection `lingfish.crowdsec` for managing CrowdSec with `cscli`. Published to Ansible Galaxy.
Currently has one module (`allowlist`) and one role (`cscli`) that wraps it.

## Commands

```bash
# Lint (run before committing)
yamllint .
ansible-lint

# ansible-test needs the checkout at .../ansible_collections/lingfish/crowdsec
ansible-test sanity --venv
ansible-test units --venv

# Integration tests against a CrowdSec container (docker or podman)
tests/integration/run.sh v1.8.2
```

## CI Order

Lint, ansible-test (sanity + units on ansible-core 2.18 to 2.22), integration (CrowdSec 1.6.8, 1.7, 1.8, latest),
then Galaxy publish on release only. The release tag must be `v` + the `galaxy.yml` version.

## Key Files

- `plugins/modules/allowlist.py`: the module. `plan()` is pure (current state in, commands out) and is what unit tests exercise.
- `plugins/module_utils/cscli.py`: runs `cscli`, parses JSON and timestamps, validates durations
- `roles/cscli/`: loops over `cscli_allowlists` calling the module
- `tests/integration/run.sh`: starts a CrowdSec container and points `cscli_path` at a `docker exec` wrapper

## How cscli allowlists work (verified against the source and 1.8.2)

- `list`/`inspect`/`check` go through the LAPI over HTTP. `create`/`delete`/`add`/`remove` require the LAPI to be
  enabled locally and write straight to the database. So writes only work on the LAPI host, and there's no API alternative.
- `list -o json` returns `null` when there are no allowlists. Permanent entries have expiration `0001-01-01T00:00:00.000Z`.
  An empty comment means the `description` key is missing.
- `add` skips existing values with only a warning (no update), and silently skips unparseable values with exit 0.
  The module validates values up front and checks the result after applying.
- `add` takes one comment and one expiration per call, so additions are grouped by (comment, expiration).

## Conventions

- FQCN everywhere. Modules are GPL-3.0-or-later with the standard header, as `ansible-test sanity` requires.
- Keep `ansible-test sanity` clean without ignore files.
