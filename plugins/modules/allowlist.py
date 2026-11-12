#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jason Lingohr
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: allowlist
short_description: Manage CrowdSec centralized allowlists
version_added: 0.1.0
description:
  - Create, update and delete CrowdSec centralized allowlists and their entries using C(cscli allowlists).
  - C(cscli) writes allowlists directly to the CrowdSec database, so this module must run on the host
    running the CrowdSec Local API (LAPI). Use C(delegate_to) to target it from other plays.
  - Allowlists managed by the CrowdSec Console are read-only to C(cscli); the module fails if asked to change one.
author:
  - Jason Lingohr (@lingfish)
requirements:
  - CrowdSec 1.6.8 or later on the target host.
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: posix
options:
  name:
    description:
      - Name of the allowlist.
    type: str
    required: true
  description:
    description:
      - Description of the allowlist.
      - Required when the allowlist has to be created.
      - C(cscli) cannot change the description of an existing allowlist, so a differing value only produces a warning.
    type: str
  state:
    description:
      - V(present) creates the allowlist if needed and manages its entries.
      - V(absent) deletes the allowlist and all its entries.
    type: str
    choices: [present, absent]
    default: present
  entries:
    description:
      - Desired entries of the allowlist.
      - Entries are matched on the exact O(entries[].value) string, so V(192.0.2.1) and V(192.0.2.1/32) are different entries.
      - An entry whose comment or expiration does not match is removed and added again.
    type: list
    elements: dict
    default: []
    suboptions:
      value:
        description:
          - IP address or CIDR range.
        type: str
        required: true
      comment:
        description:
          - Comment stored with the entry.
        type: str
        default: ''
      expiration:
        description:
          - How long the entry lasts after it is added, as a duration such as V(12h) or V(7d).
          - The expiration is only set when the entry is added. An existing entry that has not expired yet
            is left alone and is not extended. An expired entry is added again.
          - Omit for a permanent entry.
        type: str
  exclusive:
    description:
      - Remove entries from the allowlist that are not listed in O(entries).
    type: bool
    default: true
  cscli_path:
    description:
      - Name or path of the C(cscli) binary.
    type: path
    default: cscli
  config:
    description:
      - Path to the CrowdSec configuration file, passed to C(cscli --config).
      - Defaults to whatever C(cscli) uses, normally C(/etc/crowdsec/config.yaml).
    type: path
notes:
  - Changing an existing entry removes it and adds it again, so it is briefly not allowlisted.
  - Adding entries also deletes existing decisions that the new entries cover, as C(cscli allowlists add) does.
'''

EXAMPLES = r'''
- name: Allowlist office and monitoring addresses
  lingfish.crowdsec.allowlist:
    name: infra
    description: Infrastructure addresses
    entries:
      - value: 203.0.113.0/24
        comment: office
      - value: 198.51.100.7
        comment: monitoring

- name: Temporarily allowlist a vendor, keeping entries added by hand
  lingfish.crowdsec.allowlist:
    name: vendors
    description: Third-party access
    exclusive: false
    entries:
      - value: 192.0.2.50
        comment: pentest
        expiration: 7d

- name: Manage an allowlist from a play that targets other hosts
  lingfish.crowdsec.allowlist:
    name: infra
    description: Infrastructure addresses
    entries: "{{ infra_entries }}"
  delegate_to: lapi.example.com
  run_once: true

- name: Delete an allowlist
  lingfish.crowdsec.allowlist:
    name: old
    state: absent
'''

RETURN = r'''
allowlist:
  description:
    - State of the allowlist after the module ran. Empty if the allowlist does not exist.
    - In check mode, the predicted state. Expirations of entries that would be added are shown as the requested duration.
  returned: always
  type: dict
  sample:
    name: infra
    description: Infrastructure addresses
    entries:
      - value: 203.0.113.0/24
        comment: office
        expiration: null
commands:
  description: C(cscli) commands that were run, or would be run in check mode.
  returned: always
  type: list
  elements: str
  sample:
    - /usr/bin/cscli --color no allowlists create infra --description 'Infrastructure addresses'
    - /usr/bin/cscli --color no allowlists add --comment office -- infra 203.0.113.0/24
'''

import ipaddress
from datetime import datetime, timezone

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.lingfish.crowdsec.plugins.module_utils.cscli import (
    Cscli,
    cscli_argument_spec,
    format_command,
    is_duration,
    parse_time,
)


def entry_matches(item, entry, now):
    """Whether an existing allowlist item satisfies a desired entry."""
    if (item.get('description') or '') != (entry.get('comment') or ''):
        return False

    expires = parse_time(item.get('expiration'))
    if entry.get('expiration'):
        return expires is not None and expires > now
    return expires is None


def compute_changes(items, entries, exclusive, now):
    """Work out which values to remove and which entries to add.

    Values that need updating appear in both lists: cscli can't modify an
    item in place, so it has to be removed and added again.
    """
    current = dict((item['value'], item) for item in items)
    wanted = set()
    to_remove = []
    to_add = []

    for entry in entries:
        value = entry['value']
        wanted.add(value)
        item = current.get(value)
        if item is None:
            to_add.append(entry)
        elif not entry_matches(item, entry, now):
            to_remove.append(value)
            to_add.append(entry)

    if exclusive:
        to_remove.extend(value for value in current if value not in wanted)

    return to_remove, to_add


def group_additions(entries):
    """Group entries by (comment, expiration), since cscli applies one of each per add."""
    groups = []
    index = {}
    for entry in entries:
        key = (entry.get('comment') or '', entry.get('expiration') or '')
        if key not in index:
            index[key] = len(groups)
            groups.append((key, []))
        groups[index[key]][1].append(entry['value'])
    return groups


def describe(allowlist):
    """Normalised view of a cscli allowlist, used for diffs and return values."""
    if allowlist is None:
        return {}

    entries = []
    for item in allowlist.get('items') or []:
        expiration = item.get('expiration')
        entries.append(dict(
            value=item['value'],
            comment=item.get('description') or '',
            expiration=expiration if parse_time(expiration) else None,
        ))

    return dict(
        name=allowlist.get('name'),
        description=allowlist.get('description') or '',
        entries=sorted(entries, key=lambda e: e['value']),
    )


def predict(before, name, description, to_remove, to_add):
    kept = [e for e in before.get('entries', []) if e['value'] not in to_remove]
    added = [
        dict(value=e['value'], comment=e.get('comment') or '', expiration=e.get('expiration'))
        for e in to_add
    ]
    return dict(
        name=name,
        description=before.get('description', description or ''),
        entries=sorted(kept + added, key=lambda e: e['value']),
    )


def plan(params, allowlists, now, warn):
    """Return (commands, predicted_after) for the requested state.

    Raises ValueError for requests that can't be satisfied.
    """
    name = params['name']
    current = next((a for a in allowlists if a.get('name') == name), None)

    if current is not None and current.get('console_managed'):
        raise ValueError(
            'Allowlist %s is managed by the CrowdSec Console and cannot be changed with cscli' % name
        )

    before = describe(current)

    if params['state'] == 'absent':
        if current is None:
            return [], {}
        return [['allowlists', 'delete', name]], {}

    commands = []
    description = params.get('description')

    if current is None:
        if not description:
            raise ValueError('description is required to create allowlist %s' % name)
        commands.append(['allowlists', 'create', name, '--description', description])
    elif description is not None and description != before['description']:
        warn(
            'Allowlist %s has description %r, not %r. cscli cannot change the description of an '
            'existing allowlist; delete and recreate it to change it.' % (name, before['description'], description)
        )

    items = (current.get('items') or []) if current is not None else []
    to_remove, to_add = compute_changes(items, params['entries'], params['exclusive'], now)

    if to_remove:
        commands.append(['allowlists', 'remove', '--', name] + to_remove)

    for (comment, expiration), values in group_additions(to_add):
        command = ['allowlists', 'add']
        if comment:
            command += ['--comment', comment]
        if expiration:
            command += ['--expiration', expiration]
        commands.append(command + ['--', name] + values)

    return commands, predict(before, name, description, to_remove, to_add)


def validate(params):
    seen = set()
    for entry in params['entries']:
        value = entry['value']
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError('Invalid allowlist entry %r; use an IP address or CIDR range' % value)

        if value in seen:
            raise ValueError('Duplicate allowlist entry: %s' % value)
        seen.add(value)

        expiration = entry.get('expiration')
        if expiration and not is_duration(expiration):
            raise ValueError('Invalid expiration %r for %s; use a duration such as 12h or 7d' % (expiration, value))


def list_allowlists(cscli):
    # An empty list is serialised as null.
    return cscli.run_json(['allowlists', 'list']) or []


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        description=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        entries=dict(
            type='list',
            elements='dict',
            default=[],
            options=dict(
                value=dict(type='str', required=True),
                comment=dict(type='str', default=''),
                expiration=dict(type='str'),
            ),
        ),
        exclusive=dict(type='bool', default=True),
    )
    argument_spec.update(cscli_argument_spec())

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    params = module.params
    cscli = Cscli(module)

    try:
        validate(params)
        allowlists = list_allowlists(cscli)
        before = describe(next((a for a in allowlists if a.get('name') == params['name']), None))
        commands, after = plan(params, allowlists, datetime.now(timezone.utc), module.warn)
    except ValueError as e:
        module.fail_json(msg=str(e))

    if commands and not module.check_mode:
        for command in commands:
            cscli.run(command)
        after = describe(next((a for a in list_allowlists(cscli) if a.get('name') == params['name']), None))

        # cscli logs and skips values it can't add, but still exits 0.
        missing = sorted(
            set(e['value'] for e in params['entries']) - set(e['value'] for e in after.get('entries', []))
        )
        if params['state'] == 'present' and missing:
            module.fail_json(
                msg='cscli did not add these entries to allowlist %s: %s' % (params['name'], ', '.join(missing)),
                changed=True, allowlist=after,
                commands=[format_command(cscli.argv(command)) for command in commands],
            )

    result = dict(
        changed=bool(commands),
        allowlist=after,
        commands=[format_command(cscli.argv(command)) for command in commands],
    )
    if module._diff:
        result['diff'] = dict(before=before, after=after)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
