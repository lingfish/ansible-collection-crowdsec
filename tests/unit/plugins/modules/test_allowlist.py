# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jason Lingohr
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.lingfish.crowdsec.plugins.modules import allowlist

NOW = datetime(2026, 11, 12, 0, 0, 0, tzinfo=timezone.utc)
FUTURE = '2026-12-01T00:00:00.000Z'
PAST = '2026-11-01T00:00:00.000Z'
NEVER = '0001-01-01T00:00:00.000Z'


def item(value, comment='', expiration=NEVER):
    return dict(value=value, description=comment, expiration=expiration, created_at='2026-11-01T00:00:00.000Z')


def entry(value, comment='', expiration=None):
    return dict(value=value, comment=comment, expiration=expiration)


def params(**kwargs):
    p = dict(name='infra', description='Infra', state='present', entries=[], exclusive=True)
    p.update(kwargs)
    return p


def noop_warn(msg):
    raise AssertionError('unexpected warning: %s' % msg)


class TestEntryMatches:
    def test_same(self):
        assert allowlist.entry_matches(item('192.0.2.1', 'a'), entry('192.0.2.1', 'a'), NOW)

    def test_comment_differs(self):
        assert not allowlist.entry_matches(item('192.0.2.1', 'a'), entry('192.0.2.1', 'b'), NOW)

    def test_missing_comment_matches_empty(self):
        assert allowlist.entry_matches(dict(value='192.0.2.1'), entry('192.0.2.1'), NOW)

    def test_permanent_wanted_but_expiring(self):
        assert not allowlist.entry_matches(item('192.0.2.1', expiration=FUTURE), entry('192.0.2.1'), NOW)

    def test_expiring_wanted_and_not_expired(self):
        assert allowlist.entry_matches(item('192.0.2.1', expiration=FUTURE), entry('192.0.2.1', expiration='7d'), NOW)

    def test_expiring_wanted_but_expired(self):
        assert not allowlist.entry_matches(item('192.0.2.1', expiration=PAST), entry('192.0.2.1', expiration='7d'), NOW)

    def test_expiring_wanted_but_permanent(self):
        assert not allowlist.entry_matches(item('192.0.2.1'), entry('192.0.2.1', expiration='7d'), NOW)


class TestComputeChanges:
    def test_add_missing(self):
        to_remove, to_add = allowlist.compute_changes([], [entry('192.0.2.1')], True, NOW)
        assert to_remove == []
        assert [e['value'] for e in to_add] == ['192.0.2.1']

    def test_nothing_to_do(self):
        assert allowlist.compute_changes([item('192.0.2.1', 'a')], [entry('192.0.2.1', 'a')], True, NOW) == ([], [])

    def test_update_is_remove_and_add(self):
        to_remove, to_add = allowlist.compute_changes([item('192.0.2.1', 'a')], [entry('192.0.2.1', 'b')], True, NOW)
        assert to_remove == ['192.0.2.1']
        assert [e['value'] for e in to_add] == ['192.0.2.1']

    def test_exclusive_removes_unlisted(self):
        to_remove, to_add = allowlist.compute_changes(
            [item('192.0.2.1'), item('192.0.2.2')], [entry('192.0.2.1')], True, NOW)
        assert to_remove == ['192.0.2.2']
        assert to_add == []

    def test_non_exclusive_keeps_unlisted(self):
        assert allowlist.compute_changes([item('192.0.2.1'), item('192.0.2.2')], [entry('192.0.2.1')], False, NOW) == ([], [])

    def test_exclusive_with_no_entries_empties_list(self):
        to_remove, to_add = allowlist.compute_changes([item('192.0.2.1')], [], True, NOW)
        assert to_remove == ['192.0.2.1']

    def test_values_are_exact_strings(self):
        to_remove, to_add = allowlist.compute_changes([item('192.0.2.1/32')], [entry('192.0.2.1')], True, NOW)
        assert to_remove == ['192.0.2.1/32']
        assert [e['value'] for e in to_add] == ['192.0.2.1']


def test_group_additions():
    groups = allowlist.group_additions([
        entry('192.0.2.1', 'a'),
        entry('192.0.2.2', 'b'),
        entry('192.0.2.3', 'a'),
        entry('192.0.2.4', 'a', '7d'),
    ])
    assert groups == [
        (('a', ''), ['192.0.2.1', '192.0.2.3']),
        (('b', ''), ['192.0.2.2']),
        (('a', '7d'), ['192.0.2.4']),
    ]


def test_describe():
    assert allowlist.describe(None) == {}
    assert allowlist.describe(dict(name='infra', items=None)) == dict(name='infra', description='', entries=[])
    assert allowlist.describe(dict(
        name='infra', description='Infra',
        items=[item('192.0.2.2', 'b', FUTURE), item('192.0.2.1', 'a')],
    )) == dict(name='infra', description='Infra', entries=[
        dict(value='192.0.2.1', comment='a', expiration=None),
        dict(value='192.0.2.2', comment='b', expiration=FUTURE),
    ])


class TestPlan:
    def test_create(self):
        commands, after = allowlist.plan(
            params(entries=[entry('192.0.2.1', 'office'), entry('192.0.2.2', expiration='7d')]), [], NOW, noop_warn)
        assert commands == [
            ['allowlists', 'create', 'infra', '--description', 'Infra'],
            ['allowlists', 'add', '--comment', 'office', '--', 'infra', '192.0.2.1'],
            ['allowlists', 'add', '--expiration', '7d', '--', 'infra', '192.0.2.2'],
        ]
        assert after == dict(name='infra', description='Infra', entries=[
            dict(value='192.0.2.1', comment='office', expiration=None),
            dict(value='192.0.2.2', comment='', expiration='7d'),
        ])

    def test_create_needs_description(self):
        with pytest.raises(ValueError, match='description is required'):
            allowlist.plan(params(description=None), [], NOW, noop_warn)

    def test_unchanged(self):
        current = [dict(name='infra', description='Infra', items=[item('192.0.2.1', 'a')])]
        commands, after = allowlist.plan(params(entries=[entry('192.0.2.1', 'a')]), current, NOW, noop_warn)
        assert commands == []
        assert after == allowlist.describe(current[0])

    def test_update_removes_before_adding(self):
        current = [dict(name='infra', description='Infra', items=[item('192.0.2.1', 'a'), item('192.0.2.9')])]
        commands, after = allowlist.plan(params(entries=[entry('192.0.2.1', 'b')]), current, NOW, noop_warn)
        assert commands == [
            ['allowlists', 'remove', '--', 'infra', '192.0.2.1', '192.0.2.9'],
            ['allowlists', 'add', '--comment', 'b', '--', 'infra', '192.0.2.1'],
        ]
        assert after['entries'] == [dict(value='192.0.2.1', comment='b', expiration=None)]

    def test_other_allowlists_ignored(self):
        current = [dict(name='other', description='x', items=[item('192.0.2.1')])]
        commands, after = allowlist.plan(params(), current, NOW, noop_warn)
        assert commands == [['allowlists', 'create', 'infra', '--description', 'Infra']]

    def test_description_mismatch_warns(self):
        warnings = []
        current = [dict(name='infra', description='Old', items=[])]
        commands, after = allowlist.plan(params(), current, NOW, warnings.append)
        assert commands == []
        assert after['description'] == 'Old'
        assert len(warnings) == 1 and 'cannot change the description' in warnings[0]

    def test_no_description_given_does_not_warn(self):
        current = [dict(name='infra', description='Old', items=[])]
        assert allowlist.plan(params(description=None), current, NOW, noop_warn) == ([], allowlist.describe(current[0]))

    def test_console_managed(self):
        current = [dict(name='infra', console_managed=True, items=[])]
        with pytest.raises(ValueError, match='managed by the CrowdSec Console'):
            allowlist.plan(params(), current, NOW, noop_warn)

    def test_absent(self):
        current = [dict(name='infra', description='Infra', items=[item('192.0.2.1')])]
        assert allowlist.plan(params(state='absent'), current, NOW, noop_warn) == ([['allowlists', 'delete', 'infra']], {})

    def test_absent_already(self):
        assert allowlist.plan(params(state='absent'), [], NOW, noop_warn) == ([], {})


class TestValidate:
    def test_ok(self):
        allowlist.validate(params(entries=[entry('192.0.2.1'), entry('2001:db8::/32', expiration='12h'), entry('192.0.2.0/24')]))

    def test_duplicate(self):
        with pytest.raises(ValueError, match='Duplicate'):
            allowlist.validate(params(entries=[entry('192.0.2.1'), entry('192.0.2.1', 'x')]))

    def test_bad_value(self):
        with pytest.raises(ValueError, match='Invalid allowlist entry'):
            allowlist.validate(params(entries=[entry('example.com')]))

    def test_bad_expiration(self):
        with pytest.raises(ValueError, match='Invalid expiration'):
            allowlist.validate(params(entries=[entry('192.0.2.1', expiration='1 week')]))


# End-to-end tests of main() with a fake cscli.

class ModuleExit(Exception):
    pass


@contextmanager
def module_args(args):
    """Set module arguments; works with both old and new ansible-core test APIs."""
    try:
        from ansible.module_utils.testing import patch_module_args
    except ImportError:
        serialized = to_bytes(json.dumps({'ANSIBLE_MODULE_ARGS': args}))
        old = basic._ANSIBLE_ARGS
        basic._ANSIBLE_ARGS = serialized
        try:
            yield
        finally:
            basic._ANSIBLE_ARGS = old
    else:
        with patch_module_args(args):
            yield


class FakeCscli:
    """Simulates cscli allowlists against an in-memory database."""

    def __init__(self, allowlists=None, skip_values=()):
        self.allowlists = allowlists or []
        self.skip_values = skip_values
        self.calls = []

    def get(self, name):
        return next(a for a in self.allowlists if a['name'] == name)

    def __call__(self, module, argv, **kwargs):
        args = argv[argv.index('allowlists') + 1:]
        self.calls.append(args)
        action = args[0]

        if action == 'list':
            return 0, json.dumps(self.allowlists or None), ''
        if action == 'create':
            self.allowlists.append(dict(name=args[1], description=args[3], items=[]))
        elif action == 'delete':
            self.allowlists.remove(self.get(args[1]))
        elif action in ('add', 'remove'):
            sep = args.index('--')
            opts = dict(zip(args[1:sep:2], args[2:sep:2]))
            name, values = args[sep + 1], args[sep + 2:]
            allowlist_ = self.get(name)
            if action == 'remove':
                allowlist_['items'] = [i for i in allowlist_['items'] if i['value'] not in values]
            else:
                expiration = FUTURE if '--expiration' in opts else NEVER
                allowlist_['items'].extend(
                    item(v, opts.get('--comment', ''), expiration) for v in values if v not in self.skip_values)
        return 0, '', ''


@pytest.fixture
def run(monkeypatch):
    def exit_json(self, **kwargs):
        kwargs.setdefault('failed', False)
        raise ModuleExit(kwargs)

    def fail_json(self, **kwargs):
        kwargs['failed'] = True
        raise ModuleExit(kwargs)

    monkeypatch.setattr(basic.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(basic.AnsibleModule, 'fail_json', fail_json)
    monkeypatch.setattr(basic.AnsibleModule, 'get_bin_path', lambda self, arg, required=False, opt_dirs=None: '/usr/bin/cscli')

    def _run(fake, **args):
        def run_command(self, argv, **kwargs):
            return fake(self, argv, **kwargs)

        monkeypatch.setattr(basic.AnsibleModule, 'run_command', run_command)
        with module_args(args):
            with pytest.raises(ModuleExit) as exc:
                allowlist.main()
        return exc.value.args[0]

    return _run


def test_main_creates_and_is_idempotent(run):
    fake = FakeCscli()
    args = dict(name='infra', description='Infra', entries=[dict(value='192.0.2.1', comment='office')])

    result = run(fake, **args)
    assert result['changed'] is True
    assert not result['failed']
    assert result['commands'] == [
        "/usr/bin/cscli --color no allowlists create infra --description Infra",
        "/usr/bin/cscli --color no allowlists add --comment office -- infra 192.0.2.1",
    ]
    assert result['allowlist']['entries'] == [dict(value='192.0.2.1', comment='office', expiration=None)]

    result = run(fake, **args)
    assert result['changed'] is False
    assert result['commands'] == []


def test_main_check_mode_changes_nothing(run):
    fake = FakeCscli()
    result = run(fake, name='infra', description='Infra', entries=[dict(value='192.0.2.1')],
                 _ansible_check_mode=True, _ansible_diff=True)
    assert result['changed'] is True
    assert fake.allowlists == []
    assert [c[0] for c in fake.calls] == ['list']
    assert result['diff']['before'] == {}
    assert result['diff']['after']['entries'] == [dict(value='192.0.2.1', comment='', expiration=None)]


def test_main_config_is_passed(run):
    fake = FakeCscli([dict(name='infra', description='Infra', items=[])])
    result = run(fake, name='infra', config='/etc/crowdsec/other.yaml', entries=[dict(value='192.0.2.1')])
    assert result['commands'] == [
        "/usr/bin/cscli --color no --config /etc/crowdsec/other.yaml allowlists add -- infra 192.0.2.1",
    ]


def test_main_fails_when_cscli_skips_value(run):
    fake = FakeCscli(skip_values=('192.0.2.1',))
    result = run(fake, name='infra', description='Infra', entries=[dict(value='192.0.2.1')])
    assert result['failed'] is True
    assert result['changed'] is True
    assert 'did not add these entries' in result['msg']


def test_main_fails_on_cscli_error(run):
    def broken(module, argv, **kwargs):
        return 1, '', 'local API is disabled -- this command must be run on the local API machine\n'

    result = run(broken, name='infra', description='Infra')
    assert result['failed'] is True
    assert result['msg'] == 'cscli failed: local API is disabled -- this command must be run on the local API machine'


def test_main_rejects_invalid_value(run):
    result = run(FakeCscli(), name='infra', description='Infra', entries=[dict(value='nope')])
    assert result['failed'] is True
    assert 'Invalid allowlist entry' in result['msg']
