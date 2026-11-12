# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jason Lingohr
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from datetime import datetime, timedelta, timezone

import pytest

from ansible_collections.lingfish.crowdsec.plugins.module_utils.cscli import (
    format_command,
    is_duration,
    parse_time,
)


@pytest.mark.parametrize('value', [None, '', '0001-01-01T00:00:00.000Z', '0001-01-01T00:00:00Z'])
def test_parse_time_empty(value):
    assert parse_time(value) is None


@pytest.mark.parametrize('value, expected', [
    ('2026-11-12T10:20:30.000Z', datetime(2026, 11, 12, 10, 20, 30, tzinfo=timezone.utc)),
    ('2026-11-12T10:20:30Z', datetime(2026, 11, 12, 10, 20, 30, tzinfo=timezone.utc)),
    ('2026-11-12T10:20:30.123456789Z', datetime(2026, 11, 12, 10, 20, 30, 123456, tzinfo=timezone.utc)),
    ('2026-11-12T21:20:30.5+11:00', datetime(2026, 11, 12, 10, 20, 30, 500000, tzinfo=timezone.utc)),
    ('2026-11-12T05:20:30-05:00', datetime(2026, 11, 12, 10, 20, 30, tzinfo=timezone.utc)),
])
def test_parse_time(value, expected):
    assert parse_time(value) == expected
    assert parse_time(value).utcoffset() is not None


def test_parse_time_offset_preserved():
    assert parse_time('2026-11-12T21:20:30+11:00').utcoffset() == timedelta(hours=11)


def test_parse_time_invalid():
    with pytest.raises(ValueError):
        parse_time('yesterday')


@pytest.mark.parametrize('value', ['30s', '12h', '7d', '1h30m', '1.5h', '100ms'])
def test_is_duration(value):
    assert is_duration(value)


@pytest.mark.parametrize('value', ['', '7', 'd', '7 days', '2026-01-01', '-1h', '1w'])
def test_is_not_duration(value):
    assert not is_duration(value)


def test_format_command():
    assert format_command(['cscli', 'allowlists', 'add', '--comment', 'my office']) == \
        "cscli allowlists add --comment 'my office'"
