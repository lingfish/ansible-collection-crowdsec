# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jason Lingohr
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import re
import shlex
from datetime import datetime, timedelta, timezone

# Go zero time, which cscli emits for "no expiration".
_ZERO_TIME_PREFIX = '0001-01-01'

_RFC3339 = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$'
)

# Go durations plus the "d" (days) unit accepted by cscli, e.g. 12h, 7d, 1h30m.
_DURATION = re.compile(r'^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h|d))+$')


def cscli_argument_spec():
    return dict(
        cscli_path=dict(type='path', default='cscli'),
        config=dict(type='path'),
    )


def parse_time(value):
    """Parse an RFC 3339 timestamp from cscli into an aware datetime.

    Returns None for empty values and Go's zero time.
    """
    if not value or value.startswith(_ZERO_TIME_PREFIX):
        return None

    match = _RFC3339.match(value)
    if not match:
        raise ValueError('unrecognised timestamp: %s' % value)

    year, month, day, hour, minute, second, fraction, offset = match.groups()
    micro = int((fraction or '0')[:6].ljust(6, '0'))

    if offset in ('Z', 'z'):
        tz = timezone.utc
    else:
        sign = -1 if offset[0] == '-' else 1
        tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))

    return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tz)


def is_duration(value):
    return bool(_DURATION.match(value))


def format_command(argv):
    return ' '.join(shlex.quote(arg) for arg in argv)


class Cscli(object):
    """Thin wrapper around the cscli binary."""

    def __init__(self, module):
        self.module = module
        self.binary = module.get_bin_path(module.params['cscli_path'], required=True)
        self.config = module.params.get('config')

    def argv(self, args):
        argv = [self.binary, '--color', 'no']
        if self.config:
            argv += ['--config', self.config]
        return argv + list(args)

    def run(self, args):
        argv = self.argv(args)
        rc, stdout, stderr = self.module.run_command(argv, environ_update={'LC_ALL': 'C'})
        if rc != 0:
            self.module.fail_json(
                msg='cscli failed: %s' % (stderr.strip() or stdout.strip()),
                cmd=format_command(argv), rc=rc, stdout=stdout, stderr=stderr,
            )
        return stdout

    def run_json(self, args):
        stdout = self.run(list(args) + ['--output', 'json'])
        try:
            return json.loads(stdout)
        except ValueError as e:
            self.module.fail_json(msg='Unable to parse cscli JSON output: %s' % e, stdout=stdout)
