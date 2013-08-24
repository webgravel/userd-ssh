#!/usr/bin/env python2.7
# Updates mapping used by SSH server.

import sys

sys.path.append('/gravel/pkg/gravel-common')
sys.path.append('/gravel/pkg/gravel-userd')

import users
import ssh_info
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('uid', type=int)
args = parser.parse_args()

user = users.User(args.uid)

# todo: remove old domains

for prop in user.data.custom.get('web', []):
    host = prop['host']
    port = int(prop['port'])
    domain = domains.Domain(host)
    domain.data.port = port
    domain.data.owner = args.uid
    domain.save()
