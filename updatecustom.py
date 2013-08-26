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

for prop in user.data.old_custom.get('ssh', []):
    username = prop['username']
    fingerprint = prop['fingerprint']
    try:
        info = ssh_info.SSHUserKey(username)
        del info.data.keys[fingerprint]
    except KeyError:
        pass
    else:
        info.save()

for prop in user.data.custom.get('ssh', []):
    username = prop['username']
    fingerprint = prop['fingerprint']
    info = ssh_info.SSHUserKey(username)
    info.data.keys[fingerprint] = {'uid': args.uid}
    info.save()
