#!/usr/bin/env python2.7
import sys
import os

sys.path.append('/gravel/pkg/gravel-common')
sys.path.append('/gravel/pkg/gravel-node')

import sshd
import ssh_info
import gravelnode

key_dir = os.path.join('/gravel/system/node/ssh_keys')

if not os.path.exists(key_dir + '/id_rsa'):
    print 'fetching server keys from master'
    pub = gravelnode.master_call('get', 'sshd_rsa.pub', check_output=True)
    priv = gravelnode.master_call('get', 'sshd_rsa', check_output=True)

    if not pub or not priv:
        raise ValueError('invalid ssh keys: pub, priv = %r, %r' % (pub, priv))

    if not os.path.exists(key_dir):
        os.mkdir(key_dir)
        os.chmod(key_dir, 0o700)

    with open(key_dir + '/id_rsa', 'w') as f:
        f.write(priv)

    with open(key_dir + '/id_rsa.pub', 'w') as f:
        f.write(pub)

port = 22
print 'running sshd.py on port %d' % port
sshd.main(key_dir, port=port)
