from twisted.cred.portal import Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh.factory import SSHFactory
from twisted.internet import reactor
from twisted.conch.ssh.keys import Key
from twisted.conch.interfaces import IConchUser
from twisted.conch.avatar import ConchUser
from twisted.conch.ssh.channel import SSHChannel
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials
from twisted.python import components
from twisted.conch.ssh import session
from twisted.cred import portal
from twisted.internet import reactor
from zope.interface import implements, providedBy

import os
import pwd
import hashlib
import shlex

class settings: pass
settings = settings()

def nothing():
    pass

class KeyConchUser(ConchUser):
    def __init__(self, avatarId):
        ConchUser.__init__(self)
        self.avatarId = avatarId
        self.channelLookup['session'] = session.SSHSession

class KeySession:
    implements(session.ISession)

    def __init__(self, avatar):
        self.avatar = avatar
        self.pty_size = None

    def execCommand(self, proto, exec_cmd):
        username, key_id = self.avatar.avatarId
        if key_id != '5f:62:fb:ec:4f:e1:82:e5:36:7d:76:2e:2c:50:8a:a5:e7:65:a5:6e:84:cb:11:b4:3b:a6:50:c1:b2:4c:a7:ae':
            raise ValueError('invalid key')

        print username, key_id
        uid = int(username)
        cmd = ['/usr/local/bin/graveluser',
               'attach', str(uid), '--']
        if self.pty_size:
            cmd += ['env', 'ROWS=%d' % self.pty_size[0], 'COLS=%d' % self.pty_size[1],
                    '--', '/gravel/pkg/gravel-userd-ssh/pty-helper']
        cmd += shlex.split(exec_cmd)
        self.pty = reactor.spawnProcess(proto,
                                        cmd[0], cmd, os.environ, '/')
        self.avatar.conn.transport.transport.setTcpNoDelay(1)

    def getPty(self, term, windowSize, modes):
        self.pty_size = windowSize
        self.pty_term = term

    def eofReceived(self):
        self.pty.signalProcess('HUP')

    def openShell(self, proto):
        self.execCommand(proto, 'bash')

    def closed(self):
        pass

components.registerAdapter(KeySession, KeyConchUser, session.ISession)

class KeyRealm(object):
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        r = interfaces[0], KeyConchUser(avatarId), nothing
        return r

def get_ssh_key_fingerprint(data, algo=hashlib.sha256):
    key = data.split(None, 2)[1]
    fp_plain = algo(key).hexdigest()
    return ':'.join( a + b for a,b in zip(fp_plain[::2], fp_plain[1::2]) )

class KeyChecker(object):
    implements(ICredentialsChecker)

    credentialInterfaces = (ISSHPrivateKey,)

    def requestAvatarId(self, credentials):
        key = 'ssh-rsa ' + credentials.blob.encode('base64').replace('\n', '')
        id = get_ssh_key_fingerprint(key)
        return (credentials.username, id)

def main(keys_path, username_get, gid, port=2022):
    settings.username_get = username_get
    settings.gid = gid

    with open(keys_path + '/id_rsa') as privateBlobFile:
        privateBlob = privateBlobFile.read()
        privateKey = Key.fromString(data=privateBlob)

    with open(keys_path + '/id_rsa.pub') as publicBlobFile:
        publicBlob = publicBlobFile.read()
        publicKey = Key.fromString(data=publicBlob)

    factory = SSHFactory()
    factory.privateKeys = {'ssh-rsa': privateKey}
    factory.publicKeys = {'ssh-rsa': publicKey}
    factory.portal = Portal(KeyRealm())
    factory.portal.registerChecker(KeyChecker())

    reactor.listenTCP(port, factory)
    reactor.run()

if __name__ == '__main__':
    main('../../tmp', lambda name: 1002, 100)
