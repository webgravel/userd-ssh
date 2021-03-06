from twisted.cred.portal import Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.conch.checkers import SSHPublicKeyDatabase
from twisted.conch.ssh.factory import SSHFactory
from twisted.internet import reactor, defer
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
from twisted.internet.error import ProcessExitedAlready
from zope.interface import implements, providedBy

import os
import pwd
import hashlib
import shlex
import crypt

import ssh_info

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
        self.proc = None
        self.uid, = self.avatar.avatarId

    def execCommand(self, proto, exec_cmd):
        print('execCommand uid=%d cmd=%r' % (self.uid, exec_cmd))
        self._execCommand(proto, ['sh', '-c', exec_cmd])

    def _execCommand(self, proto, exec_args):
        uid = self.uid
        cmd = ['/usr/local/bin/graveluser',
               'attach', str(uid), '--']
        if self.pty_size:
            cmd += ['env', 'ROWS=%d' % self.pty_size[0], 'COLS=%d' % self.pty_size[1],
                    '--', '/gravel/pkg/gravel-userd-ssh/pty-helper']
        cmd += exec_args
        print cmd
        self.proc = reactor.spawnProcess(ProcessExitWorkaroundWrapper(proto),
                                        cmd[0], cmd, os.environ, '/')

        self.avatar.conn.transport.transport.setTcpNoDelay(1)

    def getPty(self, term, windowSize, modes):
        self.pty_size = windowSize
        self.pty_term = term

    def windowChanged(self, windowSize):
        print 'windowChanged', windowSize

    def eofReceived(self):
        if self.proc:
            self.proc.closeStdin()

    def openShell(self, proto):
        print('openShell uid=%d' % (self.uid, ))
        self._execCommand(proto, ['bash', '--login'])

    def closed(self):
        try:
            self.proc.signalProcess('HUP')
        except (OSError, ProcessExitedAlready):
            pass
        self.proc.loseConnection()

class ProcessExitWorkaroundWrapper(object):
    '''
    Process seems to call processExited long before processEnded.
    However SSHSessionProcessProtocol closes channel on processEnded.
    '''
    def __init__(self, obj):
        self._obj = obj

    def __getattr__(self, name):
        return getattr(self._obj, name)

    def processExited(self, reason=None):
        return self.processEnded(reason)

    def childDataReceived(self, a, data):
        return self._obj.childDataReceived(a, data)

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
        fingerprint = get_ssh_key_fingerprint(key)

        try:
            options = ssh_info.SSHUserKey.get(credentials.username, fingerprint)
        except KeyError:
            return defer.fail(UnauthorizedLogin())
        except:
            import traceback
            traceback.print_exc()

        return (options['uid'], )

class PasswordChecker(object):
    implements(ICredentialsChecker)

    credentialInterfaces = (IUsernamePassword,)

    def requestAvatarId(self, credentials):
        username = credentials.username
        password = credentials.password

        def checker(token):
            return crypt.crypt(password, token) == token

        try:
            options = ssh_info.SSHUserKey.get_with_checker(username, checker)
        except KeyError:
            return defer.fail(UnauthorizedLogin())
        except:
            import traceback
            traceback.print_exc()

        return (options['uid'], )

def main(keys_path, port):
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
    factory.portal.registerChecker(PasswordChecker())

    reactor.listenTCP(port, factory)
    reactor.run()

if __name__ == '__main__':
    main('../../tmp', 2022)
