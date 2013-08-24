import graveldb

PATH = '/gravel/system/node'

class SSHUserKey(graveldb.Table('domains', PATH)):
    default = dict(keys={})
    autocreate = False

    @staticmethod
    def get(self, user_name, key_fingerprint):
        return SSHUserKey(user_name).data.keys[key_fingerprint]

    def setup(self):
        pass
