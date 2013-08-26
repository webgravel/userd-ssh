import graveldb

PATH = '/gravel/system/node'

class SSHUserKey(graveldb.Table('sshuserkeys', PATH)):
    default = dict(keys={})

    @staticmethod
    def get(user_name, key_fingerprint):
        return SSHUserKey(user_name).data.keys[key_fingerprint]
