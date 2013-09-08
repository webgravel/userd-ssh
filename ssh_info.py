import graveldb

PATH = '/gravel/system/nodecache'

class SSHUserKey(graveldb.Table('sshuserkeys', PATH)):
    default = dict(keys={})

    @staticmethod
    def get(user_name, authdata):
        return SSHUserKey(user_name).data.keys[authdata]

    @staticmethod
    def get_with_checker(user_name, checker):
        for k, v in SSHUserKey(user_name).data.keys.items():
            if checker(k):
                return v
        raise KeyError('auth failed')
