import os, hashlib

class KeyedMAC:
    def __init__(self):
        self.key = os.urandom(hashlib.sha1().digest_size)
        #self.key = b"YELLOW SUBMARINE" #For testing

    def mac_sha1_sign(self, key, msg):
        return hashlib.sha1(key + msg).digest()

    def mac_sha1_verify(self, key, msg, tag):

        tag_new = hashlib.sha1(key + msg).digest()

        #An obvious check
        if len(tag) != len(tag_new):
            return False
        
        #To avoid timing attacks, be sure to check all the bytes
        result = 0
        for x, y in zip(tag, tag_new):
            result |= x ^ y
        return result == 0

    def verify_post(self, msg, tag):

        ret = False
        try:
            ret = self.mac_sha1_verify(self.key, msg, bytes.fromhex(tag))
        except Exception as e:
            print(e)
            ret = False
        return ret

    def mac_post(self, msg):
        return self.mac_sha1_sign(self.key, msg.encode("utf-8")).hex()
