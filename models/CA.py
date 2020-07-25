import math
from Crypto.PublicKey import RSA

from models.AS import AS
from models.VS import VS

class Voter:
    def __init__(self, hash_national_code, hash_certificate_num, key_pair):
        self.hash_national_code = hash_national_code
        self.hash_certificate_num = hash_certificate_num
        self.key_pair = key_pair
class CA:

    def __init__(self):
        self.key_pair = RSA.generate(1024)
        self.pub_keys = [self.get_pub_key()]
        self.create_AS()
        self.create_vs()


    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key

    def create_AS(self):
        key = RSA.generate(1024)
        AS_ = AS(key)
        self.pub_keys.append(AS_)
        return AS_

    def create_vs(self):
        key = RSA.generate(1024)
        VS_ = VS(key)
        self.pub_keys.append(VS_)
        return VS_
