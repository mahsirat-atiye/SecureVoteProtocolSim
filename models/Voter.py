from models.Utils import *


class Voter:
    def __init__(self, national_code, certificate_num):
        self.national_code = national_code
        self.certificate_num = certificate_num


    def pub_prv_key_request_to_ca(self, ca_pub_key):
        message = str(self.national_code) + ", " + str(self.certificate_num)
        return encrypt(message=message, key=ca_pub_key)

    def authentication_request(self, as_pub_key):
        message = str(self.national_code) + ", " + str(self.certificate_num)
        return encrypt(message=message, key=as_pub_key)

