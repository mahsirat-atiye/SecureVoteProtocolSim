from models.Utils import *


class Voter:
    def __init__(self, national_code, certificate_num):
        self.national_code = national_code
        self.certificate_num = certificate_num
        self.symmetric_key_with_as = generate_secret_key_for_AES_cipher()

    def get_auth_symmetric_key(self):
        return self.national_code, self.symmetric_key_with_as

    def pub_prv_key_request_to_ca(self, ca_pub_key):
        message = str(self.national_code) + ", " + str(self.certificate_num)
        return encrypt(message=message, key=ca_pub_key)

    def authentication_request(self, as_pub_key):
        message = str(self.national_code) + ", " + str(self.certificate_num)
        return encrypt(message=message, key=as_pub_key)

    def voting_request_after_auth(self, msg, as_pub_key):
        messages, signs = msg
        v = verify_multi_packet(messages, signs, as_pub_key)
        if v:
            padding_character = "{"
            i_cod = decrypt_message(messages[0], self.symmetric_key_with_as, padding_character)
            key_pair = decrypt_message(messages[1], self.symmetric_key_with_as, padding_character)
            T = decrypt_message(messages[2], self.symmetric_key_with_as, padding_character)

            print("00000000000000000000")
            key_pair = (str(key_pair)[4: -2].encode('UTF-8'))

            key = RSA.importKey(key_pair)
            print(key_pair)
            print("8888888888888888888888888")
            print(key.exportKey())



        pass
