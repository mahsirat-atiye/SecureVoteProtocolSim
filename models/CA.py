import math
from Crypto.PublicKey import RSA

from models.AS import AS
from models.Utils import decrypt, verify, encrypt, sign, encrypt_multi_packet, sign_multi_packet
from models.VS import VS


class CA:

    def __init__(self):
        self.key_pair = RSA.generate(4096)
        self.pub_keys = dict()
        self.pub_keys[hash("CA")] = self.get_pub_key()
        self.key_pair_dict = dict()
        self.key_pair_dict[hash("CA")] = (
            {"national_code": hash("CA"), "certificate_num": hash(""), "key_pair": self.key_pair})

    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key

    def create_AS(self):
        key = RSA.generate(1024)
        self.key_pair_dict[hash("AS")] = ({"national_code": hash("AS"), "certificate_num": hash(""), "key_pair": key})

        AS_ = AS(key)
        self.pub_keys[hash("AS")] = key.publickey()
        return AS_

    def create_vs(self):
        key = RSA.generate(1024)
        self.key_pair_dict[hash("VS")] = ({"national_code": hash("VS"), "certificate_num": hash(""), "key_pair": key})

        VS_ = VS(key)
        self.pub_keys[hash("VS")] = key.publickey()
        return VS_

    def get_pub_key_of(self, item):
        if hash(item) in self.pub_keys.keys():
            return self.pub_keys[hash(item)]
        else:
            return None

    def response_to_pub_prv_key_request(self, message):
        decrypted_message = str(decrypt(message=message, key_pair=self.key_pair))
        voter_identifications = decrypted_message.split(", ")
        #         considering national code and certificate num mach!
        if hash(str(voter_identifications[0])) not in self.key_pair_dict.keys():
            key = RSA.generate(1024)

            self.key_pair_dict[hash(str(voter_identifications[0]))] = (
                {"national_code": hash(str(voter_identifications[0])),
                 "certificate_num": hash(str(voter_identifications[1])),
                 "key_pair": key})
            self.pub_keys[hash(str(voter_identifications[0]))] = key.publickey()

    def response_to_authentication_request_part2(self, message):
        encrypted_message, signature = message
        v = verify(encrypted_message, signature, self.pub_keys[hash("AS")])
        if v:
            decrypted_msg = decrypt(encrypted_message, self.key_pair)
            identifications = decrypted_msg.split(b", ")
            if hash(identifications[0]) in self.key_pair_dict.keys():
                data = self.key_pair_dict[hash(identifications[0])]
                if data["certificate_num"] == hash(identifications[1]):
                    my_message =(data["key_pair"].exportKey())
                    my_encrypted_messages = encrypt_multi_packet(my_message, self.pub_keys[hash("AS")])
                    my_signatures = sign_multi_packet(my_encrypted_messages, self.key_pair)
                    return (my_encrypted_messages, my_signatures)

        return None
