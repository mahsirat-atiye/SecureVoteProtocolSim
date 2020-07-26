import math
from Crypto.PublicKey import RSA

from models.AS import AS
from models.Utils import decrypt, verify, encrypt, sign, encrypt_multi_packet, sign_multi_packet
from models.VS import VS


class CA:

    def __init__(self):
        self.key_pair = RSA.generate(4096)
        self.pub_keys = dict()
        self.pub_keys[("CA")] = self.get_pub_key()
        self.key_pair_dict = dict()
        self.key_pair_dict[("CA")] = (
            {"national_code": hash("CA"), "certificate_num": hash(""), "key_pair": self.key_pair})

    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key

    def create_AS(self):
        key = RSA.generate(1024)
        self.key_pair_dict[("AS")] = ({"national_code": hash("AS"), "certificate_num": hash(""), "key_pair": key})

        AS_ = AS(key)
        self.pub_keys[("AS")] = key.publickey()
        return AS_

    def create_vs(self):
        key = RSA.generate(1024)
        self.key_pair_dict[("VS")] = ({"national_code": hash("VS"), "certificate_num": hash(""), "key_pair": key})

        VS_ = VS(key)
        self.pub_keys[("VS")] = key.publickey()
        return VS_

    def get_pub_key_of(self, item):
        if (item) in self.pub_keys.keys():
            return self.pub_keys[(item)]
        else:
            print("No key ", item ,"in : ", self.pub_keys.keys())
            return None

    def response_to_pub_prv_key_request(self, message):
        print("response_to_pub_prv_key_request")
        decrypted_message = str(decrypt(message=message, key_pair=self.key_pair))
        voter_identifications = decrypted_message.split(", ")
        #         considering national code and certificate num mach!
        i_code = str(voter_identifications[0])[2:]
        c_num = str(voter_identifications[1])[:-1]
        print("response_to_pub_prv_key_request : i code: ", i_code, " c num: ", c_num)
        if i_code not in self.key_pair_dict.keys():
            print("No key registered")

            key = RSA.generate(1024)
            self.key_pair_dict[i_code] = (
                {"national_code": hash(i_code),
                 "certificate_num": hash(c_num),
                 "key_pair": key})
            self.pub_keys[i_code] = key.publickey()

    def response_to_authentication_request_part2(self, message):
        encrypted_message, signature = message
        v = verify(encrypted_message, signature, self.pub_keys[("AS")])
        if v:
            print("verified response_to_authentication_request_part2" )
            decrypted_msg = decrypt(encrypted_message, self.key_pair)
            identifications = decrypted_msg.split(b", ")
            # identifications = [b"b'002-036-135", b"123-a'"]
            c_num = str(identifications[1])[2:-2]
            i_code = str(identifications[0])[4: -1]
            print(self.key_pair_dict.keys())
            if (i_code) in self.key_pair_dict.keys():
                data = self.key_pair_dict[(i_code)]
                if data["certificate_num"] == hash(c_num):
                    print("Going to phase 3")
                    my_message =(data["key_pair"].exportKey())
                    my_encrypted_messages = encrypt_multi_packet(my_message, self.pub_keys[("AS")])
                    my_signatures = sign_multi_packet(my_encrypted_messages, self.key_pair)

                    second_message = i_code
                    encrypted_second_message = encrypt(second_message, self.pub_keys[("AS")])
                    signed_second_message = sign(encrypted_second_message, self.key_pair)

                    return (my_encrypted_messages, my_signatures, encrypted_second_message, signed_second_message)

        return None
