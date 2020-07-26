from Crypto.PublicKey import RSA

from models.Utils import decrypt, encrypt, sign, verify_multi_packet, decrypt_multi_packet, verify, \
    encrypt_multi_packet, encrypt_binary


class AS:
    def __init__(self, key_pair):
        self.key_pair = key_pair

    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key

    def response_to_authentication_request_part1(self, message, ca_pub_key):
        decrypted_message = str(decrypt(message=message, key_pair=self.key_pair))
        encrypted_message = encrypt(decrypted_message, ca_pub_key)
        signature = sign(encrypted_message, self.key_pair)
        return [encrypted_message, signature]

    def response_to_authentication_request_part3(self, messages_signatures, ca_pub_key, ca):
        encrypted_messages, signatures, encrypted_national_code, signed_national_code = messages_signatures
        v1 = verify_multi_packet(encrypted_messages, signatures, ca_pub_key)
        v2 = verify(encrypted_national_code, signed_national_code, ca_pub_key)

        v = v1 and v2
        if v:
            print("verified: response_to_authentication_request_part3")
            msg = decrypt_multi_packet(encrypted_messages, self.key_pair)
            national_code = decrypt(encrypted_national_code, self.key_pair)

            national_code = national_code[2: -1]
            secret_key = 9
            # todo

            key = RSA.importKey(msg)
            voter_pub_key = RSA.importKey(key.publickey().exportKey())
            T = encrypt_multi_packet((encrypt_binary(national_code, self.key_pair)), voter_pub_key)


