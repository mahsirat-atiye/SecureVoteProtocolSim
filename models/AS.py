from Crypto.PublicKey import RSA

from models.Utils import decrypt, encrypt, sign, verify_multi_packet, decrypt_multi_packet, verify, \
    encrypt_multi_packet, encrypt_binary, encrypt_message, generate_secret_key_for_AES_cipher


class AS:
    def __init__(self, key_pair):
        self.key_pair = key_pair
        self.symmetric_keys = dict()

    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key

    def response_to_authentication_request_part1(self, message, ca_pub_key):
        decrypted_message = str(decrypt(message=message, key_pair=self.key_pair))
        encrypted_message = encrypt(decrypted_message, ca_pub_key)
        signature = sign(encrypted_message, self.key_pair)
        return [encrypted_message, signature]

    def add_symmetric_key(self, national_code, symmetric_key_with_as):
        self.symmetric_keys[national_code] = symmetric_key_with_as

    def response_to_authentication_request_part3(self, messages_signatures, ca_pub_key):
        encrypted_messages, signatures, encrypted_national_code, signed_national_code = messages_signatures
        v1 = verify_multi_packet(encrypted_messages, signatures, ca_pub_key)
        v2 = verify(encrypted_national_code, signed_national_code, ca_pub_key)

        v = v1 and v2
        if v:
            print("verified: response_to_authentication_request_part3")
            msg = decrypt_multi_packet(encrypted_messages, self.key_pair)
            national_code = decrypt(encrypted_national_code, self.key_pair)
            print("---------")
            print(national_code)
            national_code_binary = national_code

            national_code = str(national_code_binary)[2: -1]
            secret_key = self.symmetric_keys[national_code]
            key = RSA.importKey(msg)
            voter_pub_key = RSA.importKey(key.publickey().exportKey())
            T = encrypt_multi_packet((encrypt_binary(national_code_binary, self.key_pair)), voter_pub_key)

            padding_character = "{"
            encrypted_T = encrypt_message(str(T), secret_key, padding_character)
            encrypted_i_code = encrypt_message(national_code, secret_key, padding_character)
            encrypted_pair_key = encrypt_message(str(key.exportKey()), secret_key, padding_character)

            sending_messages = [encrypted_i_code, encrypted_pair_key, encrypted_T]

            signed_encrypted_T = sign(encrypted_T, self.key_pair)
            signed_encrypted_i_code = sign(encrypted_i_code, self.key_pair)
            signed_encrypted_pair_key = sign(encrypted_pair_key, self.key_pair)

            signs = [signed_encrypted_i_code, signed_encrypted_pair_key, signed_encrypted_T]

            return (sending_messages, signs)
