from models.Utils import *


def change_key_util(original_key):
    pass


class Voter:
    def __init__(self, national_code, certificate_num, selected_candidate):
        self.national_code = national_code
        self.certificate_num = certificate_num
        self.symmetric_key_with_as = generate_secret_key_for_AES_cipher()
        self.selected_candidate = selected_candidate

    def get_auth_symmetric_key(self):
        return self.national_code, self.symmetric_key_with_as

    def pub_prv_key_request_to_ca(self, ca_pub_key):
        message = str(self.national_code) + ", " + str(self.certificate_num)
        return encrypt(message=message, key=ca_pub_key)

    def authentication_request(self, as_pub_key):
        message = str(self.national_code) + ", " + str(self.certificate_num)
        return encrypt(message=message, key=as_pub_key)

    def voting_request_after_auth(self, msg, as_pub_key, vs_pub_key):
        messages, signs = msg
        v1 = verify_multi_packet(messages[:-1], signs[:-1], as_pub_key)
        v2 = verify_multi_packet(messages[-1], signs[-1], as_pub_key)
        if v1 and v2:
            padding_character = "{"
            i_cod = decrypt_message(messages[0], self.symmetric_key_with_as, padding_character)
            if i_cod.startswith(self.national_code.encode('utf-8')):
                key_pair = decrypt_message(messages[1], self.symmetric_key_with_as, padding_character)
                key_pair = key_pair.replace(b"\\n", b"\n")
                key_pair = key_pair[2: -10]
                key = RSA.importKey(key_pair)
                key_pair = key.exportKey()
                self.key_pair = RSA.importKey(key_pair)

                decrypted_T_symmetric_key = [decrypt_message_binary(m, self.symmetric_key_with_as) for m in
                                             messages[-1]]
                token = decrypt_multi_packet(decrypted_T_symmetric_key, self.key_pair)

                verify_t = verify(self.national_code.encode('utf-8'), token, as_pub_key)
                #                 the national id is correctly set!

                if verify_t:
                    encrypted_selected_candidate = encrypt(self.selected_candidate, vs_pub_key)
                    signed_selected_candidate = sign(encrypted_selected_candidate, self.key_pair)

                    encrypted_i_code = encrypt(self.national_code, vs_pub_key)
                    signed_i_code = sign(encrypted_i_code, self.key_pair)
                    return token, encrypted_selected_candidate, encrypted_i_code, \
                           signed_selected_candidate, signed_i_code
