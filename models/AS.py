from models.Utils import decrypt, encrypt, sign, verify_multi_packet, decrypt_multi_packet


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

    def response_to_authentication_request_part3(self, messages_signatures, ca_pub_key):
        encrypted_messages, signatures = messages_signatures
        print(len(encrypted_messages))
        print(len(signatures))
        v = verify_multi_packet(encrypted_messages, signatures, ca_pub_key)
        print(v)
        if v:
            msg = decrypt_multi_packet(encrypted_messages, self.key_pair)
