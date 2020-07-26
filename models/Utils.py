from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
import base64, os


def generate_secret_key_for_AES_cipher():
    AES_key_length = 32
    secret_key = os.urandom(AES_key_length)
    encoded_secret_key = base64.b64encode(secret_key)
    return encoded_secret_key


def encrypt_message(private_msg, encoded_secret_key, padding_character):
    secret_key = base64.b64decode(encoded_secret_key)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    padded_private_msg = private_msg + (padding_character * ((16 - len(private_msg)) % 16))
    encrypted_msg = cipher.encrypt(padded_private_msg.encode('UTF-8'))
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg


def decrypt_message(encoded_encrypted_msg, encoded_secret_key, padding_character):
    secret_key = base64.b64decode(encoded_secret_key)
    encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decrypted_msg = cipher.decrypt(encrypted_msg)
    unpadded_private_msg = decrypted_msg.rstrip(padding_character.encode('UTF-8'))
    return unpadded_private_msg


####### BEGIN HERE #######


private_msg = """
 Lorem ipsum dolor sit amet, malis recteque posidonium ea sit, te vis meliore verterem. Duis movet comprehensam eam ex, te mea possim luptatum gloriatur. Modus summo epicuri eu nec. Ex placerat complectitur eos.
"""
padding_character = "{"

secret_key = generate_secret_key_for_AES_cipher()

encrypted_msg = encrypt_message(private_msg, secret_key, padding_character)
decrypted_msg = decrypt_message(encrypted_msg, secret_key, padding_character)


def decrypt(message, key_pair):
    decrypter = PKCS1_OAEP.new(key_pair)
    decrypted = decrypter.decrypt(message)
    return decrypted


def encrypt(message, key):
    encrypter = PKCS1_OAEP.new(key)
    encrypted = encrypter.encrypt(message.encode('UTF-8'))
    return encrypted


def encrypt_binary(message, key):
    encrypter = PKCS1_OAEP.new(key)
    encrypted = encrypter.encrypt(message)
    return encrypted


def decrypt_multi_packet(messages, key_pair):
    decrypter = PKCS1_OAEP.new(key_pair)
    decrypted_message = b""
    for message in messages:
        decrypted = decrypter.decrypt(message)
        decrypted_message += (decrypted)
    return decrypted_message


def encrypt_multi_packet(message, key):
    encrypter = PKCS1_OAEP.new(key)
    mlen = len(message) // 100
    encrypts = []
    for i in range(100):
        msg = message[i * mlen: (i + 1) * mlen]
        encrypted = encrypter.encrypt(msg)
        encrypts.append(encrypted)

    msg = message[100 * mlen:]

    encrypted = encrypter.encrypt(msg)
    encrypts.append(encrypted)
    return encrypts


def sign_multi_packet(messages, key):
    signs = []
    for message in messages:
        s = sign(message, key)
        signs.append(s)
    return signs


def sign(message, key):
    # message = message.encode('UTF-8')
    signer = PKCS1_v1_5.new(key)
    digest = SHA512.new()
    digest.update(message)

    return signer.sign(digest)


def verify(message, signature, pub_key):
    # message = message.encode('UTF-8')
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA512.new()
    digest.update(message)
    return signer.verify(digest, signature)


def verify_multi_packet(messages, signatures, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA512.new()
    for message, signature in list(zip(messages, signatures)):
        digest = SHA512.new()
        digest.update(message)
        v = signer.verify(digest, signature)
        if not v:
            return v
    return True
