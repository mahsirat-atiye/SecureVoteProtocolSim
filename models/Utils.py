from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512


def decrypt(message, key_pair):
    decrypter = PKCS1_OAEP.new(key_pair)
    decrypted = decrypter.decrypt(message)
    return decrypted


def encrypt(message, key):
    encrypter = PKCS1_OAEP.new(key)
    encrypted = encrypter.encrypt(message.encode('UTF-8'))
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
    print(len(msg))
    print(mlen)
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
