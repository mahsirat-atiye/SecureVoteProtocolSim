from OpenSSL import crypto
import os
import sys
import datetime

HOME = os.getcwd()
TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA
now = datetime.datetime.now()
d = now.date()

key = crypto.PKey()


def generate_key(pub_key_file, prv_key_file):
    print("Key generation")
    key.generate_key(TYPE_RSA, 4096)
    f = open(pub_key_file, "w")
    g = open(prv_key_file, "w")
    f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))
    g.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    f.close()
    g.close()
