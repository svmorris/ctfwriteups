# import ecdsa
# import random


# priv_key = b"\x02\xb2\x7b\xd5\x53\x37\x9c\x6e\xf0\x3c\x96\x6f\xf2\xf7\xd2\x3b\x34\x01\x0e\xf0\x69\x6f\x8e\x16\x64\xcc\xd6\xba\xf2\x99\xa6\xb5"
# # p = b"2b27bd553379c6ef03c966ff2f7d23b34010ef0696f8e1664ccd6baf299a6b5"

# sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
# vk = sk.get_verifying_key()
# sig = sk.sign(b"admin")
# found = "".join("{:02x}".format(c) for c in sig)
# print(found)

# https://crypto.stackexchange.com/questions/57846/recovering-private-key-from-secp256k1-signatures
import ecdsa, hashlib
from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import Signature
from ecdsa import SigningKey, VerifyingKey, der
from pwn import *

curve          = ecdsa.SECP256k1
text_to_sign   = b"admin"
hash_algorithm = hashlib.sha1

def get_key_from_hash():

    m_hash1 = '21298df8a3277357ee55b01df9530b535cf08ec1'
    sig1_hex = '13d8f71de2338048bcddd4846ea9762fa022172b6602f269c519892d8bf7e94f77608e0387a7ba5392bd1e2b4ded1048133fb584b7686233af00a6e7c5d427e7'
    m_hash2 = 'c692d6a10598e0a801576fdd4ecf3c37e45bfbc4'
    sig2_hex = '13d8f71de2338048bcddd4846ea9762fa022172b6602f269c519892d8bf7e94fdcb6d55b347bfbe8c6a37e2b7c6ca764d7bd07f52d56df2ff80df7a59cbe51ec'

    m_hash1 = int(m_hash1, 16)
    r = int(sig1_hex[:len(sig1_hex)//2], 16)
    sig1 = int(sig1_hex[len(sig1_hex)//2:], 16)
    m_hash2 = int(m_hash2, 16)
    sig2 = int(sig2_hex[len(sig2_hex)//2:], 16)

    print("m_hash1 = " + hex(m_hash1))
    print("sig1 = " + hex(sig1))
    print("m_hash2 = " + hex(m_hash2))
    print("sig2 = " + hex(sig2))
    print("r = " + hex(r))

    r_i = inverse_mod(r, curve.order)
    m_h_diff = (m_hash1 - m_hash2) % curve.order

    for k_try in (sig1 - sig2, sig1 + sig2, -sig1 - sig2, -sig1 + sig2):

        k = (m_h_diff * inverse_mod(k_try, curve.order)) % curve.order

        s_E = (((((sig1 * k) % curve.order) - m_hash1) % curve.order) * r_i) % curve.order

        key = SigningKey.from_secret_exponent(s_E, curve=curve, hashfunc=hash_algorithm)

        if key.get_verifying_key().pubkey.verifies(m_hash1, Signature(r, sig1)):
            print("ECDSA Private Key = " + "".join("{:02x}".format(c) for c in key.to_string())) # If we got here we found a solution
            return key

def sign_text(priv_key):
    sk = ecdsa.SigningKey.from_string(priv_key.to_string(), curve=curve)
    vk = sk.get_verifying_key()
    sig = sk.sign(text_to_sign)
    signed_message = "".join("{:02x}".format(c) for c in sig)
    return "{},{}".format(text_to_sign.decode("utf-8"), signed_message)

def send_message(s_m):
    target = remote('chal.cybersecurityrumble.de', 10100)
    print("Sending '{}'".format(s_m))
    target.sendline(s_m)
    target.interactive()

signed_message = sign_text(get_key_from_hash())
print(send_message(signed_message))
