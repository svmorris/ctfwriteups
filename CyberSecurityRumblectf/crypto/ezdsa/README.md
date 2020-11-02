# ezdsa

## Description
This task has two parts to it, the first part is the signer. You can send a message to the server and it will sign it and send it back. The second part is the verifier. The verifier will take the message and the signature of the message and verify they match.

## Analysis
Lets take a look at the signer code:
```Python
import socketserver
import random
import ecdsa


key = open("secp256k1-key.pem").read()
sk = ecdsa.SigningKey.from_pem(key)


def sony_rand(n):
    return random.getrandbits(8*n).to_bytes(n, "big")


def sign(data):
    if data == b"admin":
        raise ValueError("Not Permitted!")
    signature = sk.sign(data, entropy=sony_rand)
    return signature


class TCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        data = self.rfile.readline().strip()
        try:
            signature = sign(data).hex()
            self.wfile.write(b"Your token: " + data + b"," + signature.encode())
        except ValueError as ex:
            self.wfile.write(b"Invalid string submitted: " + str(ex).encode())


if __name__ == '__main__':
    server = socketserver.ForkingTCPServer(("0.0.0.0", 10101), TCPHandler)
    server.serve_forever()
```
Basic info we can get from it:
- Every request will call `sign(our_data)`
- `sign()` will check that our input is NOT "admin", and will sign
- It's using some sort or rand function for the entropy of the signer
- The ecdsa curve they are using is "secp256k1"
- We can send it any message (besides "admin") and get the signature of the message

Now lets take a look at the verifier:
```Python
import socketserver
import ecdsa
import pyjokes
from flag import FLAG


key = open("pub.pem").read()
vk = ecdsa.VerifyingKey.from_pem(key) 


def valid_signature(msg, sig):
    try:
        vk.verify(sig, msg)
        return True
    except ecdsa.BadSignatureError:
        return False


class TCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        data = self.rfile.readline().strip()
        user, signature = data.split(b",")
        sig = bytes.fromhex(signature.decode())
        try:
            if valid_signature(user, sig):
                if user == b"admin":
                    self.wfile.write(b"Hello admin! Here is your flag: " + FLAG)
                else:
                    self.wfile.write(pyjokes.get_joke().encode())
            else:
                self.wfile.write(b"Invalid signature!")
        except Exception as ex:
            self.wfile.write(b"Something went wrong!")


if __name__ == '__main__':
    server = socketserver.ForkingTCPServer(("0.0.0.0", 10100), TCPHandler)
    server.serve_forever()
```
Basic info we can get from it:
- The handler will try to first `valid_signature`
- `valid_signature` will use the msg and signature you provided and verify they match
- Checks that the message you send equals "admin" before sending the flag

Since we cannot send "admin" to the signer I had to do some research into how ecdsa works. 

## How the algorithm
An ECDSA signature is a pair of integers `(r,s)`.

The ECDSA signature algorithm works like so:
1. `e = H(m)` where H is a hashing function (i.e sha1, sha256)
2. Pick a random `k` such that `0 < k < n-1`
3. Compute `(x,y) = kG` where G is the prime order of curve
4. `r = x mod n`
5. `s = inverse(k)*(z+r*d) mod n` where d is a private key integer and z is the leftmost bits of e
6. Send `(m,r,s)`

The ECDSA verification algorithm works like so:
1. `e = H(m)`
2. `w = inverse(s) mod n`
3. `u_1 = zw mod n` and `u_2 = zw mod n`
4. `(x,y) = u_1*G + u_2*Q` where Q = d x Q
5. If `r` is congruent with `x mod n` we know the signature is valid

## How we can crack it
When I send the signer different strings to sign i noticed it would always send something with the prefix "13d8f71de2338048bcddd4846ea9762fa022172b6602f269c519892d8bf7e94f".... If we think back to how the ECDSA signature looks `(r,s)` we can see that r is not changing. This means we know that `r = x mod n` has to always be the same. From this information we can figure out that they are using the same "random" `k` everytime. So now lets make two request to the server with different m's. The signer will send us back `(m1,r,s1) and (m2,r,s2)`.

Since we know k is constant we can easily solve for it with the following equation:
```
k = (H(m1) - h(M2)) / (s1 - s2)
```
We then can solve for what x was: 
```
x = (k*s1 - h(m1)) / r
```

With k and x known we can now start writing the script to sign "admin" and send to the server.

## Solution
```Python
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
```
Once you run this script the server will print "Hello admin! Here is your flag: CSR{m33333333333p}".

flag = CSR{m33333333333p}