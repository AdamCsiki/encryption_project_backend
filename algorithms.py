from __future__ import print_function

import binascii
import hashlib
import json
import base64

import sys

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16


def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def pad_bytes(s):
    padding = BLOCK_SIZE - len(s) % BLOCK_SIZE
    return s + bytes([padding] * padding)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def unpad_bytes(s):
    padding = s[-1]
    return s[:-padding]


def aes_encrypt(message: str | bytes, key: str):
    key = key.encode("utf-8")

    iv = get_random_bytes(BLOCK_SIZE)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    if not isinstance(message, bytes):
        # padding the message
        encrypted = pad(message).encode("utf-8")
    else:
        encrypted = pad_bytes(message)

    encrypted = cipher.encrypt(encrypted)

    return base64.b64encode(iv + encrypted).decode()


# Tot ce face e ca desparte iv-ul de mesajul encriptat
# asta dupa ce a fo convertit din base64 in bytes
def aes_breaker(encrypted):
    return encrypted[:BLOCK_SIZE], encrypted[BLOCK_SIZE:]


def aes_decrypt(encrypted: str | bytes, key: str):
    key = key.encode("utf-8")
    encrypted = base64.b64decode(encrypted)

    iv, encrypted = aes_breaker(encrypted)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    message = cipher.decrypt(encrypted)

    if not isinstance(message, bytes):
        # padding the message
        message = unpad(message).decode()
    else:
        message = unpad_bytes(message)

    return message


def des_encrypt(message: str | bytes, key: str):
    m = hashlib.md5(key.encode())
    key = m.digest()

    (dk, iv) = (key[:8], key[8:])
    cipher = DES.new(dk, DES.MODE_CBC, iv)

    if not isinstance(message, bytes):
        # padding the message
        encrypted = pad(message).encode("utf-8")
    else:
        encrypted = pad_bytes(message)

    encrypted = cipher.encrypt(encrypted)

    return base64.b64encode(encrypted).decode()


def des_decrypt(encrypted: str | bytes, key: str):
    m = hashlib.md5(key.encode())
    key = m.digest()
    encrypted = base64.b64decode(encrypted)

    (dk, iv) = (key[:8], key[8:])
    cipher = DES.new(dk, DES.MODE_CBC, iv)

    message = cipher.decrypt(encrypted)

    if not isinstance(message, bytes):
        # padding the message
        message = unpad(message).decode()
    else:
        message = unpad_bytes(message)

    return message.decode()
