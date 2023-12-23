"""
Cryptographic applications library based on elliptic curve cryptography.
Can be used for asymmetric and symmetric cryptography, signature verification,
and supports password-secured cryptography.
Built on the eciespy, coincurve and hashlib modules.
"""

import hashlib
import os
import traceback
from ecies.utils import generate_key
import ecies
import coincurve
from cryptography.fernet import Fernet
from errors import EncryptionOptionError, SignatureOptionError

FAMILY_NAME = "EC-secp256k1"

encryption_options = [
    ""
]
signature_options = [
    ""
]

DEFAULT_KEY_LENGTH = 2048
DEFAULT_ENCRYPTION_OPTION = ""
DEFAULT_SIGNATURE_OPTION = ""


def generate_keys(keylength: int = DEFAULT_KEY_LENGTH):
    if not keylength:
        keylength = DEFAULT_KEY_LENGTH
    key = generate_key()

    public_key = bytearray(key.public_key.format(False))
    private_key = bytearray(key.secret)

    return (public_key, private_key)


def derive_public_key(private_key: bytearray):
    if isinstance(private_key, bytes) or isinstance(private_key, bytearray):
        private_key = private_key.hex()
    key = coincurve.PrivateKey.from_hex(private_key)
    return key.public_key.format(False)


def encrypt(data_to_encrypt: bytearray, public_key, encryption_options=""):
    if isinstance(data_to_encrypt, str):
        print("data to encrypt must be of type bytearray")
    if isinstance(public_key, bytearray):
        public_key = public_key.hex()
    encrypted_data = ecies.encrypt(public_key, data_to_encrypt)
    return encrypted_data


def decrypt(encrypted_data: bytearray, private_key: bytearray, encryption_options=""):
    if isinstance(private_key, coincurve.keys.PrivateKey):
        key = private_key.to_hex()
    elif isinstance(private_key, bytearray):
        key = private_key.hex()
    elif isinstance(private_key, str):
        key = private_key

    if(type(encrypted_data) == bytearray):
        encrypted_data = bytes(encrypted_data)
    decrypted_data = ecies.decrypt(
        key, encrypted_data)
    return decrypted_data


def sign(data: bytes, private_key: bytearray, signature_options=""):
    if isinstance(private_key, coincurve.keys.PrivateKey):
        key = private_key
    elif isinstance(private_key, bytearray):
        key = coincurve.PrivateKey.from_hex(private_key.hex())
    elif isinstance(private_key, str):
        key = coincurve.PrivateKey.from_hex(private_key)
    return key.sign(data)


def verify_signature(
    signature: bytes,
    data: bytes,
    public_key: bytes,
    signature_options=""
):
    if isinstance(public_key, str):
        public_key = bytes(bytearray.fromhex(public_key))
    elif isinstance(public_key, bytearray):
        public_key = bytes(public_key)

    if isinstance(data, bytearray):
        data = bytes(data)
    if isinstance(signature, bytearray):
        signature = bytes(signature)

    return coincurve.verify_signature(signature, data, public_key)


def get_encrytpion_options():
    return encryption_options


def get_signature_options():
    return signature_options
