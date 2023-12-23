"""Cryptographic applications library based on the RSA algorithm."""
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512
from errors import EncryptionOptionError, SignatureOptionError

FAMILY_NAME = "RSA"

encryption_options = [
    "PKCS1_OAEP"
]
signature_options = [
    "SHA256-PKCS1_15",
    "SHA512-PKCS1_15"
]

DEFAULT_KEY_LENGTH = 2048
DEFAULT_ENCRYPTION_OPTION = "PKCS1_OAEP"
DEFAULT_SIGNATURE_OPTION = "SHA256-PKCS1_15"


def generate_keys(keylength: int = DEFAULT_KEY_LENGTH):
    if not keylength:
        keylength = DEFAULT_KEY_LENGTH
    key = RSA.generate(keylength)
    public_key = key.publickey().export_key(format='DER')
    private_key = key.export_key(format='DER')

    return (bytearray(public_key), bytearray(private_key))


def derive_public_key(private_key: bytearray):
    private_key_obj = RSA.import_key(private_key)
    return bytearray(private_key_obj.publickey().export_key(format='DER'))


def encrypt(data_to_encrypt: bytearray, public_key: bytearray, encryption_options=DEFAULT_ENCRYPTION_OPTION):
    if not encryption_options:
        encryption_options = DEFAULT_ENCRYPTION_OPTION
    if encryption_options == "PKCS1_OAEP":
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted_data = cipher.encrypt(data_to_encrypt)
        return bytearray(encrypted_data)
    else:
        raise EncryptionOptionError(encryption_options)


def decrypt(data_to_decrypt: bytearray, private_key: bytearray, encryption_options=DEFAULT_ENCRYPTION_OPTION):
    if not encryption_options:
        encryption_options = DEFAULT_ENCRYPTION_OPTION
    if encryption_options == "PKCS1_OAEP":
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_data = cipher.decrypt(data_to_decrypt)
        return bytearray(decrypted_data)
    else:
        raise EncryptionOptionError(encryption_options)


def sign(data: bytearray, private_key: bytearray, signature_options=DEFAULT_SIGNATURE_OPTION):
    if not signature_options:
        signature_options = DEFAULT_SIGNATURE_OPTION
    if signature_options == "SHA256-PKCS1_15":
        key = RSA.import_key(private_key)
        h = SHA256.new(data)
        signature = pkcs1_15.new(key).sign(h)
        return bytearray(signature)
    elif signature_options == "SHA512-PKCS1_15":
        key = RSA.import_key(private_key)
        h = SHA512.new(data)
        signature = pkcs1_15.new(key).sign(h)
        return bytearray(signature)
    else:
        raise SignatureOptionError(signature_options)


def verify_signature(
        signature: bytearray,
        data: bytearray,
        public_key: bytearray,
        signature_options=DEFAULT_SIGNATURE_OPTION):
    if not signature_options:
        signature_options = DEFAULT_SIGNATURE_OPTION
    if signature_options == "SHA256-PKCS1_15":
        key = RSA.import_key(public_key)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    elif signature_options == "SHA512-PKCS1_15":
        key = RSA.import_key(public_key)
        h = SHA512.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    else:
        raise SignatureOptionError(signature_options)


def get_encrytpion_options():
    return encryption_options


def get_signature_options():
    return signature_options
