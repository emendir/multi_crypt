"""This script contains MultiCrypt's user API.
It is the single interface to the multitude of cryptographic algorithms living
in ./algorithms.
"""
import os

from utils import load_module_from_path


crypto_modules = dict()


# load all cryptographic family modules from the algorithms folder
for filename in os.listdir("algorithms"):
    module_path = os.path.join("algorithms", filename)
    init_file = os.path.join(module_path, "__init__.py")
    if not (os.path.isfile(module_path) and filename[-3:] == ".py")    \
            and not (os.path.exists(init_file) and os.path.isfile(init_file)):
        continue

    module = load_module_from_path(module_path)
    crypto_modules.update({module.FAMILY_NAME: module})


def generate_keys(family: str, keylength: int = None):
    """Generate a pair of public and private keys to be used with the specified
    family.
    Parameters:
        family (str): the cryptographic family of the keys
        keylength (int): the number of bits the key is composed of
    Returns:
        tuple: tuple of bytearrays, a public key and a private key
    """
    return crypto_modules[family].generate_keys(keylength)


def derive_public_key(
    family: str,
    private_key: bytearray
):
    """Given a private key, generate the corresponding public key.
    Parameters:
        family (str): the cryptographic family of the keys
        private_key (bytearray): the private key
    Returns:
        bytearray: the public key
    """
    return crypto_modules[family].derive_public_key(private_key)


def encrypt(
    family: str,
    data_to_encrypt: bytearray,
    public_key: bytearray,
    encryption_options: str = None
):
    """Encrypt the provided data using the specified public key and encryption
    family.
    Parameters:
        family (str): the cryptographic family to be used for the encryption
        data_to_encrypt (bytearray): the data to encrypt
        public_key (bytearray): the public key to be used for the encryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytearray: the encrypted data
    """
    return crypto_modules[family].encrypt(
        data_to_encrypt,
        public_key,
        encryption_options
    )


def decrypt(
    family: str,
    data_to_decrypt: bytearray,
    private_key: bytearray,
    encryption_options: str = None
):
    """Decrypt the provided data using the specified private key and encryption
    family.
    Parameters:
        family (str): the cryptographic family to be used for the decryption
        data_to_decrypt (bytearray): the data to decrypt
        private_key (bytearray): the private key to be used for the decryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytearray: the encrypted data
    """
    return crypto_modules[family].decrypt(
        data_to_decrypt,
        private_key,
        encryption_options
    )


def sign(
    family: str,
    data: bytearray,
    private_key: bytearray,
    signature_options: str = None
):
    """Sign the provided data using the specified private key and family.
    Parameters:
        family (str): the cryptographic family to be used for the signing
        data (bytearray): the data to sign
        private_key (bytearray): the private key to be used for the signing
        signature_options (str): specification code for which
                                signature/verification protocol should be used
    Returns:
        bytearray: the signature
    """
    return crypto_modules[family].sign(data, private_key, signature_options)


def verify_signature(
    family: str,
    signature: bytearray,
    data: bytearray,
    public_key: bytearray,
    signature_options: str = None
):
    """Verify the provided signature of the provided data using the specified
    private key and family.
    Parameters:
        family (str): the cryptographic family to be used for the signature
                    verification
        signature (bytearray): the signaure to verify
        data (bytearray): the data to sign
        public_key (bytearray): the public key to verify the signature against
        signature_options (str): specification code for which
                                signature/verification protocol should be used
    Returns:
        bool: whether or not the signature matches the data
    """
    return crypto_modules[family].verify_signature(
        signature,
        data,
        public_key,
        signature_options
    )


def get_all_families():
    """Get a list of all the cryptography families implemented by this library.

    Returns:
        list: a list of strings, the names of the supported cryptographic
                families
    """
    return [
        name for name, mod in list(crypto_modules.items())
    ]


def get_encryption_families():
    """Get a list of all the cryptography families implemented by this library
    which support encryption.

    Returns:
        list: a list of strings, the names of the supported cryptographic
                families
    """
    return [
        name for name, mod in list(crypto_modules.items())
        if hasattr(mod, "encrypt") and hasattr(mod, "decrypt")
    ]


def get_encrytpion_options(family):
    """Get the encryption options supported by this cryptographic family.
    Parameters:
        family (str): the name of the cryptographic famliy to query
    Returns:
        list: a list of strings, the supported encryption options
    """
    return crypto_modules[family].get_encrytpion_options()


def get_signature_families():
    """Get a list of all the cryptography families implemented by this library
    which support cryptographic signing.

    Returns:
        list: a list of strings, the names of the supported cryptographic
                families
    """
    return [
        name for name, mod in list(crypto_modules.items())
        if hasattr(mod, "sign") and hasattr(mod, "verify_signature")
    ]


def get_signature_options(family):
    """Get the signature options supported by this cryptographic family.
    Parameters:
        family (str): the name of the cryptographic famliy to query
    Returns:
        list: a list of strings, the supported signature options
    """
    return crypto_modules[family].get_signature_options()
