"""
Use this script as a template for creating new modules for MultiCrypt,
adding implementions of additional cryptographic families.

Advice for Building:
- make sure you have read ./CryptoFamilyModules.md to learn about some of the
    specifications such modules should fulfill
- read the docstrings of the provided functions carefully to understand what
    they should do
- read the code of existing modules in the algorithms folder

Instructions for Implementing:
Once you've built your module, simply place it in the algorithms folder and
multicrypt will detect and use it automatically.
"""

FAMILY_NAME = "TEMPLATE"

ENCRYPTION_OPTIONS = [
    ""
]
SIGNATURE_OPTIONS = [
    ""
]

DEFAULT_KEY_LENGTH = 2048
DEFAULT_ENCRYPTION_OPTION = ""
DEFAULT_SIGNATURE_OPTION = ""


def generate_keys(keylength: int = DEFAULT_KEY_LENGTH):
    """Generate a pair of public and private keys.
    Parameters:
        keylength (int): the number of bits the key is composed of
    Returns:
        tuple: tuple of bytearrays, a public key and a private key
    """
    private_key: bytearray
    public_key: bytearray
    return (public_key, private_key)


def derive_public_key(
    private_key: bytearray
):
    """Given a private key, generate the corresponding public key.
    Parameters:
        private_key (bytearray): the private key
    Returns:
        bytearray: the public key
    """
    public_key: bytearray
    return public_key


def encrypt(
    data_to_encrypt: bytearray,
    public_key: bytearray,
    encryption_options: str = DEFAULT_ENCRYPTION_OPTION
):
    """Encrypt the provided data using the specified public key.
    Parameters:
        data_to_encrypt (bytearray): the data to encrypt
        public_key (bytearray): the public key to be used for the encryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytearray: the encrypted data
    """
    cipher: bytearray
    return cipher


def decrypt(
    data_to_decrypt: bytearray,
    private_key: bytearray,
    encryption_options: str = DEFAULT_ENCRYPTION_OPTION
):
    """Decrypt the provided data using the specified private key.
    Parameters:
        data_to_decrypt (bytearray): the data to decrypt
        private_key (bytearray): the private key to be used for the decryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytearray: the encrypted data
    """
    plaintext: bytearray
    return plaintext


def sign(
    data: bytearray,
    private_key: bytearray,
    signature_options: str = DEFAULT_SIGNATURE_OPTION
):
    """Sign the provided data using the specified private key.
    Parameters:
        data (bytearray): the data to sign
        private_key (bytearray): the private key to be used for the signing
        signature_options (str): specification code for which
                                signature/verification protocol should be used
    Returns:
        bytearray: the signature
    """
    signature: bytearray
    return signature


def verify_signature(
    family: str,
    signature: bytearray,
    data: bytearray,
    public_key: bytearray,
    signature_options: str = DEFAULT_SIGNATURE_OPTION
):
    """Verify the provided signature of the provided data using the specified
    private key.
    Parameters:
        signature (bytearray): the signaure to verify
        data (bytearray): the data to sign
        public_key (bytearray): the public key to verify the signature against
        signature_options (str): specification code for which
                                signature/verification protocol should be used
    Returns:
        bool: whether or not the signature matches the data
    """
    authenitcated: bool
    return authenitcated


def get_encrytpion_options():
    """Get the encryption options supported by this cryptographic family.
    Returns:
        list: a list of strings, the supported encryption options
    """
    return ENCRYPTION_OPTIONS


def get_signature_options():
    """Get the signature options supported by this cryptographic family.
    Returns:
        list: a list of strings, the supported signature options
    """
    return SIGNATURE_OPTIONS
