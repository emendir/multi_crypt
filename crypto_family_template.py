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
    Args:
        keylength (int): the number of bits the key is composed of
    Returns:
        tuple: tuple of bytess, a public key and a private key
    """
    private_key: bytes
    public_key: bytes
    return (public_key, private_key)


def derive_public_key(
    private_key: bytes
):
    """Given a private key, generate the corresponding public key.
    Args:
        private_key (bytes): the private key
    Returns:
        bytes: the public key
    """
    public_key: bytes
    return public_key


def encrypt(
    data_to_encrypt: bytes,
    public_key: bytes,
    encryption_options: str = DEFAULT_ENCRYPTION_OPTION
):
    """Encrypt the provided data using the specified public key.
    Args:
        data_to_encrypt (bytes): the data to encrypt
        public_key (bytes): the public key to be used for the encryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytes: the encrypted data
    """
    cipher: bytes
    return cipher


def decrypt(
    data_to_decrypt: bytes,
    private_key: bytes,
    encryption_options: str = DEFAULT_ENCRYPTION_OPTION
):
    """Decrypt the provided data using the specified private key.
    Args:
        data_to_decrypt (bytes): the data to decrypt
        private_key (bytes): the private key to be used for the decryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytes: the encrypted data
    """
    plaintext: bytes
    return plaintext


def sign(
    data: bytes,
    private_key: bytes,
    signature_options: str = DEFAULT_SIGNATURE_OPTION
):
    """Sign the provided data using the specified private key.
    Args:
        data (bytes): the data to sign
        private_key (bytes): the private key to be used for the signing
        signature_options (str): specification code for which
                                signature/verification protocol should be used
    Returns:
        bytes: the signature
    """
    signature: bytes
    return signature


def verify_signature(
    family: str,
    signature: bytes,
    data: bytes,
    public_key: bytes,
    signature_options: str = DEFAULT_SIGNATURE_OPTION
):
    """Verify the provided signature of the provided data using the specified
    private key.
    Args:
        signature (bytes): the signaure to verify
        data (bytes): the data to sign
        public_key (bytes): the public key to verify the signature against
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
