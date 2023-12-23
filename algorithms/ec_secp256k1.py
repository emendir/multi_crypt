"""Cryptographic applications library based on elliptic curve cryptography."""


from ecies.utils import generate_key
import ecies
import coincurve
from errors import EncryptionOptionError, SignatureOptionError

FAMILY_NAME = "EC-secp256k1"

ENCRYPTION_OPTIONS = [
    "AES_256_GCM"
]
SIGNATURE_OPTIONS = [
    "SHA256"
]

DEFAULT_KEY_LENGTH = 2048
DEFAULT_ENCRYPTION_OPTION = "AES_256_GCM"
DEFAULT_SIGNATURE_OPTION = "SHA256"


def generate_keys(keylength: int = DEFAULT_KEY_LENGTH):
    """Generate a pair of public and private keys.
    Parameters:
        keylength (int): the number of bits the key is composed of
    Returns:
        tuple: tuple of bytearrays, a public key and a private key
    """
    if not keylength:
        keylength = DEFAULT_KEY_LENGTH
    key = generate_key()

    public_key = bytearray(key.public_key.format(False))
    private_key = bytearray(key.secret)

    return (public_key, private_key)


def derive_public_key(private_key: bytearray):
    """Given a private key, generate the corresponding public key.
    Parameters:
        private_key (bytearray): the private key
    Returns:
        bytearray: the public key
    """
    key = coincurve.PrivateKey.from_hex(private_key.hex())
    return key.public_key.format(False)


def encrypt(data_to_encrypt: bytearray, public_key, encryption_options=""):
    """Encrypt the provided data using the specified public key.
    Parameters:
        data_to_encrypt (bytearray): the data to encrypt
        public_key (bytearray): the public key to be used for the encryption
        encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
    Returns:
        bytearray: the encrypted data
    """
    if not encryption_options:
        encryption_options = DEFAULT_ENCRYPTION_OPTION

    if encryption_options == "AES_256_GCM":
        return bytearray(
            ecies.encrypt(public_key.hex(), bytes(data_to_encrypt))
        )
    raise EncryptionOptionError(encryption_options)


def decrypt(
    encrypted_data: bytearray,
    private_key: bytearray,
    encryption_options=""
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
    if not encryption_options:
        encryption_options = DEFAULT_ENCRYPTION_OPTION

    if encryption_options == "AES_256_GCM":
        return ecies.decrypt(private_key.hex(),  bytes(encrypted_data))

    raise EncryptionOptionError(encryption_options)


def sign(data: bytes, private_key: bytearray, signature_options=""):
    """Sign the provided data using the specified private key.
    Parameters:
        data (bytearray): the data to sign
        private_key (bytearray): the private key to be used for the signing
        signature_options (str): specification code for which
                                signature/verification protocol should be used
    Returns:
        bytearray: the signature
    """
    key = coincurve.PrivateKey.from_hex(private_key.hex())

    if not signature_options:
        signature_options = DEFAULT_SIGNATURE_OPTION

    if signature_options == "SHA256":
        return key.sign(data, hasher=coincurve.utils.sha256)

    raise SignatureOptionError(signature_options)


def verify_signature(
    signature: bytes,
    data: bytes,
    public_key: bytes,
    signature_options=""
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
    if not signature_options:
        signature_options = DEFAULT_SIGNATURE_OPTION

    if signature_options == "SHA256":
        return coincurve.verify_signature(
            bytes(signature),
            bytes(data),
            bytes(public_key),
            hasher=coincurve.utils.sha256
        )
    raise SignatureOptionError(signature_options)


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
