"""This module contains Crypt, a class that enables an object-oriented approach
to working with cryptography.
For a functional approach, use multicrypt, with Crypt is based on.
Crypt implements all the functionality of multi_crypt."""

from utils import to_bytearray
from multi_crypt import (  # pylint:disable=unused-import
    generate_keys, derive_public_key,
    encrypt, decrypt,
    sign, verify_signature,
    get_all_families,
    get_encryption_families,
    get_signature_families,
    get_encrytpion_options,
    get_signature_options,
)


class Crypt:
    """An object for performing various cryptographic operations.

    It provides public and private key generation & verification,
    encryption & decryption and signing & signature-verification functionality.
    If can even be used if only a public key is provided, limiting it to only
    encryption and signature verification, but can of course be unlocked from
    this state to enable full functionality.
    """

    public_key: bytearray
    private_key: bytearray

    def __init__(
        self,
        family: str,
        private_key: bytearray = None,
        public_key: bytearray = None
    ):
        """Create a Crypt object for an existing set of cryptographic keys.

        To create a Crypt with newly generated keys, use `Crypt.new()`
        Supplying a private key will enable all cryptographic operations,
        supplying a public key only will enable only encryption and signature
        verification.

        Parameters:
            family (str): the cryptographic family of the keys
            private_key (bytearray): the private key. Required for the ability
                                    to decrypt and sign data
            public_key (bytearray): the public key. Not required if private_key
                                    is supplied
        Returns:
            Crypt: Crypt object for performing cryptographic operations
        """
        self.family = family
        if private_key:
            # type checking private key
            self.private_key = to_bytearray(private_key, "private_key")
            self.public_key = derive_public_key(self.family, self.private_key)
        else:
            self.private_key = None
        if public_key:
            public_key = to_bytearray(public_key, "private_key")
            if private_key:
                if not self.public_key == public_key:
                    raise KeyMismatchError()
            self.public_key = public_key
        elif not private_key:
            raise ValueError(
                "Either private_key or public_key must be supplied."
            )

    @staticmethod
    def new(family: str, keylength: int = None):
        """Create a Crypt object from a newly generated pair of public and
        private keys.
        Parameters:
            family (str): the cryptographic family of the keys
            keylength (int): the number of bits the key is composed of
        Returns:
            Crypt: Crypt object for performing cryptographic operations
        """
        # pylint: disable=unused-variable
        public_key, private_key = generate_keys(
            family=family, keylength=keylength
        )
        return Crypt(family, private_key)

    def unlock(self, private_key):
        """Unlock the Crypt with a private key to enable decryption and signing
        if the Crypt was initiated with only a public key.
        Parameters:
            private_key (bytearray): the private key corresponding to this
                                    Crypt's public key
        """
        # type checking private key
        private_key = to_bytearray(private_key, "private_key")

        if derive_public_key(self.family, private_key) != self.public_key:
            raise ValueError((
                "Wrong private key! The given private key does not match this "
                "encryptor's public key."
            ))
        self.private_key = private_key

    def encrypt(
        self,
        data_to_encrypt: bytearray,
        encryption_options: str = None
    ):
        """Encrypt the provided data using the specified public key.
        Parameters:
            data_to_encrypt (bytearray): the data to encrypt
            encryption_options (str): specification code for which
                                    encryption/decryption protocol should be used
        Returns:
            bytearray: the encrypted data
        """
        return encrypt(
            self.family,
            data_to_encrypt,
            self.public_key,
            encryption_options=encryption_options
        )

    def decrypt(
        self,
        encrypted_data: bytearray,
        encryption_options: str = None
    ):
        """Decrypt the provided data using the specified private key.
        Parameters:
            data_to_decrypt (bytearray): the data to decrypt
            encryption_options (str): specification code for which
                                    encryption/decryption protocol should be used
        Returns:
            bytearray: the encrypted data
        """
        if not self.private_key:
            raise LockedError()
        return decrypt(
            self.family,
            encrypted_data,
            self.private_key,
            encryption_options=encryption_options
        )

    def sign(self, data: bytes, signature_options: str = None):
        """Sign the provided data using the specified private key.
        Parameters:
            data (bytearray): the data to sign
            private_key (bytearray): the private key to be used for the signing
            signature_options (str): specification code for which
                                    signature/verification protocol should be used
        Returns:
            bytearray: the signature
        """
        if not self.private_key:
            raise LockedError()
        return sign(
            self.family,
            data,
            self.private_key,
            signature_options=signature_options
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        signature_options: str = None
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
        return verify_signature(
            self.family,
            signature,
            data,
            self.public_key,
            signature_options=signature_options
        )

    def get_private_key(self, key_type=bytearray):
        """Returns the private key as the specified type."""
        if key_type == bytearray:
            return self.private_key
        elif key_type == bytes:
            return bytes(self.private_key)
        elif key_type == str:
            return self.private_key.hex()
        else:
            raise ValueError(
                f"Unsupported type '{key_type}'. "
                "Supported types: bytearray, bytes, str"
            )

    def get_public_key(self, key_type=bytearray):
        """Returns the private key as the specified type."""
        if key_type == bytearray:
            return self.public_key
        elif key_type == bytes:
            return bytes(self.public_key)
        elif key_type == str:
            return self.public_key.hex()
        else:
            raise ValueError(
                f"Unsupported type '{key_type}'. "
                "Supported types: bytearray, bytes, str"
            )

    def get_encrytpion_options(self):
        """Get the encryption options supported by this cryptographic family.
        Parameters:
            family (str): the name of the cryptographic famliy to query
        Returns:
            list: a list of strings, the supported encryption options
        """
        return get_encrytpion_options(self.family)

    def get_signature_options(self):
        """Get the signature options supported by this cryptographic family.
        Parameters:
            family (str): the name of the cryptographic famliy to query
        Returns:
            list: a list of strings, the supported signature options
        """
        return get_signature_options(self.family)


class LockedError(Exception):
    """Error when user tries to perform private-key operations with a locked
    Encryptor object."""

    def __str__(self):
        return (
            "This Crypt is locked. "
            "Unlock with Encryptor.unlock() in order to decrypt and sign data."
        )


class KeyMismatchError(Exception):
    """Error when user supplies non-corresponding public and private keys."""
    def_message = "This supplied private and public keys don't match."

    def __init__(self, message=def_message):
        super().__init__()
        self.message = message

    def __str__(self):
        return self.message
