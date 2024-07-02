"""Automated tests for crypt.Crypt"""

from datetime import datetime
from termcolor import colored as coloured

if True:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from multi_crypt import Crypt
    from multi_crypt import derive_public_key

# pylint: disable=missing-function-docstring
# pylint: disable=global-statement
# pylint: disable=invalid-name

PYTEST = False
BREAKPOINTS = False

CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests


def mark(success, message, duration):
    """Prints a test report comprising of check or cross depending on the input
    test success along with the provided message."""
    if success:
        mark_symbol = coloured("✓", "green")
    else:
        mark_symbol = coloured("✗", "red")
        if BREAKPOINTS:
            breakpoint()
    print(mark_symbol, message, coloured(
        str(round(duration.total_seconds() * 100000) / 100) + "ms", "yellow"))
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


crypt: Crypt


def test_create_crypt(family, ):
    global crypt
    start_time = datetime.utcnow()
    crypt = Crypt.new(family)

    reconstructed_crypt = Crypt(family, crypt.private_key)
    duration = (datetime.utcnow() - start_time)

    key_sanity = crypt.public_key == derive_public_key(family, crypt.private_key)
    reconstruction_success = (
        crypt.private_key == reconstructed_crypt.private_key
        and crypt.public_key == reconstructed_crypt.public_key
    )

    mark(
        key_sanity and reconstruction_success,
        f"{crypt.family}: Private Key Check",
        duration
    )


def test_encryption_decryption(encryption_options=None):
    original_data = b"Hello there!"

    start_time = datetime.utcnow()
    encrypted_data = crypt.encrypt(original_data)
    decrypted_data = crypt.decrypt(encrypted_data)
    duration = (datetime.utcnow() - start_time)

    mark(
        decrypted_data == original_data,
        f"{crypt.family}-{encryption_options}: Encryption & Decryption",
        duration
    )


def test_signing_verification(signature_options=None):
    original_data = b"Hello there!"

    start_time = datetime.utcnow()
    signature = crypt.sign(original_data)
    is_verified = crypt.verify_signature(signature, original_data)
    duration = (datetime.utcnow() - start_time)

    mark(
        is_verified,
        f"{crypt.family}-{signature_options}: Signing & Verification",
        duration
    )


def run_tests():
    print("Running tests for Crypt:")
    test_create_crypt(CRYPTO_FAMILY)
    test_encryption_decryption()
    test_signing_verification()


if __name__ == '__main__':
    run_tests()
