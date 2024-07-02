"""Automated tests for crypt.Crypt's locking functionality"""

from datetime import datetime
from termcolor import colored as coloured

if True:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from multi_crypt import Crypt, LockedError

# pylint: disable=missing-function-docstring
# pylint: disable=global-statement
# pylint: disable=invalid-name


PYTEST = False
BREAKPOINTS = False

CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests


def mark(success, message, duration=None):
    """Prints a test report comprising of check or cross depending on the input
    test success along with the provided message."""
    if success:
        mark_symbol = coloured("✓", "green")
    else:
        mark_symbol = coloured("✗", "red")
        if BREAKPOINTS:
            breakpoint()
    if duration:
        duration_str = coloured(
            str(round(duration.total_seconds() * 100000) / 100) + "ms",
            "yellow"
        )
    else:
        duration_str = ""
    print(mark_symbol, message, duration_str)
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


crypt: Crypt
encryptor: Crypt


def test_create_encryptor(family):
    global crypt
    global encryptor

    crypt = Crypt.new(family)

    start_time = datetime.utcnow()
    encryptor = Crypt(family, public_key=crypt.public_key)
    duration = (datetime.utcnow() - start_time)

    mark(
        encryptor.public_key == crypt.public_key,
        f"{crypt.family}: Created Crypt",
        duration
    )


def test_encryption(encryption_options=None):
    original_data = b"Hello there!"

    start_time = datetime.utcnow()
    encrypted_data = encryptor.encrypt(original_data)
    duration = (datetime.utcnow() - start_time)

    encryption_success = (
        crypt.decrypt(
            encrypted_data, encryption_options=encryption_options
        ) == original_data
    )
    mark(
        encryption_success,
        f"{crypt.family}-{encryption_options}: Encryption",
        duration
    )


def test_decryption_locking(encryption_options=None):
    original_data = b"Hello there!"
    encrypted_data = crypt.encrypt(original_data)

    locking: bool
    try:
        encryptor.decrypt(encrypted_data)
    except LockedError:
        # Crypt's decrypt successfully raised an exception
        locking = True
    else:
        # encryptor's decrypt didn't raise an error
        locking = False

    mark(
        locking,
        f"{crypt.family}-{encryption_options}: Decryption locks correctly",
    )


def test_signing_locking(signature_options=None):
    data = b"Hello there!"

    locking: bool
    try:
        encryptor.sign(data)
    except LockedError:
        # Crypt's decrypt successfully raised an exception
        locking = True
    else:
        # encryptor's decrypt didn't raise an error
        locking = False
    mark(
        locking,
        f"{crypt.family}-{signature_options}: Signing locks correctly",
    )


def test_verification(signature_options=None):
    data = b"Hello there!"

    signature = crypt.sign(data, signature_options=signature_options)

    start_time = datetime.utcnow()
    is_verified = encryptor.verify_signature(
        signature,
        data,
        signature_options=signature_options
    )
    duration = (datetime.utcnow() - start_time)

    mark(
        is_verified,
        f"{crypt.family}-{signature_options}: Signature verification",
        duration
    )


def test_unlocking(encryption_options=None, signature_options=None):
    encryptor.unlock(crypt.private_key)

    original_data = b"Hello there!"

    start_time = datetime.utcnow()
    encrypted_data = crypt.encrypt(original_data)
    decrypted_data = crypt.decrypt(encrypted_data)
    duration = (datetime.utcnow() - start_time)

    mark(
        decrypted_data == original_data,
        f"{crypt.family}-{encryption_options}: Unlocked decryption",
        duration
    )

    original_data = b"Hello there!"

    start_time = datetime.utcnow()
    signature = crypt.sign(original_data)
    is_verified = crypt.verify_signature(signature, original_data)
    duration = (datetime.utcnow() - start_time)

    mark(
        is_verified,
        f"{crypt.family}-{signature_options}: Unlocked signing",
        duration
    )


def run_tests():
    print("Running tests for Crypt locking:")

    test_create_encryptor(CRYPTO_FAMILY)
    test_encryption()
    test_decryption_locking()
    test_signing_locking()
    test_verification()
    test_unlocking()


if __name__ == '__main__':
    run_tests()
