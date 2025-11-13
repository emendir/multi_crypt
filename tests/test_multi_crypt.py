"""Automated tests for multi_crypt"""

from datetime import datetime
from termcolor import colored as coloured

if True:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    import multi_crypt
    from multi_crypt import (
        generate_keys, check_key_pair,
        encrypt, decrypt,
        sign, verify_signature
    )
# pylint: disable=missing-function-docstring
# pylint: disable=global-statement

PYTEST = False
BREAKPOINTS = False


def mark(success, message, duration):
    """Prints a test report comprising of check or cross depending on the input
    test success along with the provided message."""
    if success:
        mark_symbol = coloured("✓", "green")
    else:
        mark_symbol = coloured("✗", "red")
        if BREAKPOINTS:
            breakpoint()
    print(
        mark_symbol,
        message,
        coloured(str(round(duration.total_seconds()*100000)/100)+"ms", "yellow")
    )
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


def test_key_generation_check(family, ):
    start_time = datetime.utcnow()
    public_key, private_key = generate_keys(family, )

    keypair_valid = check_key_pair(family, private_key, public_key)
    duration = (datetime.utcnow() - start_time)

    mark(
        keypair_valid,
        f"{family}: Key Pair Check",
        duration
    )


def test_encryption_decryption(family, encryption_options=None):
    public_key, private_key = generate_keys(family, )
    original_data = b"Hello there!"

    start_time = datetime.utcnow()
    encrypted_data = encrypt(family, original_data,
                             public_key, encryption_options)
    decrypted_data = decrypt(family, encrypted_data,
                             private_key, encryption_options)
    duration = (datetime.utcnow() - start_time)
    mark(
        decrypted_data == original_data,
        f"{family}-{encryption_options}: Encryption & Decryption",
        duration
    )


def test_signing_verification(family, signature_options=None):
    public_key, private_key = generate_keys(family, )
    data = b"Hello there!"
    alt_data = b"Hello, World!"

    start_time = datetime.utcnow()
    signature = sign(family, data, private_key, signature_options)
    is_verified = verify_signature(
        family, signature, data, public_key, signature_options
    )
    duration = (datetime.utcnow() - start_time)

    alt_signature = sign(family, alt_data, private_key, signature_options)
    # this verification should return False
    is_verified_alt = verify_signature(
        family, alt_signature, data, public_key, signature_options
    )
    mark(
        is_verified and not is_verified_alt,
        f"{family}-{signature_options}: Signing & Verification",
        duration
    )


def run_tests():
    print("Running tests for all algorithms:")

    for family in multi_crypt.get_all_families():
        test_key_generation_check(family, )
    for family in multi_crypt.get_encryption_families():
        test_encryption_decryption(family)
        for option in multi_crypt.get_encrytpion_options(family):
            test_encryption_decryption(family, option)
    for family in multi_crypt.get_signature_families():
        test_signing_verification(family)
        for option in multi_crypt.get_signature_options(family):
            test_signing_verification(family, option)


if __name__ == '__main__':
    run_tests()
