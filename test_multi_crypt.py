import multi_crypt
from multi_crypt import encrypt, decrypt, sign, verify_signature, generate_keys, check_private_key
from termcolor import colored as coloured

PYTEST = False
BREAKPOINTS = False


def mark(success, message):
    """Returns a check or cross character depending on the input success."""
    if success:
        mark = coloured("✓", "green")
    else:
        mark = coloured("✗", "red")
        if BREAKPOINTS:
            breakpoint()
    print(mark, message)
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


def test_encryption_decryption(family, encryption_options=None):
    public_key, private_key = generate_keys(family, )
    original_data = b"Hello, World!"

    encrypted_data = encrypt(family, original_data, public_key, encryption_options)
    decrypted_data = decrypt(family, encrypted_data, private_key, encryption_options)

    mark(decrypted_data == original_data, f"{family}-{encryption_options}: Encryption & Decryption")


def test_signing_verification(family, signature_options=None):
    public_key, private_key = generate_keys(family, )
    original_data = b"Hello, World!"

    signature = sign(family, original_data, private_key, signature_options)
    is_verified = verify_signature(
        family, original_data, public_key, signature, signature_options)

    mark(is_verified, f"{family}-{signature_options}: Signing & Verification")


def test_check_private_key(family, ):
    public_key, private_key = generate_keys(family, )
    mark(check_private_key(family, public_key, private_key), "Private Key Check")


def run_tests():
    for family in multi_crypt.get_all_families():
        test_check_private_key(family, )
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
