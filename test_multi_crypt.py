import multi_crypt
from multi_crypt import encrypt, decrypt, sign, verify_signature, generate_keys, derive_public_key
from termcolor import colored as coloured
from datetime import datetime
PYTEST = False
BREAKPOINTS = False


def mark(success, message, duration):
    """Returns a check or cross character depending on the input success."""
    if success:
        mark = coloured("✓", "green")
    else:
        mark = coloured("✗", "red")
        if BREAKPOINTS:
            breakpoint()
    print(mark, message, coloured(str(round(duration.total_seconds()*100000)/100)+"ms", "yellow"))
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


def test_key_generation_derivation(family, ):
    start_time = datetime.utcnow()
    public_key, private_key = generate_keys(family, )

    derived_pubkey = derive_public_key(family, private_key)
    duration = (datetime.utcnow() - start_time)

    mark(
        derived_pubkey == public_key,
        f"{family}: Private Key Check",
        duration
    )


def test_encryption_decryption(family, encryption_options=None):
    public_key, private_key = generate_keys(family, )
    original_data = b"Hello, World!"

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
    start_time = datetime.utcnow()
    public_key, private_key = generate_keys(family, )
    original_data = b"Hello, World!"

    signature = sign(family, original_data, private_key, signature_options)
    is_verified = verify_signature(
        family, signature, original_data, public_key, signature_options)
    duration = (datetime.utcnow() - start_time)

    mark(
        is_verified,
        f"{family}-{signature_options}: Signing & Verification",
        duration
    )


def run_tests():
    for family in multi_crypt.get_all_families():
        test_key_generation_derivation(family, )
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
