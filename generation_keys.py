import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from load_functions import save_public_key, save_private_key, save_symmetric_key
from encryption import asymmetric_encrypt


def generate_symmetric_key(length: int) -> bytes:
    """Generates a symmetric key for symmetric encryption algorithm.
    Args:
        length (int): Key length in bytes.
    Returns:
        bytes: Symmetric key.
    """
    symmetric_key = os.urandom(length)
    logging.info("Symmetric key generated")
    return symmetric_key


def generate_asymmetric_keys() -> tuple:
    """Generates an asymmetric key for asymmetric encryption algorithm.
    Returns:
        tuple: Asymmetric keys.
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    logging.info("Asymmetric key generated")
    return private_key, public_key


def create_keys(length: int, settings: dict) -> None:
    """Generates symmetric, public and private keys, 
    stores them in the specified paths and decrypts the symmetric key using the public key.
    Args:
        length (int): Symmetric key length.
        settings (dict): Dictionary with paths.
    """
    if length == 128 or length == 192 or length == 256:
        length = int(length/8)
        symmetric_key = generate_symmetric_key(length)
        private_key, public_key = generate_asymmetric_keys()
        save_public_key(public_key, settings['public'])
        save_private_key(private_key, settings['private'])
        ciphered_key = asymmetric_encrypt(public_key, symmetric_key)
        save_symmetric_key(ciphered_key, settings['symmetric_key'])
        logging.info(
            "Symmetric and asymmetric keys generated and written to a file")
    else:
        logging.info(
            "Invalid key length: the key length should be 128/192/256 in 8-bit increments")
        raise ValueError