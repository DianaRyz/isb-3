import os
import logging
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from load_functions import load_private_key, load_symmetric_key, read_text, write_text
from decryption import asymmetric_decrypt


def asymmetric_encrypt(public_key, text: bytes) -> bytes:
    """Encrypts an input text using public key.
    Args:
        public_key: Public key of asymmetric encryption algorithm.
        text (bytes): Text for encryption.
    Returns:
        bytes: Encrypted text.
    """
    cipher_text = public_key.encrypt(
        text,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    logging.info("The text using the public key has been encrypted")
    return cipher_text


def symmetric_encrypt(key: bytes, text: bytes) -> bytes:
    """Encrypts an input text using symmetric key.
    Args:
        key (bytes): Symmetric key of symmetric encryption algorithm.
        text (bytes): Text for encryption.
    Returns:
        bytes: Encrypted text.
    """
    padder = symmetric_padding.ANSIX923(128).padder()
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_text) + encryptor.finalize()
    logging.info("The text using the symmetric key has been encrypted")
    return iv + cipher_text


def encryption_text(settings: dict) -> None:
    """Reads the saves keys and encrypts the specified text, writing it to a new text file.
    Args:
        settings (dict): Dictionary with paths.
    """
    private_key = load_private_key(settings["private"])
    cipher_key = load_symmetric_key(settings["symmetric_key"])
    symmetric_key = asymmetric_decrypt(private_key, cipher_key)
    text = read_text(settings["initial_text"])
    cipher_text = symmetric_encrypt(symmetric_key, text)
    write_text(cipher_text, settings["encrypted_text"])
    logging.info("The text using the keys has been encrypted")