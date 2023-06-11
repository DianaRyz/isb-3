import logging
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from load_functions import load_private_key, load_symmetric_key, read_text, write_text


def asymmetric_decrypt(private_key, cipher_text: bytes) -> bytes:
    """Decrypts an asymmetrical ciphertext using private key.
    Args:
        private_key: Private key of asymmetric encryption algorithm.
        cipher_text (bytes): Encrypted text.
    Returns:
        bytes: Decrypted text.
    """
    text = private_key.decrypt(
        cipher_text,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    logging.info(
        "The asymmetric encrypted text using the private key has been decrypted")
    return text


def symmetric_decrypt(key: bytes, cipher_text: bytes) -> bytes:
    """Decrypts a symmetrical ciphertext using symmetric key.
    Args:
        key (bytes): Symmetric key of symmetric encryption algorithm.
        cipher_text (bytes): Encrypted text.
    Returns:
        bytes: Decrypted text.
    """
    cipher_text, iv = cipher_text[16:], cipher_text[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = symmetric_padding.ANSIX923(64).unpadder()
    unpadded_text = unpadder.update(text) + unpadder.finalize()
    logging.info(
        "The symmetrical ciphertext using the symmetric key has been decrypted")
    return unpadded_text


def decryption_text(settings: dict) -> None:
    """Reads an encrypts text file and decrypts the text using keys, saving it to a new file.
    Args:
        settings (dict): Dictionary with paths.
    """
    cipher_text = read_text(settings["encrypted_text"])
    private_key = load_private_key(settings["private"])
    cipher_key = load_symmetric_key(settings["symmetric_key"])
    symmetric_key = asymmetric_decrypt(private_key, cipher_key)
    text = symmetric_decrypt(symmetric_key, cipher_text)
    write_text(text, settings["decrypted_text"])
    logging.info("The text was decrypted and written to a file")