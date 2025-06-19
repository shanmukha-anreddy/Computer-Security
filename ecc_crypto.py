from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# ECC Key Generation
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Save/Load Keys
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_private_key_from_pem(pem_input):
    if isinstance(pem_input, str):
        pem_bytes = pem_input.encode('utf-8')
    elif isinstance(pem_input, bytes):
        pem_bytes = pem_input
    else:
        raise TypeError(f"PEM input must be string or bytes, got {type(pem_input)}")
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None,
        backend=default_backend()
    )

def serialize_private_key_to_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def serialize_public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def load_public_key(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_public_key_from_pem(pem_input):
    if isinstance(pem_input, str):
        pem_bytes = pem_input.encode('utf-8')
    elif isinstance(pem_input, bytes):
        pem_bytes = pem_input
    else:
        raise TypeError(f"PEM input must be string or bytes, got {type(pem_input)}")
    return serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )

# ECC Encryption/Decryption

def encrypt_data(public_key, data):
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return ephemeral_public_bytes + iv + encryptor.tag + ciphertext


def decrypt_data(private_key, encrypted_data):
    # Extract ephemeral public key
    pem_end = encrypted_data.find(b'-----END PUBLIC KEY-----') + len(b'-----END PUBLIC KEY-----\n')
    ephemeral_public_bytes = encrypted_data[:pem_end]
    ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_bytes, backend=default_backend())
    iv = encrypted_data[pem_end:pem_end+12]
    tag = encrypted_data[pem_end+12:pem_end+28]
    ciphertext = encrypted_data[pem_end+28:]
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
