import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_pem, pub_pem

def rsa_encrypt_data(data: bytes, pub_pem: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    key_size_bytes = public_key.key_size // 8

    chunk_size = key_size_bytes - 2 * 32 - 2

    out = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        enc_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        out.extend(enc_chunk)

    return bytes(out)

def rsa_decrypt_data(data: bytes, priv_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
    key_size_bytes = private_key.key_size // 8

    out = bytearray()
    for i in range(0, len(data), key_size_bytes):
        chunk = data[i:i + key_size_bytes]
        dec_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        out.extend(dec_chunk)

    return bytes(out)