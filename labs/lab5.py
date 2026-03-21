from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_dsa_keys(key_size=2048):
    private_key = dsa.generate_private_key(key_size=key_size, backend=default_backend())
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


def dsa_sign(data: bytes, priv_pem: bytes) -> str:
    private_key = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
    signature = private_key.sign(data, hashes.SHA256())

    return signature.hex()


def dsa_verify(data: bytes, signature_hex: str, pub_pem: bytes) -> bool:
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        public_key.verify(signature_bytes, data, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False