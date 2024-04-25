from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Function to load an elliptic curve private key from a PEM file
def load_ec_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Add password here if your key is encrypted
            backend=default_backend()
        )
    return private_key

# Function to load an elliptic curve public key from a PEM file
def load_ec_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# Derive a symmetric key using ECDH
def derive_symmetric_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# Load key pairs for KB and KC from PEM files
private_key_kb = load_ec_private_key('KB_private_key.pem')
public_key_kb = load_ec_public_key('KB_public_key.pem')
private_key_kc = load_ec_private_key('KC_private_key.pem')
public_key_kc = load_ec_public_key('KC_public_key.pem')

# Derive symmetric keys
# K3 using KC+ (public key of KC) and KB- (private key of KB)
key_3_kc_kb = derive_symmetric_key(private_key_kc, public_key_kb)

# Generate symmetric key using KB+ (public key of KB) and KC- (private key of KC)
key_3_kb_kc = derive_symmetric_key(private_key_kb, public_key_kc)

# Print the keys
print("Key derived using KC+ and KB-:", key_3_kc_kb.hex())
print("Key derived using KB+ and KC-:", key_3_kb_kc.hex())

# Check if both keys are the same
if key_3_kc_kb == key_3_kb_kc:
    print("Both keys are identical, key agreement successful!")
else:
    print("Keys are not identical, check configuration.")
