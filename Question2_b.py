from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Generate Elliptic Curve key pairs
def generate_ec_keys():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

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

# Generate key pairs for KB and KC
private_key_kb, public_key_kb = generate_ec_keys()
private_key_kc, public_key_kc = generate_ec_keys()

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
