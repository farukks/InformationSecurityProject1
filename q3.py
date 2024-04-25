import hashlib
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Load image data
with open('q3_materials/img1.png', 'rb') as file:
    image_data = file.read()

# SHA256 hash
hash_object = hashlib.sha256()
hash_object.update(image_data)
message_digest = hash_object.digest()

# RSA key pair
private_key = serialization.load_pem_private_key(
    open('KB_private_key.pem', 'rb').read(),
    password=None,
    backend=openssl.backend
)

# Create digital signature
signature = private_key.sign(
    message_digest,
    ec.ECDSA(hashes.SHA256())
)

# Verify digital signature
public_key = serialization.load_pem_public_key(
    open('KB_public_key.pem', 'rb').read(),
    backend=openssl.backend
)

try:
    public_key.verify(
        signature,
        message_digest,
        ec.ECDSA(hashes.SHA256())
    )
    print("Digital Signature Verification: True")
    print("Message Digest: ", message_digest)
    print("Digital Signature: ", signature)
    print("Image Data: ", image_data)
except:
    print("Digital Signature Verification: False")
