from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

# Generate RSA key pair for encryption/decryption
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt message using RSA public key
def rsa_encrypt(public_key, message):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Decrypt message using RSA private key
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Generate symmetric keys using HKDF
def generate_symmetric_key(length, salt):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(os.urandom(32))  # Using 32 bytes of random data as input

# Save data to file
def save_data(filename, data):
    with open(filename, "w") as file:
        file.write(data.hex())

# Generate RSA key pair
private_key_ka, public_key_ka = generate_rsa_keys()

# Generate two symmetric keys
salt = os.urandom(16)  # Secure random salt
key_1 = generate_symmetric_key(16, salt)  # K1 - 128-bit key
key_2 = generate_symmetric_key(32, salt)  # K2 - 256-bit key

# Print symmetric keys
print("K1 (128-bit):", key_1.hex())
print("K2 (256-bit):", key_2.hex())

# Encrypt the keys with KA+
encrypted_key_1 = rsa_encrypt(public_key_ka, key_1)
encrypted_key_2 = rsa_encrypt(public_key_ka, key_2)

# Print encrypted keys
print("Encrypted K1:", encrypted_key_1.hex())
print("Encrypted K2:", encrypted_key_2.hex())

# Decrypt the keys with KA-
decrypted_key_1 = rsa_decrypt(private_key_ka, encrypted_key_1)
decrypted_key_2 = rsa_decrypt(private_key_ka, encrypted_key_2)

# Print decrypted keys
print("Decrypted K1 (128-bit):", decrypted_key_1.hex())
print("Decrypted K2 (256-bit):", decrypted_key_2.hex())

# Save keys to files
save_data("K1_original.txt", key_1)
save_data("K2_original.txt", key_2)
save_data("K1_encrypted.txt", encrypted_key_1)
save_data("K2_encrypted.txt", encrypted_key_2)
save_data("K1_decrypted.txt", decrypted_key_1)
save_data("K2_decrypted.txt", decrypted_key_2)
