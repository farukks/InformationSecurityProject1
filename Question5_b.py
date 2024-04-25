from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import binascii

# Function to load a key from a file
def load_key_from_file(file_path):
    with open(file_path, 'r') as file:
        key_hex = file.read().strip()
    return binascii.unhexlify(key_hex)

# Function to apply HMAC-SHA256 to generate a new 256-bit key using an existing key
def generate_new_key_from_hmac(key_bytes):
    # Using HKDF to derive a new key from the HMAC of the original key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=None,
        info=b'key derivation',
        backend=default_backend()
    )
    new_key = hkdf.derive(key_bytes)
    return new_key.hex()

def save_data(filename, data):
    with open(filename, "w") as file:
        file.write(data)

# Load K2 from a file
file_path = 'K2_original.txt'  # Specify the file path where K2 is stored
K2_bytes = load_key_from_file(file_path)

# Generate the new key using K2
new_key_hex = generate_new_key_from_hmac(K2_bytes)
print("New Derived Key:", new_key_hex)

save_data("NewKey_HMAC-SHA256.txt",new_key_hex)