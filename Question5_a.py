from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
import binascii

# Function to load a symmetric key from a file
def load_key_from_file(file_path):
    with open(file_path, 'r') as file:
        key_hex = file.read().strip()  # Read the key and strip any whitespace
    return binascii.unhexlify(key_hex)  # Convert the hex string back to bytes

# Function to generate HMAC-SHA256 for a given message using a symmetric key
def generate_hmac_sha256(key, message):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return h.finalize()

# Main function to demonstrate HMAC generation using a key from a file
def main():
    # Path to the file containing the symmetric key
    file_path = 'K1_original.txt'  # Change this to your actual file path

    # Load the symmetric key from the file
    key = load_key_from_file(file_path)

    # Define a message
    message = "Sevdiğini söylemek kolay olan ama zor olan durmak hep arkasında."

    # Generate HMAC-SHA256
    hmac_sha256 = generate_hmac_sha256(key, message)

    # Print the HMAC-SHA256 output in hexadecimal format
    print("HMAC-SHA256:", hmac_sha256.hex())
    save_data("HMAC-SHA256.txt", hmac_sha256)

def save_data(filename, data):
    with open(filename, "w") as file:
        file.write(data.hex())


if __name__ == "__main__":
    main()

