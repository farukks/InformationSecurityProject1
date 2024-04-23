from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_ecdh_key_pair(file_prefix):
    # Generate a private key
    private_key = ec.generate_private_key(ec.SECP384R1())
    # Generate the public key
    public_key = private_key.public_key()


    public_key_ECDH = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    private_key_ECDH = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


    with open(f'{file_prefix}_public_key.pem', 'wb') as f:
        f.write(public_key_ECDH)
    with open(f'{file_prefix}_private_key.pem', 'wb') as f:
        f.write(private_key_ECDH)

    return f'{file_prefix}_public_key.pem', f'{file_prefix}_private_key.pem'



kb_files = generate_ecdh_key_pair("KB")
kc_files = generate_ecdh_key_pair("KC")

print(f"Keys for KB saved to: {kb_files[0]} and {kb_files[1]}")
print(f"Keys for KC saved to: {kc_files[0]} and {kc_files[1]}")
