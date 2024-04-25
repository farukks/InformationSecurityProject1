from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import time


def encrypt_aes_cbc(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()


def encrypt_aes_ctr(data, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def decrypt_aes_ctr(ciphertext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# Image file and keys
image_file = "q4_materials/image.jpg"

with open("K1_symmetric_key.pem", "r") as file:
    key_128 = bytes.fromhex(file.read())

with open("K2_symmetric_key.pem", "r") as file:
    key_256 = bytes.fromhex(file.read())

# Random IV ve nonce
iv = os.urandom(16)
nonce = os.urandom(16)

print("IV 1.:", iv.hex())
print("Nonce:", nonce.hex())

# Image data
with open(image_file, "rb") as file:
    image_data = file.read()


def AES_CBC(data, key, iv):
    start_time = time.time()
    encrypted_data_cbc_128 = encrypt_aes_cbc(data, key, iv)
    decrypted_data_cbc_128 = decrypt_aes_cbc(encrypted_data_cbc_128, key, iv)
    end_time_cbc_128 = time.time() - start_time
    return [encrypted_data_cbc_128, decrypted_data_cbc_128, end_time_cbc_128]


def AES_CTR_256(data, key, nonce):
    start_time = time.time()
    encrypted_data_ctr_256 = encrypt_aes_ctr(data, key, nonce)
    decrypted_data_ctr_256 = encrypt_aes_ctr(encrypted_data_cbc_256, key, nonce)
    end_time_ctr_256 = time.time() - start_time
    return [encrypted_data_ctr_256, decrypted_data_ctr_256, end_time_ctr_256]


[encrypted_data_cbc_128, decrypted_data_cbc_128, end_time_cbc_128] = AES_CBC(image_data, key_128, iv)
[encrypted_data_cbc_256, decrypted_data_cbc_256, end_time_cbc_256] = AES_CBC(image_data, key_256, iv)
[encrypted_data_ctr, decrypted_data_ctr, end_time_ctr] = AES_CTR_256(image_data, key_256, nonce)
iv = os.urandom(16)
print("IV 2.:", iv.hex())
[encrypted_data_cbc_128_2, decrypted_data_cbc_128_2, end_time_cbc_128_2] = AES_CBC(image_data, key_128, iv)

# Print encryption times
print("Encryption time (AES 128_1 bit CBC):", end_time_cbc_128)
print("Encryption time (AES 128_2 bit CBC):", end_time_cbc_128_2)
print("Encryption time (AES 256 bit CBC):", end_time_cbc_256)
print("Encryption time (AES 256 bit CTR):", end_time_ctr)

# Writing results to files
with open("q4_materials/encrypted_image_cbc_128_1.jpg", "wb") as file:
    file.write(encrypted_data_cbc_128)
with open("q4_materials/encrypted_image_cbc_128_1.txt", "wb") as file:
    file.write(encrypted_data_cbc_128.hex().encode())
with open("q4_materials/encrypted_image_cbc_128_2.jpg", "wb") as file:
    file.write(encrypted_data_cbc_128_2)
with open("q4_materials/encrypted_image_cbc_256_2.txt", "wb") as file:
    file.write(encrypted_data_cbc_256.hex().encode())
with open("q4_materials/encrypted_image_cbc_256.jpg", "wb") as file:
    file.write(encrypted_data_cbc_256)
with open("q4_materials/encrypted_image_ctr.jpg", "wb") as file:
    file.write(encrypted_data_ctr)


with open("q4_materials/decrypted_image_cbc_128_1.jpg", "wb") as file:
    file.write(decrypted_data_cbc_128)
with open("q4_materials/decrypted_image_cbc_128_1.txt", "wb") as file:
    file.write(decrypted_data_cbc_128.hex().encode())
with open("q4_materials/decrypted_image_cbc_128_2.jpg", "wb") as file:
    file.write(decrypted_data_cbc_128_2)
with open("q4_materials/decrypted_image_cbc_128_2.txt", "wb") as file:
    file.write(decrypted_data_cbc_128_2.hex().encode())
with open("q4_materials/decrypted_image_cbc_25x6.jpg", "wb") as file:
    file.write(decrypted_data_cbc_256)
with open("q4_materials/decrypted_image_ctrx.jpg", "wb") as file:
    file.write(decrypted_data_ctr)
