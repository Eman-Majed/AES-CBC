from keymanagement import KeyManager
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# File paths
plaintext_file = 'plaintext.txt'
encrypted_data_file = 'encrypted_data.bin'
decrypted_data_file = 'decrypted_data.txt'

def encrypt_data(key_manager):
    try:
        # Read plaintext from file
        with open(plaintext_file, 'rb') as f:
            plaintext = f.read()

        # Generate AES key and IV
        aes_key, iv = key_manager.generate_aes_key_and_iv()

        # Encrypt plaintext with AES CBC
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

        # Save IV, encrypted AES key, and encrypted data to files
        key_manager.save_iv_to_file(iv)
        key_manager.save_encrypted_aes_key_to_file(key_manager.encrypt_aes_key_with_rsa(aes_key))

        with open(encrypted_data_file, 'wb') as f:
            f.write(ciphertext)

        print("Encryption complete.")

    except Exception as e:
        print(f"Encryption failed: {str(e)}")

def decrypt_data(key_manager):
    try:
        # Decrypt AES key using RSA private key
        aes_key = key_manager.decrypt_aes_key_with_rsa()

        # Read IV and encrypted data from files
        iv = key_manager.read_iv_from_file()
        with open(encrypted_data_file, 'rb') as f:
            ciphertext = f.read()

        # Decrypt data using AES CBC
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = cipher_aes.decrypt(ciphertext)

        # Unpad decrypted data
        decrypted_data = unpad(decrypted_data, AES.block_size)

        # Save decrypted data to file
        with open(decrypted_data_file, 'wb') as f:
            f.write(decrypted_data)

        print("Decryption complete.")

    except Exception as e:
        print(f"Decryption failed: {str(e)}")

if __name__ == '__main__':
    key_manager = KeyManager()

    # Perform encryption
    encrypt_data(key_manager)

    # Perform decryption
    decrypt_data(key_manager)

    
