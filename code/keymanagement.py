from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import os

class KeyManager:
    def __init__(self): #self: to represent the instance of a class
        #key file paths
        self.public_key_file = 'mypublickey.pem'
        self.private_key_file = 'mykey.pem'
        self.iv_file = 'iv.bin'
        self.encrypted_key_file = 'encrypted_key.bin'

    def generate_aes_key_and_iv(self):
        aes_key = get_random_bytes(32)  # AES key size: 256 bits (32 bytes)
        iv = get_random_bytes(16)        # IV size: AES block size (16 bytes)
        return aes_key, iv

    def encrypt_aes_key_with_rsa(self, aes_key):
        with open(self.public_key_file, 'rb') as f:
            public_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        return encrypted_aes_key

    def decrypt_aes_key_with_rsa(self):
        with open(self.private_key_file, 'rb') as f:
            private_key = RSA.import_key(f.read())

        with open(self.encrypted_key_file, 'rb') as f:
            encrypted_aes_key = f.read()

        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        return aes_key

    def save_iv_to_file(self, iv):
        with open(self.iv_file, 'wb') as f:
            f.write(iv)

    def read_iv_from_file(self):
        with open(self.iv_file, 'rb') as f:
            iv = f.read()
            if len(iv) != 16:
                raise ValueError("IV length is not 16 bytes")
        return iv

    def save_encrypted_aes_key_to_file(self, aes_key):
        with open(self.encrypted_key_file, 'wb') as f:
            f.write(aes_key)

    def load_encrypted_aes_key_from_file(self):
        with open(self.encrypted_key_file, 'rb') as f:
            aes_key = f.read()
            if len(aes_key) == 0:
                raise ValueError("Encrypted AES key file is empty")
        return aes_key

    def rotate_keys(self):
        try:
        # Generate new AES key and IV
            new_aes_key, new_iv = self.generate_aes_key_and_iv()

        # Encrypt new AES key with RSA
            encrypted_new_aes_key = self.encrypt_aes_key_with_rsa(new_aes_key)

        # Save new IV and encrypted AES key to files
            self.save_iv_to_file(new_iv)
            self.save_encrypted_aes_key_to_file(encrypted_new_aes_key)

            print("Key rotation complete.")

        except Exception as e:
            print(f"Key rotation failed: {str(e)}")
#I'm not sure about it 
if __name__ == '__main__':
    key_manager = KeyManager()

    # Perform key rotation
    key_manager.rotate_keys()

