I generated keys at first with script in Pic , then I use it with code folder .
Task5: Encryption and Key Management
Objective:Gain hands-on experience with encryption and key management. Learn to encrypt and decrypt data securely using both symmetric and asymmetric encryption, manage encryption keys, and understand the importance of key management practices.

1. Key Pair Generation for RSA:
   - Write a script to generate a pair of RSA keys (public and private keys).
   - Save the keys to files in PEM format.
   - Ensure the key size is at least 2048 bits for adequate security.

2. Encrypting Data with AES:
   - Write a script to encrypt a given plaintext using AES in CBC (Cipher Block Chaining) mode.
   - Generate a random key and initialization vector (IV) for the encryption process.
   - Encrypt the AES key itself using the RSA public key, ensuring that only the holder of the RSA private key can decrypt it.
   - Save the encrypted data, encrypted AES key, and IV to files.

3. Decrypting Data:
   - Write a script to decrypt the previously encrypted AES key using the RSA private key.
   - Use the decrypted AES key and IV to decrypt the encrypted data.
   - Verify that the decrypted data matches the original plaintext.

Note:   - The script must include error handling for incorrect keys and IVs.
   - Implement padding (e.g., PKCS7) if the plaintext length is not a multiple of the block size (16 bytes for AES).
   - Handle key sizes of at least 2048 bits for RSA encryption to ensure adequate security.
   - Include error handling for incorrect or corrupted keys.

4. Key Management Best Practices:
   - Implement a method in your script to store keys securely (e.g., using a key management service or encrypting the keys themselves before storing).
   - Implement a basic key rotation mechanism in your script.
   - Implement access control measures in your script (e.g., requiring authentication to access keys).
