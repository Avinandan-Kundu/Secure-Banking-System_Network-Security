from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class MAC:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.backend = default_backend()
        self.generateMAC_KEY()

    def generateMAC_KEY(self):
        salt = b'bank_atm_generation'
        info_encryption = b'encryption_key' 
        info_mac = b'mac_key'
        length = 16

        # Derive keys using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info_encryption,
        )
        self.symKey = hkdf.derive(self.secret_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info_mac,
        )
        self.MACKey = hkdf.derive(self.secret_key)

    def encrypt(self, plaintext):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.symKey), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(self.MACKey, hashes.SHA256(), backend=self.backend)
        h.update(ct)
        return (ct, h.finalize())

    def decrypt(self, ct, tag):
        h = hmac.HMAC(self.MACKey, hashes.SHA256(), backend=self.backend)
        h.update(ct)
        h.verify(tag)

        cipher = Cipher(algorithms.AES(self.symKey), modes.ECB(), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

def main():
    # Initialize the MAC object with a secret key
    secret_key = b'secret_key'
    mac = MAC(secret_key)

    # Define a message to encrypt
    plaintext = b'This is a secret message'
    print('Original message:', plaintext)

    # Encrypt the message
    ciphertext, tag = mac.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext}")
    print(f"Tag: {tag}")

    # Decrypt the message
    try:
        decrypted_message = mac.decrypt(ciphertext, tag)
        print(f"Decrypted message: {decrypted_message}")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
