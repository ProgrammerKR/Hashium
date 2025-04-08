import os
import hashlib
import hmac
import base64
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class Hashium:
    def __init__(self):
        self.ph = PasswordHasher()
        self.aes_key = get_random_bytes(32)  # 256-bit AES key

    # Basic SHA-256 Hash
    def hashium_basic(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    # Salted SHA-256 Hash
    def hashium_salted(self, data: str) -> str:
        salt = os.urandom(16)
        hash_value = hashlib.sha256(salt + data.encode()).hexdigest()
        return f"{salt.hex()}:{hash_value}"

    # PBKDF2-HMAC-SHA256
    def hashium_pbkdf2(self, password: str) -> str:
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return f"{salt.hex()}:{key.hex()}"

    def verify_pbkdf2(self, password: str, stored_hash: str) -> bool:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        test_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(expected_key, test_key)

    # HMAC-SHA256
    def hashium_hmac(self, key: str, data: str) -> str:
        return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

    # Argon2 Hashing
    def hashium_argon2(self, password: str) -> str:
        return self.ph.hash(password)

    def verify_argon2(self, password: str, stored_hash: str) -> bool:
        try:
            return self.ph.verify(stored_hash, password)
        except argon2_exceptions.VerifyMismatchError:
            return False

    # AES-256 Encryption (EAX Mode)
    def encrypt_data(self, data: str) -> str:
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return f"{cipher.nonce.hex()}:{tag.hex()}:{ciphertext.hex()}"

    def decrypt_data(self, encrypted_str: str) -> str:
        nonce_hex, tag_hex, ciphertext_hex = encrypted_str.split(":")
        nonce = bytes.fromhex(nonce_hex)
        tag = bytes.fromhex(tag_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode()

    # File Hashing
    def hash_file(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    # RSA Key Generation
    def generate_rsa_keys(self, key_size: int = 2048) -> tuple:
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key.decode(), public_key.decode()

    # Digital Signature
    def sign_data(self, data: str, private_key_str: str) -> str:
        private_key = RSA.import_key(private_key_str.encode())
        digest = SHA256.new(data.encode())
        signature = pkcs1_15.new(private_key).sign(digest)
        return base64.b64encode(signature).decode()

    def verify_signature(self, data: str, signature_b64: str, public_key_str: str) -> bool:
        public_key = RSA.import_key(public_key_str.encode())
        digest = SHA256.new(data.encode())
        signature = base64.b64decode(signature_b64.encode())
        try:
            pkcs1_15.new(public_key).verify(digest, signature)
            return True
        except (ValueError, TypeError):
            return False

    # Ultra-Secure 768-bit+ Custom Hash
    def hashium_ultra_secure(self, data: str, pepper: str = "Hashium2025Ultra") -> str:
        salt = os.urandom(32)
        mixed = salt + data.encode() + pepper.encode()
        pbkdf2_key = hashlib.pbkdf2_hmac('sha512', mixed, salt, 200000, dklen=64)
        hmac_key = hashlib.sha512(pbkdf2_key).digest()
        hmac_result = hmac.new(hmac_key, pbkdf2_key, hashlib.sha512).digest()
        intermediate_hex = hmac_result.hex()
        argon_hash = self.ph.hash(intermediate_hex)
        final_hash = hashlib.sha512((argon_hash + intermediate_hex).encode()).hexdigest()
        return f"{salt.hex()}:{final_hash}"


# Example Usage
if __name__ == "__main__":
    hashium = Hashium()

    print("1. Basic Hash:", hashium.hashium_basic("mypassword"))

    print("2. Salted Hash:", hashium.hashium_salted("mypassword"))

    pbkdf2_hash = hashium.hashium_pbkdf2("mypassword")
    print("3. PBKDF2 Hash:", pbkdf2_hash)
    print("   Verify PBKDF2:", hashium.verify_pbkdf2("mypassword", pbkdf2_hash))

    print("4. HMAC Hash:", hashium.hashium_hmac("mysecretkey", "mypassword"))

    argon2_hash = hashium.hashium_argon2("mypassword")
    print("5. Argon2 Hash:", argon2_hash)
    print("   Verify Argon2:", hashium.verify_argon2("mypassword", argon2_hash))

    encrypted = hashium.encrypt_data("mypassword")
    print("6. AES Encrypted:", encrypted)
    print("   AES Decrypted:", hashium.decrypt_data(encrypted))

    print("7. File Hash (demo.txt):", hashium.hash_file("demo.txt") if os.path.exists("demo.txt") else "demo.txt not found")

    private_key, public_key = hashium.generate_rsa_keys()
    signature = hashium.sign_data("secure message", private_key)
    print("8. Digital Signature:", signature)
    print("   Verify Signature:", hashium.verify_signature("secure message", signature, public_key))

    print("9. Ultra Secure Hash (768+ bits):", hashium.hashium_ultra_secure("mypassword"))
