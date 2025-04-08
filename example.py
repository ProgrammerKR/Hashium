from hashium import Hashium
import os

def main():
    hashium = Hashium()

    print("== Hashium Demo ==")

    # 1. Basic SHA-256 Hash
    print("\n1. Basic SHA-256 Hash:")
    print(hashium.hashium_basic("mypassword"))

    # 2. Salted SHA-256 Hash
    print("\n2. Salted SHA-256 Hash:")
    print(hashium.hashium_salted("mypassword"))

    # 3. PBKDF2 Hashing and Verification
    print("\n3. PBKDF2 Hash:")
    pbkdf2_hash = hashium.hashium_pbkdf2("mypassword")
    print(pbkdf2_hash)
    print("Verify PBKDF2:", hashium.verify_pbkdf2("mypassword", pbkdf2_hash))

    # 4. HMAC Hash
    print("\n4. HMAC-SHA256 Hash:")
    print(hashium.hashium_hmac("mysecretkey", "mypassword"))

    # 5. Argon2 Hashing and Verification
    print("\n5. Argon2 Hash:")
    argon_hash = hashium.hashium_argon2("mypassword")
    print(argon_hash)
    print("Verify Argon2:", hashium.verify_argon2("mypassword", argon_hash))

    # 6. AES Encryption/Decryption
    print("\n6. AES-256 Encryption and Decryption:")
    encrypted = hashium.encrypt_data("mypassword")
    print("Encrypted:", encrypted)
    print("Decrypted:", hashium.decrypt_data(encrypted))

    # 7. File Hashing (demo.txt)
    print("\n7. File Hash (demo.txt):")
    if os.path.exists("demo.txt"):
        print(hashium.hash_file("demo.txt"))
    else:
        print("demo.txt not found. Create a file to test this.")

    # 8. Digital Signature with RSA
    print("\n8. RSA Digital Signature:")
    private_key, public_key = hashium.generate_rsa_keys()
    signature = hashium.sign_data("secure message", private_key)
    print("Signature:", signature)
    print("Verify Signature:", hashium.verify_signature("secure message", signature, public_key))

    # 9. Ultra Secure 768+ Bit Hash
    print("\n9. Ultra Secure Hash (768+ bits):")
    print(hashium.hashium_ultra_secure("mypassword"))

if __name__ == "__main__":
    main()