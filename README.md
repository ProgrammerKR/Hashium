# Hashium

**Hashium** is a powerful and highly secure Python hashing and encryption library. It combines traditional and modern cryptographic algorithms including SHA, HMAC, PBKDF2, Argon2, AES, RSA, and a custom ultra-secure hybrid algorithm developed specifically for enhanced protection.

---

## Features

- **Basic & Salted SHA-256 Hashing**
- **PBKDF2 with HMAC-SHA256**
- **Argon2 Hashing and Verification**
- **HMAC using SHA-256**
- **AES-256 Encryption and Decryption (EAX Mode)**
- **RSA Key Generation, Signing, and Verification**
- **File Hashing with SHA-256**
- **Ultra-Secure 768+ Bit Custom Hash Algorithm**
- Clean and readable code
- Python 3.8+ compatible

---

## Installation

```bash
pip install hashium
```

Or clone the repository manually:

```bash
git clone https://github.com/DeveloperKR123/Hashium.git
cd Hashium
pip install -r requirements.txt
```

---

## Requirements

- Python 3.8+
- [argon2-cffi](https://pypi.org/project/argon2-cffi/)
- [pycryptodome](https://pypi.org/project/pycryptodome/)

Install dependencies:

```bash
pip install argon2-cffi pycryptodome
```

---

## Basic Usage

```python
from hashium import Hashium

hashium = Hashium()

# Basic SHA-256 Hash
print(hashium.hashium_basic("mypassword"))

# Salted Hash
print(hashium.hashium_salted("mypassword"))

# PBKDF2 Hash and Verification
hashed = hashium.hashium_pbkdf2("mypassword")
print(hashium.verify_pbkdf2("mypassword", hashed))

# Argon2 Hash and Verify
argon_hash = hashium.hashium_argon2("mypassword")
print(hashium.verify_argon2("mypassword", argon_hash))

# AES Encryption / Decryption
encrypted = hashium.encrypt_data("mypassword")
print(hashium.decrypt_data(encrypted))

# RSA Key Pair
private_key, public_key = hashium.generate_rsa_keys()
signature = hashium.sign_data("secure message", private_key)
print(hashium.verify_signature("secure message", signature, public_key))

# Ultra Secure Hash
print(hashium.hashium_ultra_secure("mypassword"))
```

---

## Modules and Functionalities

### 1. SHA-256 Hashing

- `hashium_basic(data)`
- `hashium_salted(data)`

### 2. PBKDF2-HMAC-SHA256

- `hashium_pbkdf2(password)`
- `verify_pbkdf2(password, stored_hash)`

### 3. HMAC-SHA256

- `hashium_hmac(key, data)`

### 4. Argon2

- `hashium_argon2(password)`
- `verify_argon2(password, stored_hash)`

### 5. AES Encryption (EAX Mode)

- `encrypt_data(data)`
- `decrypt_data(encrypted_data)`

### 6. File Hashing

- `hash_file(file_path)`

### 7. RSA & Digital Signature

- `generate_rsa_keys()`
- `sign_data(data, private_key)`
- `verify_signature(data, signature, public_key)`

### 8. Ultra Secure Hash

- `hashium_ultra_secure(data, pepper='Hashium2025Ultra')`

---

## Example Script

See `example.py` in the repository to test all functionalities.

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

---

## License

This project is licensed under the **MIT License** â€“ see the [LICENSE](LICENSE) file for details.

---

## Author

**Prog. Kanishk Raj (ProgrammerKR)**  
[GitHub](https://github.com/DeveloperKR123) | Creator of [Hashium](https://github.com/DeveloperKR123/Hashium), [Hashium](https://github.com/ProgrammerKR/Hashium)

---

## Disclaimer

Hashium is intended for educational and research purposes. For mission-critical systems, it's advised to follow vetted industry cryptographic standards and seek professional security audits.