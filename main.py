import os
import sys
import binascii
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


# Function to generate a strong cryptographic key
def generate_key(algorithm):
    if algorithm == 'AES':
        key_length = 32  # AES-256 requires 32 bytes
    elif algorithm == '3DES':
        key_length = 24  # 3DES requires 24 bytes
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    key = os.urandom(key_length)
    hex_key = binascii.hexlify(key).decode()
    return hex_key


# Function to encrypt using the selected algorithm
def encrypt(plaintext, key, algorithm):
    backend = default_backend()
    key_bytes = binascii.unhexlify(key)

    iv = os.urandom(16)

    if algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=backend)
    elif algorithm == '3DES':
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=backend)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    encryptor = cipher.encryptor()
    pad_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + (chr(pad_length) * pad_length)
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()

    return binascii.hexlify(iv + ciphertext).decode()


# Function to decrypt using the selected algorithm
def decrypt(ciphertext, key, algorithm):
    backend = default_backend()
    key_bytes = binascii.unhexlify(key)

    ciphertext_bytes = binascii.unhexlify(ciphertext)
    iv = ciphertext_bytes[:16]
    actual_ciphertext = ciphertext_bytes[16:]

    if algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=backend)
    elif algorithm == '3DES':
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CBC(iv), backend=backend)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(actual_ciphertext) + decryptor.finalize()
    pad_length = decrypted_padded[-1]
    decrypted_text = decrypted_padded[:-pad_length].decode()

    return decrypted_text


def main():
    parser = argparse.ArgumentParser(description="CryptoVault: File encryption and decryption tool.")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode: encrypt or decrypt.")
    parser.add_argument('input_file', help="Input file to be processed.")
    parser.add_argument('output_file', help="Output file to save the result.")
    parser.add_argument('key_file', help="File to read or save the encryption key.")
    parser.add_argument('--algorithm', choices=['AES', '3DES'], default='AES', help="Encryption algorithm to use (default: AES).")

    args = parser.parse_args()

    try:
        with open(args.input_file, 'rb') as file:
            plaintext = file.read().decode()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    result = ""
    try:
        if args.mode == "encrypt":
            key = generate_key(args.algorithm)
            with open(args.key_file, 'w') as kf:
                kf.write(key)
            result = encrypt(plaintext, key, args.algorithm)
        elif args.mode == "decrypt":
            try:
                with open(args.key_file, 'r') as kf:
                    key = kf.read().strip()
                result = decrypt(plaintext, key, args.algorithm)
            except FileNotFoundError:
                print(f"Error: Key file '{args.key_file}' not found.")
                sys.exit(1)
            except InvalidKey as e:
                print(f"Error: Invalid key - {e}")
                sys.exit(1)
            except Exception as e:
                print(f"Decryption failed: {e}")
                sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        with open(args.output_file, 'wb') as file:
            file.write(result.encode())
    except Exception as e:
        print(f"Error writing to output file: {e}")
        sys.exit(1)

    print(f"Result successfully saved to file '{args.output_file}'.")


if __name__ == '__main__':
    main()
