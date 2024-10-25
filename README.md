# FileProtector

FileProtector is a command-line tool for file encryption and decryption, supporting AES-256 and 3DES algorithms. Designed for secure file management, FileProtector allows users to encrypt files with a generated key and decrypt them using the stored key.

## Features

- **AES-256 and 3DES Encryption**: Choose between two strong cryptographic algorithms for enhanced security.
- **Key Generation**: Automatically generates a secure key for encryption and stores it in a user-specified file.
- **Error Handling**: Informs users of file and key errors, ensuring safe file handling and use.

## Requirements

- Python 3.6+
- `cryptography` library (install with `pip install cryptography`)

## Usage

### Command Structure

```bash
python fileprotector.py <mode> <input_file> <output_file> <key_file> --algorithm <AES/3DES>
```

### Arguments

`<mode>` : Operation mode, either encrypt or decrypt.
`<input_file>` : Path to the file to be encrypted or decrypted.
`<output_file>` : Path to save the resulting file.
`<key_file>` : Path to read or save the encryption key.
`--algorithm` : Encryption algorithm to use (optional; default is AES). Options: AES or 3DES.

### Example Commands

**Encrypt a File with AES**

```bash
python fileprotector.py encrypt input.txt encrypted.bin key.txt --algorithm AES
```

**Decrypt a File with 3DES**

```bash
python fileprotector.py decrypt encrypted.bin decrypted.txt key.txt --algorithm 3DES
```

## License
This project is open-source and available under the MIT License.
