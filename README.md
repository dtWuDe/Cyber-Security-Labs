# PROJECT 1: Secure File Encryption & Decryption System

## Overview

This project provides a secure cryptographic module and an accompanying application for file encryption and decryption using AES, RSA, and SHA algorithms. It ensures data confidentiality, secure key management, and integrity verification.

## Features

### Cryptographic Module

The core module includes the following functionalities:

#### AES Key Generation
- Generates a random secret key (Ks) for AES encryption.

#### AES File Encryption
- Encrypts a file using AES with Ks.

#### AES File Decryption
- Decrypts an AES-encrypted file using the same secret key Ks.

#### RSA Key Pair Generation
- Generates a pair of public (Kpublic) and private (Kprivate) keys for RSA encryption.

#### RSA String Encryption
- Encrypts a string using the RSA public key (Kpublic).

#### RSA String Decryption
- Decrypts a string using the RSA private key (Kprivate).

#### Hashing using SHA-1 & SHA-256
- Computes SHA-1 and SHA-256 hashes of a given string.

## Application Functionality

### 1. File Encryption Process

The user selects a file (P) to encrypt.

The system:

1. Generates an AES secret key (Ks).
2. Encrypts the file (P) using Ks, producing an encrypted file (C).
3. Generates an RSA key pair (Kprivate, Kpublic).
4. Encrypts Ks using the RSA public key (Kpublic), resulting in an encrypted key (Kx).
5. Computes SHA-1 hash of Kprivate, named HKprivate.
6. Saves metadata (C.metadata file) containing Kx and HKprivate.
7. Exports Kprivate for later decryption (optionally saved as a file).

### 2. File Decryption Process

The user selects an encrypted file (C) for decryption.

The user provides the RSA private key (Kprivate) (from input or file).

The system:

1. Computes SHA-1 hash of Kprivate and compares it with HKprivate from metadata.
   - If hashes do not match, decryption fails.
   - If hashes match, the system decrypts Kx to obtain Ks.
2. Uses Ks to decrypt C and recover the original file (P).

## License

This project is licensed under the MIT License. See the LICENSE file for details.

# PROJECT 3: Exploiting Overflow Vulnerabilities

## Overview

This project provides a platform for users to engage in challenges that exploit overflow vulnerabilities, with a particular focus on buffer overflows and memory corruption techniques. The challenges are designed to enhance understanding of security vulnerabilities and the methods used to exploit them.
