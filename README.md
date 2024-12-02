# Ransomware Development Project

## Introduction
This project involves developing a ransomware application using Python. The application utilizes encryption and a client-server architecture to facilitate communication between the attacker and the victim.

## Overview
The main objectives of this project are:

- Generate a random 128-bit key (16 characters) using ASCII characters.
- Find and encrypt all `.txt` files on the victim's computer.
- Send the encryption key back to the server.

### Key Features
- **Payload:**
  - Encrypts all `.txt` files on the system using AES encryption.
  - Generates a public/private key pair using RSA.
  - Saves the encryption key to the desktop as `Key.key`.
  - Encrypts the key using the RSA public key and saves it as `encryptedKey.key`.
  - Saves the public/private key pair in `keyPair.key`.
  - Sends the encrypted key to the server.
  - Includes a decryption function to restore files using the original key.

- **User Interface:**
  - Displays a prompt (CLI or GUI) indicating that encryption is in progress.
  - Waits for user input to decrypt files after encryption.

## Requirements
- Python 3.x
- Required libraries (install via pip):
  - `pycryptodome`
  - Any other dependencies used in the project

## Usage
1. Run the application to start the encryption process.
2. Follow the prompts for encryption progress.
3. Enter the original key when prompted to decrypt the files.

## Disclaimer
**This project is for educational purposes only. Unauthorized use of ransomware is illegal and unethical.**

## License
This project is licensed under the MIT License.

## Acknowledgments
- Inspired by cryptographic techniques and malware research.
