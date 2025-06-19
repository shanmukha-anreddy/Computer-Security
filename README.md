# Blockchain-Assisted Hybrid Cryptographic Steganography (ECC + LSB)

## Overview
This project demonstrates a proof-of-concept for secure whistleblower communication using:
- **ECC** (Elliptic Curve Cryptography) for strong encryption
- **LSB** (Least Significant Bit) steganography for hiding data in images
- **IPFS** for decentralized storage
- **(Optional) Blockchain** for tamper-proof hash storage (simulated)

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Add a PNG cover image (e.g., `cover.png`) to the project folder.

## Usage
- Run `main.py` and follow prompts to:
  - Generate ECC keys
  - Encrypt a message
  - Hide encrypted data in an image
  - Upload the image to IPFS and store/retrieve the hash
  - Extract and decrypt the message

## Security Notes
- For demonstration, blockchain hash storage is simulated.
- Use strong, unique cover images for best steganography results.

## References
- Cryptography, Stegano, Web3.py, IPFS libraries
- See project code and comments for details
