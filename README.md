

```markdown
# 🔐 Blockchain-Assisted Hybrid Cryptographic Steganography (ECC + LSB)

## 📌 Overview
This project is a proof-of-concept system for secure whistleblower communication using a hybrid of modern cryptography, steganography, and decentralized technologies:

- 🔐 **ECC (Elliptic Curve Cryptography)** for strong public-key encryption  
- 🖼️ **LSB (Least Significant Bit) steganography** to hide encrypted messages inside images  
- 🌐 **IPFS (InterPlanetary File System)** for decentralized file storage  
- ⛓️ **(Optional)** Simulated blockchain integration for tamper-proof hash storage  

---

## ⚙️ Setup

1. Clone the repository  
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
```
3. Add a PNG cover image (e.g., `cover.png`) to the project folder

---

## 🚀 Usage

Run the main script and follow prompts:

```bash
python main.py
```

You can:

* Generate ECC public/private key pairs
* Encrypt a plaintext message
* Embed encrypted data in an image using LSB
* Upload the stego-image to IPFS and get its hash
* (Optionally) Simulate blockchain storage for the IPFS hash
* Extract and decrypt the hidden message from the image

---

## 🔐 Security Notes

* Blockchain hash storage is simulated in this demo
* For best results, use high-resolution, unique cover images
* Always verify integrity and authenticity of keys and files

---

## 📚 References

* [cryptography](https://pypi.org/project/cryptography/)
* [stegano](https://pypi.org/project/stegano/)
* [web3.py](https://github.com/ethereum/web3.py)
* [IPFS HTTP Client](https://github.com/ipfs-shipyard/py-ipfs-http-client)

> Check the code and in-line comments for detailed explanations of each step.

```

Let me know if you'd like this turned into a visually enhanced `README` with badges, demo screenshots, or a table of contents!
```
