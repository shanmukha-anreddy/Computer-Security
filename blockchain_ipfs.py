import hashlib
import os
import requests
from web3 import Web3

# === BLOCKCHAIN CONFIGURATION (FILL THESE IN) ===
INFURA_URL = "https://mainnet.infura.io/v3/a1f03d93d9f3428385032bd3db5b25fd"  # Use testnet for free!
CONTRACT_ADDRESS = "0xYourContractAddressHere"  # Replace with deployed contract address
CONTRACT_ABI = [...]  # Replace with your contract ABI as a Python list
PRIVATE_KEY = "0xYourPrivateKeyHere"  # NEVER share this publicly
WALLET_ADDRESS = "0xYourWalletAddressHere"  # Your wallet address

# === STORE HASH ON BLOCKCHAIN ===
def store_ipfs_hash_on_blockchain(ipfs_hash):
    w3 = Web3(Web3.HTTPProvider(INFURA_URL))
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    nonce = w3.eth.get_transaction_count(WALLET_ADDRESS)
    txn = contract.functions.storeHash(ipfs_hash).build_transaction({
        'from': WALLET_ADDRESS,
        'nonce': nonce,
        'gas': 200000,
        'gasPrice': w3.to_wei('10', 'gwei')
    })
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f"Transaction sent: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print("Transaction mined:", receipt)
    return tx_hash.hex()

# === RETRIEVE HASH FROM BLOCKCHAIN ===
def get_ipfs_hash_from_blockchain():
    w3 = Web3(Web3.HTTPProvider(INFURA_URL))
    contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    return contract.functions.getHash().call()

# === SIMULATION FUNCTIONS (for fallback/testing) ===
def simulate_store_hash(ipfs_hash):
    # Simulate blockchain storage by writing to a file
    with open('ipfs_hash.txt', 'w') as f:
        f.write(ipfs_hash)
    return True

def simulate_get_hash():
    with open('ipfs_hash.txt', 'r') as f:
        return f.read().strip()

def upload_to_ipfs(file_path):
    """
    Uploads a file to the local IPFS node and returns the real IPFS CID.
    Requires IPFS Desktop or daemon running at http://127.0.0.1:5001
    """
    url = 'http://127.0.0.1:5001/api/v0/add'
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, files=files)
    response.raise_for_status()
    return response.json()['Hash']  # This is the real IPFS CID!


def upload_to_pinata(file_path, api_key=None, api_secret=None):
    """
    Uploads a file to Pinata and returns the global IPFS CID.
    The API key and secret should be passed as arguments or set in environment variables PINATA_API_KEY and PINATA_API_SECRET.
    """
    import os
    api_key = api_key or os.getenv('PINATA_API_KEY')
    api_secret = api_secret or os.getenv('PINATA_API_SECRET')
    if not api_key or not api_secret:
        raise ValueError("Pinata API key and secret must be provided or set in environment variables.")
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": api_key,
        "pinata_secret_api_key": api_secret
    }
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, files=files, headers=headers)
    response.raise_for_status()
    return response.json()['IpfsHash']  # This is the global CID!

def simulate_get_hash():
    with open('ipfs_hash.txt', 'r') as f:
        return f.read().strip()
