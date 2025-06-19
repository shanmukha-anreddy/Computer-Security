from web3 import Web3

# Use your Infura HTTPS endpoint
w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/a1f03d93d9f3428385032bd3db5b25fd"))

if w3.is_connected():
    block_number = w3.eth.block_number
    print(f"Latest block number: {block_number}")
else:
    print("Failed to connect to Ethereum network.")
