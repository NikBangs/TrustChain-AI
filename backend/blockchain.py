import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

w3 = Web3(Web3.HTTPProvider(os.getenv("RPC")))

contract_address = Web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS"))
private_key = os.getenv("PRIVATE_KEY")
account = w3.eth.account.from_key(private_key)

abi = [
    {
        "inputs": [{"internalType": "string", "name": "domain", "type": "string"}],
        "name": "reportSite",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "domain", "type": "string"}],
        "name": "isReported",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

contract = w3.eth.contract(address=contract_address, abi=abi)

def report_site(domain):
    tx = contract.functions.reportSite(domain).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 100000,
        'gasPrice': w3.to_wei('10', 'gwei')
    })
    signed = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.to_hex(tx_hash)

def is_reported(domain):
    return contract.functions.isReported(domain).call()
