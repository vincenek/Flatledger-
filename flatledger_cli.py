import hashlib
import json
import os
from datetime import datetime
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

LEDGER_FILE = "ledger.json"
ANCHOR_FILE = "anchors.md"

def initialize_ledger():
    if not os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "w") as f:
            json.dump({"transactions": [], "anchors": {}}, f)

def generate_wallet():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    return {
        "private": private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex(),
        "public": public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
    }

def calculate_hash(tx_data):
    sha = hashlib.sha256()
    sha.update(
        f"{tx_data['timestamp']}{tx_data['sender']}{tx_data['receiver']}"
        f"{tx_data['amount']}{tx_data['currency']}{tx_data['prev_hash']}".encode()
    )
    return sha.hexdigest()

def new_transaction(sender_priv, receiver_pub, amount, currency="USD"):
    initialize_ledger()
    
    with open(LEDGER_FILE, "r") as f:
        ledger = json.load(f)
    
    last_hash = ledger["transactions"][-1]["tx_hash"] if ledger["transactions"] else "0"
    
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(sender_priv)
    )
    
    tx_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "sender": private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "receiver": receiver_pub,
        "amount": float(amount),
        "currency": currency,
        "prev_hash": last_hash
    }
    
    signature = private_key.sign(
        f"{tx_data['timestamp']}{tx_data['receiver']}{amount}".encode()
    ).hex()
    
    tx_data["signature"] = signature
    tx_data["tx_hash"] = calculate_hash(tx_data)
    
    ledger["transactions"].append(tx_data)
    
    with open(LEDGER_FILE, "w") as f:
        json.dump(ledger, f, indent=2)
    
    print(f"Transaction added: {tx_data['tx_hash']}")
    return tx_data

def verify_ledger():
    with open(LEDGER_FILE, "r") as f:
        ledger = json.load(f)
    
    prev_hash = "0"
    for idx, tx in enumerate(ledger["transactions"]):
        if tx["prev_hash"] != prev_hash:
            print(f"Chain broken at transaction {idx}")
            return False
        
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(tx["sender"]))
            public_key.verify(
                bytes.fromhex(tx["signature"]),
                f"{tx['timestamp']}{tx['receiver']}{tx['amount']}".encode()
            )
        except:
            print(f"Invalid signature at transaction {idx}")
            return False
        
        calculated_hash = calculate_hash(tx)
        if calculated_hash != tx["tx_hash"]:
            print(f"Hash mismatch at transaction {idx}")
            return False
        
        prev_hash = tx["tx_hash"]
    
    print("Ledger verification successful!")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FlatLedger CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    # Generate wallet
    gen_parser = subparsers.add_parser("generate-wallet")
    
    # New transaction
    tx_parser = subparsers.add_parser("new-transaction")
    tx_parser.add_argument("--sender", required=True)
    tx_parser.add_argument("--receiver", required=True)
    tx_parser.add_argument("--amount", required=True)
    tx_parser.add_argument("--currency", default="USD")
    
    # Verify ledger
    subparsers.add_parser("verify-ledger")
    
    args = parser.parse_args()
    
    if args.command == "generate-wallet":
        wallet = generate_wallet()
        print(f"New wallet:\n{json.dumps(wallet, indent=2)}")
    elif args.command == "new-transaction":
        new_transaction(args.sender, args.receiver, args.amount, args.currency)
    elif args.command == "verify-ledger":
        verify_ledger()
