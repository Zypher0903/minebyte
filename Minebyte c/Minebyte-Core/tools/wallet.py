import hashlib
import time
import binascii
import ecdsa
import requests
import json
import os
import sys

# Install: pip install ecdsa requests

class MinebyteWallet:
    def __init__(self, port=8334):
        self.private_key = None
        self.public_key = None
        self.address = None
        self.node_url = f"http://localhost:{port}"
        self.load_wallet()

    def print_header(self):
        print(f"""
        Minebyte Wallet [v1.1.0]
        Secure ECDSA & RPC Client
        Connected to Node: {self.node_url}
        """)


    def load_wallet(self):
        if os.path.exists("wallet.dat"):
            with open("wallet.dat", "r") as f:
                hex_key = f.read().strip()
                self.private_key = ecdsa.SigningKey.from_string(binascii.unhexlify(hex_key), curve=ecdsa.SECP256k1)
                self.public_key = self.private_key.get_verifying_key()
                self.derive_address()
                print("[INFO] Wallet loaded.")
        else:
            print("[INFO] No wallet found. Please generate one.")

    def generate_wallet(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        
        with open("wallet.dat", "w") as f:
            f.write(binascii.hexlify(self.private_key.to_string()).decode())
            
        self.derive_address()
        print(f"[SUCCESS] New Wallet Generated!")

    def derive_address(self):
        pub_key_bytes = self.public_key.to_string() 
        sha = hashlib.sha256()
        sha.update(binascii.hexlify(pub_key_bytes)) 
        self.address = "mb" + sha.hexdigest()[:32]
        print(f"Address: {self.address}")

    def sign_transaction(self, receiver, amount):
        timestamp = int(time.time())
        pub_key_hex = binascii.hexlify(self.public_key.to_string()).decode()
        
        data = f"{pub_key_hex}{receiver}{float(amount):.6f}{timestamp}"
        data_hash = hashlib.sha256(data.encode('utf-8')).digest()
        signature = self.private_key.sign_digest(data_hash, sigencode=ecdsa.util.sigencode_string)
        
        tx = {
            "senderPubKey": pub_key_hex,
            "receiver": receiver,
            "amount": float(amount),
            "timestamp": timestamp,
            "signature": binascii.hexlify(signature).decode()
        }
        
        return tx

    def run(self):
        self.print_header()
        while True:
            cmd = input("minebyte-cli > ").strip()
            
            if cmd == "help":
                print("Commands: generate, info, send <addr> <amount>, exit")
            elif cmd == "generate":
                self.generate_wallet()
            elif cmd == "info":
                if self.address:
                    self.derive_address()
                else:
                    print("No wallet loaded.")
            elif cmd.startswith("send"):
                parts = cmd.split()
                if len(parts) < 3:
                    print("Usage: send <receiver> <amount>")
                    continue
                if not self.private_key:
                    print("Load or generate wallet first.")
                    continue
                
                try:
                    tx = self.sign_transaction(parts[1], parts[2])
                    print("[NET] Sending transaction to node...")
                    response = requests.post(self.node_url, json=tx)
                    print(f"[NODE] Response: {response.text}")
                except Exception as e:
                    print(f"[ERROR] Could not connect to node: {e}")

            elif cmd == "exit":
                break
            else:
                print("Unknown command.")

if __name__ == "__main__":
    port = 8334
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    wallet = MinebyteWallet(port)
    wallet.run()
