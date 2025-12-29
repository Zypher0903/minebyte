# Minebyte Core v1.0.0

Minebyte is a distributed ledger protocol implementation in C++ designed for educational purposes and high-performance system engineering demonstration.

## Features

### 1. True Cryptography
- **secp256k1**: Uses the same elliptic curve as Bitcoin for digital signatures.
- **SHA-256**: Custom implementation of the hashing algorithm.
- **ECDSA Verification**: Full verification of transaction signatures at the node level.

### 2. Blockchain Architecture
- **Merkle Trees**: Efficient transaction integrity verification using Merkle Roots in block headers.
- **Proof of Work**: Adjustable difficulty mining mechanism.
- **Persistence**: Automatic saving and loading of the blockchain state to `chain.dat`.

### 3. Networking & RPC
- **RPC Server**: Built-in TCP server (port 8334) listening for JSON transactions.
- **Cross-Platform**: Compatible with Windows (Winsock) and Linux (BSD Sockets).

### 4. Wallet
- **Python CLI**: A secure wallet tool that generates ECDSA key pairs and signs transactions locally before broadcasting them to the node.

## Building the Node

Prerequisites: `gcc`, `g++`, `make`.

### Windows (MinGW)
```bash
make
./minebyte_node
```

### Linux
```bash
make
./minebyte_node
```

## Running the Wallet

Prerequisites: Python 3, `ecdsa`, `requests`.

```bash
pip install ecdsa requests
python tools/wallet.py
```

## Usage

1. Start the **Node** (`minebyte_node.exe`). It will start the RPC server and verify crypto.
2. Start the **Wallet** (`wallet.py`).
3. Generate a wallet and send coins to an address.
4. The Node will receive the transaction, verify the signature, and add it to the pool.
5. Press `Enter` in the Node terminal to mine a new block.

---
*Minebyte Systems Engineering Project - 2025*
