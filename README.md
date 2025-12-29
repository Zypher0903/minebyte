# Minebyte Core

Minebyte is a minimal, educational implementation of a distributed ledger protocol written in C++. It demonstrates core blockchain concepts including Proof-of-Work consensus, ECDSA digital signatures using the secp256k1 curve, Merkle trees, transaction propagation, and peer-to-peer network synchronization.

The project is intended for learning purposes and as a reference for low-level blockchain systems engineering.

## Features

- Full ECDSA signature generation and verification using secp256k1 (same curve as Bitcoin)
- Custom SHA-256 implementation
- Merkle tree construction for transaction integrity
- Proof-of-Work mining with configurable difficulty
- On-disk persistence of the blockchain state
- Built-in RPC server for wallet interaction
- Peer-to-peer networking with chain synchronization and transaction/block broadcasting
- Cross-platform socket support (Windows and Unix-like systems)

## Repository Structure
minebyte/
├── src/
│   ├── core/          # Blockchain, Block, Transaction logic
│   ├── crypto/        # SHA-256 and micro-ecc integration
│   ├── p2p/           # P2P networking layer
│   └── main.cpp       # Node entry point
├── tools/
│   └── wallet.py      # CLI wallet (Python)
├── Makefile           # Build configuration
└── README.md
text## Building the Node

### Prerequisites

- A C++11-compliant compiler (g++, clang++, or MSVC)
- GNU Make (or compatible, e.g., mingw32-make on Windows)

### Linux / macOS

```bash
make
./minebyte_node [P2P_PORT] [RPC_PORT] [PEER_IP:PORT...]
Windows
Recommended: Install MSYS2 and the MinGW toolchain.
Bashmake
minebyte_node.exe [P2P_PORT] [RPC_PORT] [PEER_IP:PORT...]
Default ports if none specified: P2P on 8333, RPC on 8334.
Running the Wallet
Prerequisites

Python 3.6 or newer

Bashpip install ecdsa requests
cd tools
python wallet.py [RPC_PORT]
Default RPC port: 8334.
Wallet Commands

generate – create a new key pair
info     – display current address
send <address> <amount> – broadcast a transaction
exit     – close the wallet

Network Usage
To start a seed node:
Bash./minebyte_node
To connect additional nodes:
Bash./minebyte_node 9000 9001 127.0.0.1:8333
Nodes automatically request chain synchronization on connection and propagate new transactions and blocks.
Notes
This implementation prioritizes clarity and correctness over performance optimizations. It serves as a functional prototype rather than production-grade software.
