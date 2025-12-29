CXX = g++
CC = gcc
# Enable secp256k1 in micro-ecc
CFLAGS = -Wall -O2 -I src/crypto/ecc -D uECC_CURVE=uECC_secp256k1
CXXFLAGS = -Wall -O2 -std=c++11 -I src/crypto/ecc -D uECC_CURVE=uECC_secp256k1

# Project structure
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Files
SRCS_C = src/crypto/sha256.c src/crypto/ecc/uECC.c
SRCS_CPP = src/core/Block.cpp src/core/Blockchain.cpp src/p2p/P2PNode.cpp main.cpp

# Output
TARGET = minebyte_node

# Linker flags (WinSock)
LDFLAGS = -lws2_32

all: clean build

build:
	@echo "[BUILD] Compiling Crypto Layer (C)..."
	$(CC) $(CFLAGS) -c src/crypto/sha256.c -o sha256.o
	$(CC) $(CFLAGS) -c src/crypto/ecc/uECC.c -o uECC.o
	
	@echo "[BUILD] Compiling Core Layer (C++)..."
	$(CXX) $(CXXFLAGS) -c src/core/Block.cpp -o Block.o
	$(CXX) $(CXXFLAGS) -c src/core/Blockchain.cpp -o Blockchain.o
	
	@echo "[BUILD] Compiling Network Layer (P2P)..."
	$(CXX) $(CXXFLAGS) -c src/p2p/P2PNode.cpp -o P2PNode.o
	
	@echo "[BUILD] Linking..."
	$(CXX) $(CXXFLAGS) main.cpp sha256.o uECC.o Block.o Blockchain.o P2PNode.o -o $(TARGET) $(LDFLAGS)
	
	@echo "[SUCCESS] Build complete. Run ./$(TARGET) to start the node."

clean:
	rm -f *.o $(TARGET)

.PHONY: all clean build
