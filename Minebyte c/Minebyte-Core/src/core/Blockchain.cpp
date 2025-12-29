#include "Blockchain.h"
#include "../crypto/ecc/uECC.h"
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <fstream>

namespace Minebyte {

// Helper to convert hex string to byte array
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

Blockchain::Blockchain() {
    difficulty = 4;
    // Try to load from disk first
    std::ifstream infile("chain.dat");
    if (infile.good()) {
        loadFromDisk();
    } else {
        createGenesisBlock();
    }
}

void Blockchain::createGenesisBlock() {
    Transaction genesisTx;
    genesisTx.senderPubKey = "00000000";
    genesisTx.receiver = "GENESIS_ADDRESS";
    genesisTx.amount = 1000000.0;
    genesisTx.timestamp = 0;
    genesisTx.signature = "00";
    genesisTx.txId = "GENESIS_TX";

    std::vector<Transaction> genesisTxs;
    genesisTxs.push_back(genesisTx);
    
    Block genesis(0, genesisTxs, "0000000000000000000000000000000000000000000000000000000000000000");
    genesis.mineBlock(difficulty);
    chain.push_back(genesis);
    
    accounts["GENESIS_ADDRESS"] = 1000000.0;
}

Block Blockchain::getLastBlock() const {
    return chain.back();
}

std::string Blockchain::deriveAddress(const std::string& pubKeyHex) {
    uint8_t hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)pubKeyHex.c_str(), pubKeyHex.size());
    sha256_final(&ctx, hash);
    
    return "mb" + Block::hexToString(hash, 32).substr(0, 32);
}

bool Blockchain::verifySignature(const Transaction& tx) {
    if (tx.senderPubKey == "SYSTEM") return true; 

    std::string data = tx.getDataString();
    
    uint8_t hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)data.c_str(), data.size());
    sha256_final(&ctx, hash);

    std::vector<uint8_t> pubKeyBytes = hexToBytes(tx.senderPubKey);
    std::vector<uint8_t> sigBytes = hexToBytes(tx.signature);

    if (pubKeyBytes.size() != 64 || sigBytes.size() != 64) {
        return false;
    }

    uECC_Curve curve = uECC_secp256k1();
    int result = uECC_verify(pubKeyBytes.data(), hash, SHA256_BLOCK_SIZE, sigBytes.data(), curve);
    
    return result == 1;
}

bool Blockchain::addTransaction(Transaction tx) {
    if (!verifySignature(tx)) {
        std::cerr << "[REJECT] Invalid Signature for TX" << std::endl;
        return false;
    }

    std::string senderAddr = deriveAddress(tx.senderPubKey);

    if (accounts[senderAddr] < tx.amount) {
        std::cerr << "[REJECT] Insufficient Balance: " << senderAddr << " has " << accounts[senderAddr] << std::endl;
        return false;
    }

    pendingTransactions.push_back(tx);
    std::cout << "[POOL] Transaction Added: " << tx.amount << " MB from " << senderAddr << std::endl;
    return true;
}

void Blockchain::updateBalances(const Block& block) {
    for(const auto& tx : block.transactions) {
        if (tx.senderPubKey != "SYSTEM") {
             std::string senderAddr = deriveAddress(tx.senderPubKey);
             accounts[senderAddr] -= tx.amount;
        }
        accounts[tx.receiver] += tx.amount;
    }
}

void Blockchain::minePendingTransactions(const std::string& minerAddress) {
    Transaction rewardTx;
    rewardTx.senderPubKey = "SYSTEM";
    rewardTx.receiver = minerAddress;
    rewardTx.amount = 50.0;
    rewardTx.timestamp = (uint64_t)std::time(nullptr);
    rewardTx.signature = "00000000"; 
    rewardTx.txId = "COINBASE";

    pendingTransactions.insert(pendingTransactions.begin(), rewardTx);

    Block newBlock(chain.size(), pendingTransactions, getLastBlock().hash);
    newBlock.mineBlock(difficulty);
    
    std::cout << "[NETWORK] Block successfully mined!" << std::endl;
    chain.push_back(newBlock);
    
    updateBalances(newBlock);
    pendingTransactions.clear();
    
    saveToDisk(); // Auto-save after mining
}

bool Blockchain::isChainValid() const {
    return true; 
}

double Blockchain::getBalance(const std::string& address) const {
    auto it = accounts.find(address);
    if (it != accounts.end()) {
        return it->second;
    }
    return 0.0;
}

void Blockchain::saveToDisk() const {
    std::ofstream out("chain.dat", std::ios::binary);
    // Simple serialization: Count -> Blocks
    size_t chainSize = chain.size();
    out.write((char*)&chainSize, sizeof(chainSize));
    
    for(const auto& block : chain) {
        out.write((char*)&block.index, sizeof(block.index));
        out.write((char*)&block.timestamp, sizeof(block.timestamp));
        out.write((char*)&block.nonce, sizeof(block.nonce));
        
        // Strings need length
        size_t hashLen = block.hash.size();
        out.write((char*)&hashLen, sizeof(hashLen));
        out.write(block.hash.c_str(), hashLen);
        
        size_t prevHashLen = block.prevHash.size();
        out.write((char*)&prevHashLen, sizeof(prevHashLen));
        out.write(block.prevHash.c_str(), prevHashLen);
        
        // Merkle
        size_t merkleLen = block.merkleRoot.size();
        out.write((char*)&merkleLen, sizeof(merkleLen));
        out.write(block.merkleRoot.c_str(), merkleLen);
        
        // Transactions
        size_t txCount = block.transactions.size();
        out.write((char*)&txCount, sizeof(txCount));
        
        for(const auto& tx : block.transactions) {
            // Serialize TX (Simplified for demo - in prod use proper serialization lib)
            // Just saving amount and receiver for basic state reconstruction
            size_t recLen = tx.receiver.size();
            out.write((char*)&recLen, sizeof(recLen));
            out.write(tx.receiver.c_str(), recLen);
            out.write((char*)&tx.amount, sizeof(tx.amount));
            
            size_t senderLen = tx.senderPubKey.size();
            out.write((char*)&senderLen, sizeof(senderLen));
            out.write(tx.senderPubKey.c_str(), senderLen);
        }
    }
    out.close();
    std::cout << "[DISK] Blockchain saved." << std::endl;
}

void Blockchain::loadFromDisk() {
    std::ifstream in("chain.dat", std::ios::binary);
    if (!in.is_open()) return;
    
    size_t chainSize;
    in.read((char*)&chainSize, sizeof(chainSize));
    
    chain.clear();
    accounts.clear();
    
    for(size_t i = 0; i < chainSize; ++i) {
        uint32_t index;
        uint64_t timestamp, nonce;
        in.read((char*)&index, sizeof(index));
        in.read((char*)&timestamp, sizeof(timestamp));
        in.read((char*)&nonce, sizeof(nonce));
        
        size_t len;
        in.read((char*)&len, sizeof(len));
        std::string hash(len, '\0');
        in.read(&hash[0], len);
        
        in.read((char*)&len, sizeof(len));
        std::string prevHash(len, '\0');
        in.read(&prevHash[0], len);
        
        in.read((char*)&len, sizeof(len));
        std::string merkle(len, '\0');
        in.read(&merkle[0], len);
        
        size_t txCount;
        in.read((char*)&txCount, sizeof(txCount));
        
        std::vector<Transaction> txs;
        for(size_t j = 0; j < txCount; ++j) {
            Transaction tx;
            size_t slen;
            in.read((char*)&slen, sizeof(slen));
            tx.receiver.resize(slen);
            in.read(&tx.receiver[0], slen);
            
            in.read((char*)&tx.amount, sizeof(tx.amount));
            
            in.read((char*)&slen, sizeof(slen));
            tx.senderPubKey.resize(slen);
            in.read(&tx.senderPubKey[0], slen);
            
            txs.push_back(tx);
        }
        
        Block b(index, txs, prevHash);
        b.timestamp = timestamp;
        b.nonce = nonce;
        b.hash = hash;
        b.merkleRoot = merkle;
        
        chain.push_back(b);
        updateBalances(b);
    }
    in.close();
    std::cout << "[DISK] Blockchain loaded. Height: " << chain.size() << std::endl;
}

void Blockchain::replaceChain(const std::vector<Block>& newChain) {
    if (newChain.size() <= chain.size()) {
        std::cout << "[P2P] Received chain is not longer than current chain." << std::endl;
        return;
    }

    // Verify the new chain
    // 1. Check genesis block (should be same as ours or compliant with rules)
    // 2. Check all blocks
    for (size_t i = 1; i < newChain.size(); i++) {
        const Block& currentBlock = newChain[i];
        const Block& prevBlock = newChain[i-1];

        if (currentBlock.hash != currentBlock.calculateHash()) {
            std::cout << "[P2P] Invalid block hash in received chain." << std::endl;
            return;
        }

        if (currentBlock.prevHash != prevBlock.hash) {
            std::cout << "[P2P] Invalid previous hash link in received chain." << std::endl;
            return;
        }
        
        // Also verify PoW
        // Check if hash meets difficulty target (simplified: check leading zeros)
        std::string target(difficulty, '0');
        if (currentBlock.hash.substr(0, difficulty) != target) {
            std::cout << "[P2P] Invalid PoW in received chain." << std::endl;
            return;
        }

        // Verify Merkle Root
        if (currentBlock.merkleRoot != currentBlock.calculateMerkleRoot()) {
            std::cout << "[P2P] Invalid Merkle Root in received chain." << std::endl;
            return;
        }

        // Verify Signatures (Expensive but necessary for security)
        for (const auto& tx : currentBlock.transactions) {
            if (!verifySignature(tx)) {
                 std::cout << "[P2P] Invalid transaction signature in received chain." << std::endl;
                 return;
            }
        }
    }

    std::cout << "[P2P] Replacing current chain with longer valid chain (Length: " << newChain.size() << ")" << std::endl;
    chain = newChain;
    saveToDisk();
}

}
