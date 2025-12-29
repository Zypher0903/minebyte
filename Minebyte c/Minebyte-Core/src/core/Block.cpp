#include "Block.h"
#include <ctime>
#include <iostream>
#include <iomanip>
#include <cstring>

namespace Minebyte {

Block::Block(uint32_t idx, const std::vector<Transaction>& txs, const std::string& prev)
    : index(idx), transactions(txs), prevHash(prev), nonce(0) 
{
    timestamp = std::time(nullptr);
    merkleRoot = calculateMerkleRoot();
    hash = calculateHash();
}

std::string Block::hexToString(const uint8_t* data, size_t len) {
    std::stringstream ss;
    for(size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

std::string Block::calculateMerkleRoot() const {
    if (transactions.empty()) return "0000000000000000000000000000000000000000000000000000000000000000";

    std::vector<std::string> leaves;
    for (const auto& tx : transactions) {
        uint8_t txHash[32];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        // Hash the full transaction string
        std::string txStr = tx.toString();
        sha256_update(&ctx, (const uint8_t*)txStr.c_str(), txStr.size());
        sha256_final(&ctx, txHash);
        leaves.push_back(hexToString(txHash, 32));
    }
    
    std::vector<std::string> tree = leaves;
    while (tree.size() > 1) {
        std::vector<std::string> newLevel;
        for (size_t i = 0; i < tree.size(); i += 2) {
            std::string left = tree[i];
            std::string right = (i + 1 < tree.size()) ? tree[i+1] : left; // Duplicate last if odd
            std::string combined = left + right;
            
            uint8_t hash[32];
            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (const uint8_t*)combined.c_str(), combined.size());
            sha256_final(&ctx, hash);
            newLevel.push_back(hexToString(hash, 32));
        }
        tree = newLevel;
    }
    return tree.empty() ? "0" : tree[0];
}

std::string Block::calculateHash() const {
    std::stringstream ss;
    ss << index << prevHash << timestamp << merkleRoot << nonce;
    
    // Transactions are now represented by the Merkle Root, so we don't loop them here
    // This is much more efficient and correct.
    
    std::string input = ss.str();
    
    uint8_t hashRaw[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)input.c_str(), input.size());
    sha256_final(&ctx, hashRaw);
    
    return hexToString(hashRaw, SHA256_BLOCK_SIZE);
}

void Block::mineBlock(uint32_t difficulty) {
    std::string target(difficulty, '0');
    
    while(hash.substr(0, difficulty) != target) {
        nonce++;
        hash = calculateHash();
    }
    
    std::cout << "[SYSTEM] Block Mined: " << hash << std::endl;
}

}
