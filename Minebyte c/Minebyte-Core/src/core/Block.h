#ifndef BLOCK_H
#define BLOCK_H

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include "../crypto/sha256.h"

namespace Minebyte {

struct Transaction {
    std::string senderPubKey; // Hex string of public key
    std::string receiver;     // Address (hash of pubkey)
    double amount;
    uint64_t timestamp;
    std::string signature;    // Hex string of signature
    std::string txId;         // Hash of the transaction content

    // Convert transaction data (excluding signature) to string for signing/hashing
    std::string getDataString() const {
        std::stringstream ss;
        ss << senderPubKey << receiver << amount << timestamp;
        return ss.str();
    }

    std::string toString() const {
        std::stringstream ss;
        ss << txId << ":" << senderPubKey << ":" << receiver << ":" << amount << ":" << timestamp << ":" << signature;
        return ss.str();
    }
};

class Block {
public:
    uint32_t index;
    uint64_t timestamp;
    std::vector<Transaction> transactions;
    std::string prevHash;
    std::string merkleRoot;
    std::string hash;
    uint64_t nonce;

    Block(uint32_t idx, const std::vector<Transaction>& txs, const std::string& prevHash);
    
    std::string calculateHash() const;
    std::string calculateMerkleRoot() const;
    void mineBlock(uint32_t difficulty);
    
    static std::string hexToString(const uint8_t* data, size_t len);
};

}

#endif
