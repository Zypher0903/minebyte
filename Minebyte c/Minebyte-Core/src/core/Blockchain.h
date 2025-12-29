#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "Block.h"
#include <vector>
#include <map>

namespace Minebyte {

class Blockchain {
private:
    uint32_t difficulty;
    std::vector<Block> chain;
    std::vector<Transaction> pendingTransactions;
    std::map<std::string, double> accounts; // Address -> Balance map

    // Helper to update balance from a block
    void updateBalances(const Block& block);

public:
    Blockchain();
    
    void createGenesisBlock();
    Block getLastBlock() const;
    
    // Returns true if transaction is valid and added
    bool addTransaction(Transaction tx);
    
    void minePendingTransactions(const std::string& minerAddress);
    bool isChainValid() const;
    double getBalance(const std::string& address) const;
    
    // Persistence
    void saveToDisk() const;
    void loadFromDisk();
    
    // Verification helpers
    static bool verifySignature(const Transaction& tx);
    static std::string deriveAddress(const std::string& pubKeyHex);

    const std::vector<Block>& getChain() const { return chain; }
    
    // P2P Sync
    void replaceChain(const std::vector<Block>& newChain);
    std::vector<Transaction> getPendingTransactions() const { return pendingTransactions; }
};

}

#endif
