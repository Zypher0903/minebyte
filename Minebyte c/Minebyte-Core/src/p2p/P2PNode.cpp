#include "P2PNode.h"
#include <iostream>
#include <sstream>
#include <cstring>

namespace Minebyte {

P2PNode::P2PNode(Blockchain& chain, int p) : blockchain(chain), port(p), running(false) {}

P2PNode::~P2PNode() {
    running = false;
    if (serverThread.joinable()) {
        serverThread.join();
    }
    // Close all connections
    for (auto sock : activeConnections) {
        closesocket(sock);
    }
}

void P2PNode::start() {
    running = true;
    serverThread = std::thread(&P2PNode::listenForConnections, this);
    std::cout << "[P2P] Network node started on port " << port << std::endl;
}

void P2PNode::listenForConnections() {
    #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        std::cerr << "[P2P] Failed to create socket." << std::endl;
        return;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[P2P] Bind failed." << std::endl;
        return;
    }

    listen(server_fd, 5);

    while (running) {
        socket_t client = accept(server_fd, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;

        std::cout << "[P2P] New peer connected!" << std::endl;
        
        {
            std::lock_guard<std::mutex> lock(connectionMutex);
            activeConnections.push_back(client);
        }

        std::thread(&P2PNode::handleClient, this, client).detach();
    }
}

void P2PNode::connectToPeer(const std::string& ip, int port) {
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[P2P] Failed to connect to " << ip << ":" << port << std::endl;
        closesocket(sock);
        return;
    }

    std::cout << "[P2P] Connected to " << ip << ":" << port << std::endl;
    
    {
        std::lock_guard<std::mutex> lock(connectionMutex);
        activeConnections.push_back(sock);
    }

    // Immediately request chain sync
    std::string msg = "REQ_CHAIN:";
    send(sock, msg.c_str(), msg.length(), 0);

    std::thread(&P2PNode::handleClient, this, sock).detach();
}

void P2PNode::handleClient(socket_t clientSocket) {
    char buffer[16384]; // Large buffer for chain data
    while (running) {
        int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead <= 0) {
            // Disconnected
            break;
        }
        buffer[bytesRead] = '\0';
        std::string msg(buffer);
        processMessage(msg, clientSocket);
    }
    closesocket(clientSocket);
}

void P2PNode::broadcastMessage(const std::string& msg) {
    std::lock_guard<std::mutex> lock(connectionMutex);
    for (auto sock : activeConnections) {
        send(sock, msg.c_str(), msg.length(), 0);
    }
}

void P2PNode::broadcastBlock(const Block& block) {
    std::string payload = serializeBlock(block);
    std::string msg = "BLOCK:" + payload;
    broadcastMessage(msg);
}

void P2PNode::broadcastTransaction(const Transaction& tx) {
    std::string payload = serializeTx(tx);
    std::string msg = "TX:" + payload;
    broadcastMessage(msg);
}

void P2PNode::processMessage(const std::string& msg, socket_t sender) {
    size_t delimiter = msg.find(':');
    if (delimiter == std::string::npos) return;

    std::string type = msg.substr(0, delimiter);
    std::string payload = msg.substr(delimiter + 1);

    if (type == "REQ_CHAIN") {
        handleChainRequest(sender);
    } else if (type == "CHAIN") {
        handleChainResponse(payload);
    } else if (type == "BLOCK") {
        handleNewBlock(payload);
    } else if (type == "TX") {
        handleNewTx(payload);
    }
}

void P2PNode::handleChainRequest(socket_t sender) {
    // Simple implementation: Send whole chain (inefficient but works for now)
    // Format: CHAIN:COUNT|BLOCK1_DATA|BLOCK2_DATA...
    std::stringstream ss;
    const auto& chain = blockchain.getChain();
    ss << chain.size();
    
    for (const auto& block : chain) {
        ss << "|" << serializeBlock(block);
    }

    std::string response = "CHAIN:" + ss.str();
    send(sender, response.c_str(), response.length(), 0);
}

void P2PNode::handleChainResponse(const std::string& payload) {
    // Parse chain and try to replace
    std::vector<Block> newChain;
    std::stringstream ss(payload);
    std::string segment;
    
    // First segment is count
    if (!std::getline(ss, segment, '|')) return;
    int count = std::stoi(segment);
    
    // Read blocks
    while (std::getline(ss, segment, '|')) {
        if (segment.empty()) continue;
        newChain.push_back(deserializeBlock(segment));
    }

    if (newChain.size() > 0) {
        blockchain.replaceChain(newChain);
    }
}

void P2PNode::handleNewBlock(const std::string& payload) {
    Block newBlock = deserializeBlock(payload);
    // Try to add to chain (validation happens inside replaceChain equivalent or manual add)
    // For now, let's just re-request chain if we see a block with higher index
    // Or simpler: implement addBlock if valid
    
    // Simplest sync strategy: If we see a new block, check if it fits our chain tip
    Block lastBlock = blockchain.getLastBlock();
    if (newBlock.prevHash == lastBlock.hash && newBlock.index == lastBlock.index + 1) {
        // It fits! Need verify method in blockchain exposed?
        // For now, we assume if it fits, we take it (Verification TODO)
        // blockchain.addBlock(newBlock); // Missing method, use sync for now
        std::cout << "[P2P] Received new block " << newBlock.index << ". Syncing..." << std::endl;
        std::string msg = "REQ_CHAIN:";
        broadcastMessage(msg);
    }
}

void P2PNode::handleNewTx(const std::string& payload) {
    Transaction tx = deserializeTx(payload);
    if (blockchain.addTransaction(tx)) {
        std::cout << "[P2P] Received new transaction: " << tx.txId << std::endl;
        // Re-broadcast to other peers (flooding)
        // Check if we already have it to avoid loops? addTransaction returns false if invalid/exists
        // But for now, simple flood
    }
}

// Serialization Helpers (Manual JSON-ish)
std::string P2PNode::serializeBlock(const Block& block) {
    std::stringstream ss;
    ss << block.index << "," << block.timestamp << "," << block.prevHash << "," 
       << block.merkleRoot << "," << block.nonce << "," << block.hash << ",";
    
    ss << block.transactions.size();
    for (const auto& tx : block.transactions) {
        ss << ";" << serializeTx(tx);
    }
    return ss.str();
}

Block P2PNode::deserializeBlock(const std::string& data) {
    std::stringstream ss(data);
    std::string segment;
    std::vector<std::string> parts;
    
    // Split by comma for header
    while (std::getline(ss, segment, ',')) {
        parts.push_back(segment);
        if (parts.size() == 7) break; // txs are the rest
    }
    
    uint32_t index = std::stoul(parts[0]);
    // Timestamp...
    // Reconstruct block... this is getting complex for single line
    // Let's assume a simplified reconstruction for the prototype
    
    // Hack: we need a proper constructor or setters
    // Re-using the constructor that calculates hash might be wrong if we want to preserve the received hash
    // We should trust the received data structure
    
    std::vector<Transaction> txs;
    // Parse transactions part (rest of string)
    std::string txPart;
    std::getline(ss, txPart); // Read the rest
    
    if (!txPart.empty()) {
        std::stringstream txss(txPart);
        std::string txCountStr;
        std::getline(txss, txCountStr, ';'); // Skip count for now or use it
        
        std::string txStr;
        while (std::getline(txss, txStr, ';')) {
            if (!txStr.empty()) txs.push_back(deserializeTx(txStr));
        }
    }
    
    Block b(index, txs, parts[2]);
    b.timestamp = std::stoull(parts[1]);
    b.merkleRoot = parts[3];
    b.nonce = std::stoull(parts[4]);
    b.hash = parts[5];
    
    return b;
}

std::string P2PNode::serializeTx(const Transaction& tx) {
    return tx.toString(); // Uses colon separated format
}

Transaction P2PNode::deserializeTx(const std::string& data) {
    Transaction tx;
    std::stringstream ss(data);
    std::string segment;
    std::vector<std::string> parts;
    
    while (std::getline(ss, segment, ':')) {
        parts.push_back(segment);
    }
    
    if (parts.size() >= 6) {
        tx.txId = parts[0];
        tx.senderPubKey = parts[1];
        tx.receiver = parts[2];
        tx.amount = std::stod(parts[3]);
        tx.timestamp = std::stoull(parts[4]);
        tx.signature = parts[5];
    }
    return tx;
}

}
