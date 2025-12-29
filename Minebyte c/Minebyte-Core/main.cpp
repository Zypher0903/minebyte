#include <iostream>
#include <thread>
#include <cstring>
#include <string>
#include <vector>
#include "src/core/Blockchain.h"
#include "src/core/Block.h"
#include "src/crypto/ecc/uECC.h"
#include "src/p2p/P2PNode.h"

// Networking abstraction for Windows/Linux
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define IS_VALIDSOCKET(s) ((s) != INVALID_SOCKET)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    typedef int socket_t;
    #define CLOSE_SOCKET(s) close(s)
    #define IS_VALIDSOCKET(s) ((s) >= 0)
    #define INVALID_SOCKET -1
#endif

using namespace Minebyte;

void print_header() {
    std::cout << "========================================" << std::endl;
    std::cout << "   MINEBYTE CORE [v1.1.0]               " << std::endl;
    std::cout << "   Decentralized P2P Network            " << std::endl;
    std::cout << "========================================" << std::endl;
}

void rpcListener(Blockchain& bc, P2PNode& p2p, int port) {
    #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALIDSOCKET(server_fd)) {
        std::cerr << "[RPC] Failed to create socket." << std::endl;
        return;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[RPC] Bind failed." << std::endl;
        return;
    }

    listen(server_fd, 5);
    std::cout << "[RPC] Listening on port " << port << "..." << std::endl;

    while (true) {
        socket_t client = accept(server_fd, nullptr, nullptr);
        if (!IS_VALIDSOCKET(client)) continue;

        char buffer[4096] = {0};
        recv(client, buffer, 4096, 0);
        
        std::string json(buffer);
        // Basic JSON parsing (looking for keys manually)
        if (json.find("senderPubKey") != std::string::npos) {
            try {
                Transaction tx;
                size_t pos;

                // Helper lambda to extract string value
                auto extractStr = [&](const std::string& key) -> std::string {
                    pos = json.find("\"" + key + "\":\"");
                    if (pos == std::string::npos) return "";
                    pos += key.length() + 4; // quote + quote + colon + quote
                    size_t end = json.find("\"", pos);
                    return json.substr(pos, end - pos);
                };

                tx.senderPubKey = extractStr("senderPubKey");
                tx.receiver = extractStr("receiver");
                tx.signature = extractStr("signature");
                
                pos = json.find("\"amount\":");
                if (pos != std::string::npos) {
                    tx.amount = std::stod(json.substr(pos + 9));
                }
                
                pos = json.find("\"timestamp\":");
                if (pos != std::string::npos) {
                    tx.timestamp = std::stoull(json.substr(pos + 12));
                }

                if (bc.addTransaction(tx)) {
                    std::cout << "[RPC] New Transaction via RPC! Broadcasting to network..." << std::endl;
                    p2p.broadcastTransaction(tx); // GOSSIP PROTOCOL

                    const char* msg = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nTransaction Accepted";
                    send(client, msg, strlen(msg), 0);
                } else {
                    const char* msg = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nTransaction Rejected";
                    send(client, msg, strlen(msg), 0);
                }
            } catch (...) {
                std::cerr << "[RPC] Error parsing TX" << std::endl;
            }
        }

        CLOSE_SOCKET(client);
    }
}

int main(int argc, char* argv[]) {
    print_header();

    // Default Configuration
    int p2pPort = 8333;
    int rpcPort = 8334;
    std::vector<std::string> peers;

    // Parse Args: ./minebyte_node [P2P_PORT] [RPC_PORT] [PEER_IP:PORT]...
    if (argc > 1) p2pPort = std::stoi(argv[1]);
    if (argc > 2) rpcPort = std::stoi(argv[2]);
    for (int i = 3; i < argc; i++) {
        peers.push_back(argv[i]);
    }

    // Hardcoded Bootstrap Peers (if none provided and we are not the genesis node)
    // Assumption: Genesis/Seed node runs on 8333. If we are not 8333, try to connect to it.
    if (peers.empty() && p2pPort != 8333) {
        std::cout << "[INIT] No peers provided. Adding default bootstrap peer (127.0.0.1:8333)..." << std::endl;
        peers.push_back("127.0.0.1:8333");
    }
    
    std::cout << "[INIT] Initializing Minebyte Secure Protocol..." << std::endl;
    Blockchain minebyteCoin;
    
    std::cout << "[INFO] Current Height: " << minebyteCoin.getChain().size() << std::endl;

    // --- P2P NETWORK INIT ---
    std::cout << "[SYSTEM] Starting P2P Network Node on port " << p2pPort << "..." << std::endl;
    P2PNode p2pNode(minebyteCoin, p2pPort);
    p2pNode.start();

    // Connect to Bootstrap Peers
    for (const auto& peer : peers) {
        size_t colon = peer.find(':');
        if (colon != std::string::npos) {
            std::string ip = peer.substr(0, colon);
            int port = std::stoi(peer.substr(colon + 1));
            std::cout << "[P2P] Connecting to bootstrap peer: " << peer << "..." << std::endl;
            p2pNode.connectToPeer(ip, port);
        }
    }
    // ------------------------

    // --- CRYPTO TEST ---
    std::cout << "\n[CRYPTO TEST] Testing secp256k1 signature verification..." << std::endl;
    uint8_t priv[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t pub[64];
    uint8_t hash[32];
    memset(hash, 0xDE, 32); 
    uint8_t sig[64];

    uECC_make_key(pub, priv, uECC_secp256k1());
    uECC_sign(priv, hash, 32, sig, uECC_secp256k1());

    if (uECC_verify(pub, hash, 32, sig, uECC_secp256k1())) {
        std::cout << "[SUCCESS] ECDSA verification PASSED." << std::endl;
    } else {
        std::cout << "[FAIL] Verification failed!" << std::endl;
    }
    // -------------------

    std::cout << "\n[SYSTEM] Starting RPC Server on port " << rpcPort << "..." << std::endl;
    std::thread rpcThread(rpcListener, std::ref(minebyteCoin), std::ref(p2pNode), rpcPort);
    rpcThread.detach();

    std::cout << "[SYSTEM] Node is running." << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  [ENTER] - Mine pending transactions" << std::endl;
    
    while(true) {
        if (std::cin.get() == '\n') {
            minebyteCoin.minePendingTransactions("NODE_MINER_WALLET");
            std::cout << "Block mined! Broadcasting to network..." << std::endl;
            // Broadcast the new block
            p2pNode.broadcastBlock(minebyteCoin.getLastBlock());
        }
    }

    return 0;
}
