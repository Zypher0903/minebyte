#ifndef P2PNODE_H
#define P2PNODE_H

#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include "../core/Blockchain.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    // Link with ws2_32.lib handled in Makefile or pragma
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    typedef int socket_t;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket(s) close(s)
#endif

namespace Minebyte {

class P2PNode {
private:
    Blockchain& blockchain;
    int port;
    std::vector<std::string> peers;
    std::vector<socket_t> activeConnections;
    std::mutex connectionMutex;
    std::atomic<bool> running;
    std::thread serverThread;

    void listenForConnections();
    void handleClient(socket_t clientSocket);
    void processMessage(const std::string& msg, socket_t sender);
    
    // Protocol Handlers
    void handleChainRequest(socket_t sender);
    void handleChainResponse(const std::string& payload);
    void handleNewBlock(const std::string& payload);
    void handleNewTx(const std::string& payload);

    // Helpers
    std::string serializeBlock(const Block& block);
    Block deserializeBlock(const std::string& data);
    std::string serializeTx(const Transaction& tx);
    Transaction deserializeTx(const std::string& data);

public:
    P2PNode(Blockchain& chain, int port);
    ~P2PNode();

    void start();
    void connectToPeer(const std::string& ip, int port);
    void broadcastBlock(const Block& block);
    void broadcastTransaction(const Transaction& tx);
    void broadcastMessage(const std::string& msg);
};

}

#endif
