#include <winsock2.h>
#include <unistd.h>
#include <stdbool.h>
#include <ws2tcpip.h>
#include <stdio.h>


#define DEFAULT_PORT "27015"
#define DEFAULT_BUFLEN 512

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

void WSAAPI freeaddrinfo( struct addrinfo* );

int WSAAPI getaddrinfo( const char*, const char*, const struct addrinfo*,
                        struct addrinfo** );

int WSAAPI getnameinfo( const struct sockaddr*, socklen_t, char*, DWORD,
                        char*, DWORD, int );

int main() {
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    struct addrinfo *result = NULL, *ptr = NULL, hints;

    //settings for the socket - ipv4,
    ZeroMemory(&hints, sizeof (hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

// Resolve the local address and port to be used by the server

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Initialize the socket with desired values
    ListenSocket = INVALID_SOCKET;
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    listen:

    // Listen
    printf("Listening... ");
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    ClientSocket = INVALID_SOCKET;
    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    } else {
        printf("Connected. \n");
    }

    char *message = NULL;

    // Main server loop, wait for input
    while (true) {
        bool receieved = false;
        printf("Waiting... \n");
        int netContentLength = 0;
        int contentLength;
        iResult = 0;
        while (iResult == 0) {
            iResult = recv(ClientSocket, &netContentLength, 4, 0);
        }
        if (iResult > 0) {
            while (!receieved) {
                int cnt = 0;
                char recvbuf[DEFAULT_BUFLEN];
                int iSendResult;
                int recvbuflen = DEFAULT_BUFLEN;
                contentLength = ntohl(netContentLength);
                if (contentLength < DEFAULT_BUFLEN) {
                    iResult = recv(ClientSocket, recvbuf, contentLength, 0);
                    receieved = true;
                } else {
                    iResult = recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
                    strcat(message,recvbuf);
                }
                if (iResult > 0) {
                    // Echo the buffer back to the sender
                    iSendResult = send(ClientSocket, recvbuf, iResult, 0);
                    if (iSendResult == SOCKET_ERROR) {
                        printf("send failed: %d\n", WSAGetLastError());
                        closesocket(ClientSocket);
                        WSACleanup();
                        return 1;
                    }
                }
                if (strcmp(recvbuf, "exit\n") == 0) {

                    printf("Exiting...");
                    closesocket(ClientSocket);
                    WSACleanup();

                    return 0;
                }
            }
        } else {
            printf("The connection was terminated unexpectedly. Shutting down... \n");
            goto listen;
        }
    }
}