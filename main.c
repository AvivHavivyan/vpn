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

    // The full message / packet.
    char *message = "";

    // Main server loop, wait for input
    while (true) {
        bool receieved = false;
        bool exit = false;
        printf("Waiting... \n");
        // Converting from big endian to little endian.
        u_long netContentLength = 0;
        int contentLength;
        iResult = 0;
        while (iResult == 0) {
            iResult = recv(ClientSocket, &netContentLength, 4, 0);
        }
        contentLength = ntohl(netContentLength);
        if (iResult > 0) {
            while (!receieved) {
                int cnt = 0;
                char recvbuf[DEFAULT_BUFLEN];
                // Initializing recvbuf to get rid of garbage mem;
                memset(recvbuf, 0, DEFAULT_BUFLEN);
                int iSendResult;
                int recvbuflen = DEFAULT_BUFLEN;
                // If the length of the content in the current iteration
                // is smaller than the buffer size, the current "chunk" is the last.
                if (contentLength < DEFAULT_BUFLEN) {
                    iResult = recv(ClientSocket, recvbuf, contentLength, 0);
                    message = recvbuf;
                    printf("Content length: %d\n", contentLength);
                    printf("Received %d bytes\n", iResult);
                    printf("Recvbuf length: %d\n", strlen(recvbuf));
                    printf("Recvbuf: %s\n", recvbuf);

                    if (strcmp(recvbuf, "exit\n") == 0) {
                        printf("Closing connection... \n");
                        closesocket(ClientSocket);
                        exit = true;
                        goto listen;
                    }

                    receieved = true;
                } else {
                    recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
                    // Add the current "chunk" to the full message.
                    strcat(message,recvbuf);
                    contentLength -= DEFAULT_BUFLEN;
                }
            }

            // Echo back the message:
            receieved = false;
            char * startChar;
            char * endChar;
            int startIndex = 0;
            int endIndex = DEFAULT_BUFLEN - 1;

            char * curMessage;
            u_long messageLen = strlen(message);

            while (!receieved) {

                if (contentLength < DEFAULT_BUFLEN) {
                    endIndex = contentLength - 1;
                }
                startChar = &message[startIndex];
                endChar = &message[endIndex];
                curMessage = calloc(1, endChar - startChar + 1);
                memcpy(curMessage, startChar, endChar - startChar);
                startIndex = endIndex + 1;
                endIndex = endIndex + DEFAULT_BUFLEN;
                // Echo the buffer back to the sender

                if (contentLength > DEFAULT_BUFLEN) {
                    contentLength -= DEFAULT_BUFLEN;
                    netContentLength = htonl(DEFAULT_BUFLEN);
                    send(ClientSocket, &netContentLength, 4, 0);
                }
                else if (contentLength <= DEFAULT_BUFLEN) {
                    netContentLength = htonl(contentLength);
                    send(ClientSocket, &netContentLength, 4, 0);
                    receieved = true;
                }

                iResult = send(ClientSocket, curMessage, contentLength, 0);

                if (iResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    closesocket(ClientSocket);
                    WSACleanup();
                    return 1;
                }
            }

        } else {
            printf("The connection was terminated unexpectedly. Shutting down... \n");
            goto listen;
        }
    }
}