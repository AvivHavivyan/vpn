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

// Weird config stuff, only add if the compiler does not recognize the functions.

void WSAAPI freeaddrinfo( struct addrinfo* );

int WSAAPI getaddrinfo( const char*, const char*, const struct addrinfo*,
                        struct addrinfo** );

int WSAAPI getnameinfo( const struct sockaddr*, socklen_t, char*, DWORD,
                        char*, DWORD, int );

int main() {

    WSADATA wsaData; // Contains info about the winsock implementation.
    int iResult; // Number of bytes received.

    // Sockets - server and client.
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    // Initialize Winsock. (Here iResult is the exit code for WSAStartup)
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Specifying information - protocol etc.
    struct addrinfo *result = NULL, *ptr = NULL, hints;

    // Settings for the socket - ipv4,
    ZeroMemory(&hints, sizeof (hints)); // Fills a block of memory with zeroes.
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the local address and port to be used by the server
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup(); // Terminate
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

    // Setup the TCP listening socket - bind.
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    // New connections loop
    listen:

    // Listen for connections
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

    // Main server loop, wait for input
    while (true) {
        bool received = false;
        printf("Waiting... \n");
        // Converting from big endian to little endian.
        // Integers are sent as big endians while many processors use little endian,
        // thus conversion is necessary.
        u_long netContentLength = 0;
        int contentLength;
        iResult = 0;
        while (iResult == 0) {
            iResult = recv(ClientSocket, &netContentLength, 4, 0);
        }
        contentLength = ntohl(netContentLength);
        char message[contentLength];
        memset(message, 0, strlen(message));

        if (iResult > 0) {
            while (!received) {
                char recvbuf[DEFAULT_BUFLEN];
                // Initializing recvbuf to get rid of garbage mem.
                memset(recvbuf, 0, DEFAULT_BUFLEN);
                // If the length of the content in the current iteration
                // is smaller than the buffer size, the current "chunk" is the last.

                // Add jandle connection exceptions
                if (contentLength < DEFAULT_BUFLEN) {
                    iResult = recv(ClientSocket, recvbuf, contentLength, 0);
                    strcat(message,recvbuf);
                    printf("Content length: %d\n", contentLength);
                    printf("Received %d bytes\n", iResult);
                    printf("Recvbuf length: %d\n", strlen(recvbuf));
                    printf("Recvbuf: %s\n", recvbuf);

                    if (strcmp(recvbuf, "exit\n") == 0) {
                        printf("Closing connection... \n");
                        closesocket(ClientSocket);
                        goto listen;
                    }

                    received = true;
                } else {
                    recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
                    // Add the current "chunk" to the full message.
                    strcat(message,recvbuf);
                    contentLength -= DEFAULT_BUFLEN;
                }
            }

            // Echo back the message in 512 byte chunks.
            received = false;
//            char * startChar;
//            char * endChar;
            int startIndex = 0;
            int endIndex = DEFAULT_BUFLEN - 1;

            netContentLength = htonl(contentLength);
            send(ClientSocket, &netContentLength, 4, 0);

            while (!received) {
                if (contentLength < DEFAULT_BUFLEN) {
                    endIndex = contentLength;
                }
                // Get addresses of the desired start and end of the chunk in memory.
//                startChar = &message[startIndex];
//                endChar = &message[endIndex];
                char curMessage[endIndex - startIndex];
                // Allocating space for an array with a certain number of elements.
                // Copy the current chunk to curMessage
                strncpy(curMessage, &message[startIndex], endIndex - startIndex);
                // Move to the next chunk
                startIndex = endIndex + 1;
                endIndex = endIndex + DEFAULT_BUFLEN;
                // Echo the buffer back to the sender

                // When there's still more than 512 bytes left,
                // subtract the maximum buflen to account for the number of bytes left and send to client.
                if (contentLength > DEFAULT_BUFLEN) {
                    contentLength -= DEFAULT_BUFLEN;
                    send(ClientSocket, curMessage, DEFAULT_BUFLEN, 0);
                }
                // Getting to a number smaller or equal to the maximum buflen,
                // means we have reached the end of the message.
                else if (contentLength <= DEFAULT_BUFLEN) {
                    send(ClientSocket, curMessage, contentLength, 0);
                    received = true;
                }

                if (iResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    closesocket(ClientSocket);
                    WSACleanup();
                    return 1;
                }
            }

        } else {
            printf("The connection was terminated unexpectedly. Shutting down... \n");
            goto listen; // Go to the label accepting a new connection.
        }
    }
}