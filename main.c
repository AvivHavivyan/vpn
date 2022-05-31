#include <winsock2.h>
#include <stdbool.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include "utils.h"

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

char * getHostAddress(char * request) {
    char delimiter[] = " ";
    strtok(request, delimiter);
    char * address = strtok(NULL, delimiter);
    return address;
}

char * getHttpHostAddress(char * request) {
    char delimiter[] = "/";
    char requestcpy[strlen(request)];
    strtok(request, delimiter);
    char * address = strtok(NULL, delimiter);
    return address;
}

char * getHostName(char * address) {
    char * name;
    char addrcpy[strlen(address)];
    strncpy(addrcpy, address, strlen(address));
    if (strstr("http", address)) {
        char delimiter[] = ":";
        strtok(address, delimiter);
        name = (NULL, delimiter);
    } else {
        char delimiter[] = ":";
        name = strtok(address, delimiter);
    }
    return name;
}

char * getPort(char * address) {
    char delimiter[] = ":";
    char addrcpy[strlen(address)];
    char * token = strtok(address, delimiter);
    char * port = strtok(NULL, delimiter);
    if (token == NULL) return NULL;
    return port;
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;
    char a_str_cpy[strlen(a_str)];
    strcpy(a_str_cpy, a_str);
    char* tmp = a_str_cpy;


    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str_cpy + strlen(a_str_cpy) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str_cpy, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

int checkMethodType(char * response) {
    char * ret;
    char rspcpy[strlen(response)];
//    strncpy(rspcpy, reso)
    ret = strstr(response, "CONNECT");
    if (ret) return 1;
    else return 0;
}



int getContentLength(char * response) {
    char * header = "content-length";
    char rspcpy[strlen(response)];
    strcpy(rspcpy, response);
    header = lowerstring(rspcpy);
    char * substr = strstr(rspcpy, header);
    char * delim = "\n";
    char * header_line = strtok(substr, delim);
    delim = ":";
    strtok(header_line, delim);
    printf("lenstr: %s", header_line);

    char * len_str = strtok(NULL, delim);
    return atoi(len_str);
}



int setUpServer(int iResult, struct addrinfo hints, struct addrinfo * result,  SOCKET *ListenSocket) {
    // Resolve the local address and port to be used by the server
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup(); // Terminate
        return 1;
    }

    // Initialize the socket with desired values
    *ListenSocket = INVALID_SOCKET;
    *ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (*ListenSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket - bind.
    iResult = bind(*ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(*ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);
    return 0;
}

int waitForConnections() {

}

char * receiveMessage() {

}

int connectToWebserver() {

}

int sendMessageToClient() {

}

int handleHTTP() {

}

int thread(SOCKET *ClientSocket, SOCKET *HttpSocket, const SOCKET *ListenSocket, struct addrinfo hints, struct addrinfo * http_result) {

    int iResult = 0;
listen:
    // Listen for connections
    printf("Listening... ");
    if (listen(*ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(*ListenSocket);
        WSACleanup();
        return 1;
    }

    *ClientSocket = INVALID_SOCKET;
    // Accept a client socket
    *ClientSocket = accept(*ListenSocket, NULL, NULL);
    if (*ClientSocket == INVALID_SOCKET) {
        closesocket(*ListenSocket);
        WSACleanup();
        return 1;
    } else {
        printf("Connected. \n");
    }
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
            iResult = recv(*ClientSocket, &netContentLength, 4, 0);
        }
        contentLength = ntohl(netContentLength);
        char message[contentLength];
        memset(message, 0, strlen(message));
        printf("Content length: %d \n", contentLength);
        if (contentLength == 0) {
            printf("Connection terminated unexpectedly.");
            closesocket(*ClientSocket);
//            WSACleanup();
            goto listen;
        }

        if (iResult > 0) {
            while (!received) {
                char recvbuf[DEFAULT_BUFLEN];

                // Initializing recvbuf to get rid of garbage mem.
                memset(recvbuf, 0, DEFAULT_BUFLEN);

                // If the length of the content in the current iteration
                // is smaller than the buffer size, the current "chunk" is the last.
                // Add handle connection exceptions
                if (contentLength < DEFAULT_BUFLEN) {
                    recv(*ClientSocket, recvbuf, contentLength + 1, 0);
                    strcat(message,recvbuf);
                    char messagecopy[strlen(message)];
                    strncpy(messagecopy, message, strlen(message));
                    char** tokens;
//                    tokens = str_split(messagecopy, '\n');

//                    if (tokens)
//                    {
//                        int i;
//                        for (i = 0; *(tokens + i); i++)
//                        {
//                            printf("line=%s\n", *(tokens + i));
//                            free(*(tokens + i));
//                        }
//                        printf("\n");
//                        free(tokens);
//                    }

                    if (strcmp(recvbuf, "exit") == 0) {
                        printf("Closing connection... \n");
                        closesocket(*ClientSocket);
                        goto listen;
                    }

                    received = true;
                } else {
                    recv(*ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
                    // Add the current "chunk" to the full message.
                    strcat(message,recvbuf);
                    contentLength -= DEFAULT_BUFLEN;
                    printf("ContentLength: %d \n", contentLength);

                }
            }

            printf("%s", message);

            char messagecpy[strlen(message)];
            strncpy(messagecpy, message, strlen(message));
            char * hostaddress = getHostAddress(messagecpy);
            char hostaddresscopy[strlen(hostaddress)];
            char hostaddresscpy[strlen(hostaddress)];
            strcpy(hostaddresscpy, hostaddress);
            strcpy(hostaddresscopy, hostaddress);

            char * hostname = getHostName(hostaddresscpy);
            char * port = getPort(hostaddress);
            strcpy(hostaddress, hostaddresscopy);
            hints.ai_flags = 0;

            if (strcmp(port, "443") != 0) {
                port = "80";
                char * http_host_address = getHttpHostAddress(hostaddresscopy);
                printf("http host address: %s \n", http_host_address);
                iResult = getaddrinfo(http_host_address, port, &hints, &http_result);
                if (iResult != 0) {
                    iResult = getaddrinfo(hostaddress, port, &hints, &http_result);
                    printf("http host address: %s \n", hostaddress);

                }
            } else {
                iResult = getaddrinfo(hostname, port, &hints, &http_result);
            }

            if (iResult != 0) {
                printf("Failed to retrieve address data. \n");
                break;
            }
            *HttpSocket = socket(http_result->ai_family, http_result->ai_socktype, http_result->ai_protocol);
            struct sockaddr_in  *sockaddr_ipv4;
            sockaddr_ipv4 = (struct sockaddr_in *) http_result->ai_addr;
            printf("\tIPv4 address %s\n", inet_ntoa(sockaddr_ipv4->sin_addr));
            iResult = connect(*HttpSocket, http_result->ai_addr, http_result->ai_addrlen);

            if (iResult != 0) {
                printf("Failed to connect to remote server. \n");
                WSACleanup();
                return -1;
            } else {
                printf("Connected to remote server successfully on port %s. \n", port);
            }

            if (checkMethodType(message) == 1) {
                printf("CONNECT method. \n");
                char * connect = "HTTP/1.1 200 Connection Established \r\n\r\n";
                contentLength = strlen(connect);
                netContentLength = htonl(contentLength);
                send(*ClientSocket, &netContentLength, 4, 0);
                send(*ClientSocket, connect, strlen(connect), 0);
                closesocket(*ClientSocket);
//                memset(connect, 0, strlen(connect));
                goto listen;
            }

            iResult = send(*HttpSocket,  message, strlen(message), 0);
            if (iResult == SOCKET_ERROR) {
                printf("Failed to send message to remote server. \n");
                return -1;
            } else {
                printf("Bytes sent to remote webserver: %d \n", iResult);
            }

            //allocate base size/length

            char *response = (char *) malloc(1024);

//            free(response);
            memset(response, 0, strlen(response));
            int cnt = 0;

            char buffer[1024];
            memset(buffer, 0, 1024);

            int bytesRecv = 0;
            iResult = 1024;

            // wait for the end of http headers

            while (!strstr(buffer, "\r\n\r\n")) {
                memset(buffer, 0, 1024);

                iResult = recv(*HttpSocket, buffer, 1024, 0);
                bytesRecv += iResult;
                if (bytesRecv > strlen(response)) {
                    realloc(response, strlen(response) + 1024);
                }
                strncat(response, buffer, strlen(buffer));
                printf("Bytes received from Webserver: %d \n", iResult);
                if (iResult == 0) {
                    goto listen;
                }
                printf("Msg: %s \n", buffer);
//                    memset(buffer, 0, 1024);
                if (iResult == SOCKET_ERROR)
                    return -1;
            }
            char rspcpy[strlen(response)];
            char rspcpy2[strlen(response)];
            strcpy(rspcpy, response);
            strcpy(rspcpy2, response);

            if (strstr(lowerstring(rspcpy), "content-length")) {
                int len = getContentLength(rspcpy2);
                printf("%d", len);
                char buff[len];
                int total_bytes_received = 0;
                while (total_bytes_received < len) {
                    total_bytes_received += recv(*HttpSocket, buff, len, 0);
                    strcat(response, buff);
                    memset(response, 0, strlen(response));
                }
            } else if (strstr(lowerstring(rspcpy), "transfer-encoding")){

                while (!strstr(buffer, "\r\n")) {
                    memset(buffer, 0, 1024);

                    iResult = recv(*HttpSocket, buffer, 1024, 0);
                    bytesRecv += iResult;
                    if (bytesRecv > strlen(response)) {
                        realloc(response, strlen(response) + 1024);
                    }
                    strncat(response, buffer, strlen(buffer));
                    printf("Bytes received from Webserver: %d \n", iResult);
                    if (iResult == 0) {
                        goto listen;
                    }
                    printf("Msg: %s \n", buffer);
//                    memset(buffer, 0, 1024);
                    if (iResult == SOCKET_ERROR)
                        return -1;
                }
//                char chunk_len[8];
//                int len = 0;
//                recv(*HttpSocket, chunk_len, strlen(chunk_len), 0);
//                len = atoi(chunk_len);
//                printf("chunk len: %d", len);

            }

            printf("Full message: %s \n", response);

            // Echo back the message in 512 byte chunks.
            received = false;
            int startIndex = 0;
            int endIndex = DEFAULT_BUFLEN - 1;

            contentLength = strlen(response);
            int originalContentLength = contentLength;
            char * msg = message;

            netContentLength = htonl(contentLength);
            send(*ClientSocket, &netContentLength, 4, 0);

            while (!received) {
                if (contentLength < DEFAULT_BUFLEN) {
                    endIndex = originalContentLength;
                }
                char curMessage[endIndex - startIndex + 1];
                memset(curMessage, 0, DEFAULT_BUFLEN);
                // Allocating space for an array with a certain number of elements.
                // Copy the current chunk to curMessage
                strncpy(curMessage, &response[startIndex], endIndex - startIndex);
                // Move to the next chunk


                // Echo the buffer back to the sender
                // When there's still more than 512 bytes left,
                // subtract the maximum buflen to account for the number of bytes left and send to client.
                if (contentLength > DEFAULT_BUFLEN) {
                    iResult = send(*ClientSocket, curMessage, DEFAULT_BUFLEN, 0);
                    startIndex = endIndex;
                    endIndex = endIndex + DEFAULT_BUFLEN;
                }
                    // Getting to a number smaller or equal to the maximum buflen,
                    // means we have reached the end of the message.
                else if (contentLength <= DEFAULT_BUFLEN) {
                    iResult = send(*ClientSocket, curMessage, strlen(curMessage), 0);
//                    received = true;
                    closesocket(*HttpSocket);
                    closesocket(*ClientSocket);
                    memset(response, 0, strlen(response));
                    goto listen;
                }

                contentLength -= DEFAULT_BUFLEN;


                if (iResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    printf("The connection was terminated unexpectedly. Shutting down... \n");
                    goto listen;
                }
            }

        } else {
            printf("The connection was terminated unexpectedly. Shutting down... \n");
            goto listen; // Go to the label accepting a new connection.
        }
    }
}

int main() {

    WSADATA wsaData; // Contains info about the winsock implementation.
    int iResult; // Number of bytes received.

    // Sockets - server and client.
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    SOCKET HttpSocket = INVALID_SOCKET;

    // Initialize Winsock. (Here iResult is the exit code for WSAStartup)
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Specifying information - protocol etc.
    struct addrinfo *result = NULL, *ptr = NULL, hints, *http_result = NULL;

    // Settings for the socket - ipv4,
    ZeroMemory(&hints, sizeof (hints)); // Fills a block of memory with zeroes.
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    setUpServer(iResult, hints, result, &ListenSocket);


    //main thread, handles client requests and http.
    thread(&ClientSocket, &HttpSocket, &ListenSocket, hints, http_result);

}