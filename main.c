#include <winsock2.h>
#include <stdbool.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include "utils.h"


#define DEFAULT_PORT "27015"
#define HTTP_PORT "443"
#define DEFAULT_BUFLEN 512
#define KEY_LEN 256

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

// TODO: add encryption

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
    char addrcpy[strlen(address)];
    strcpy(addrcpy, address);
    address = strtok(address, ":");
    if (strlen(addrcpy) == 0) return address;
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


int getlengthtype(char * response, int len) {
    //check for transfer-encoding: chunked.
    char lower[len];
    memset(lower, 0, len);
    //CHANGE TO ACCEPT NULLBYTES? idk i don't care since it's only the headers
    memcpy(lower, response, len);
    lowerstring(lower);
    if (strstr(lower, "transfer-encoding: chunked")) {
        return 1;
    }
    if (strstr(lower, "content-length")) {
        return 0;
    }
    return -1;
}



int checkMethodType(char * response) {
    char * ret;
    ret = strstr(response, "CONNECT");
    if (ret) return 1;
    else return 0;
}


// Assuming there are no nullbytes in the headers.
int getContentLength(char * response) {
    char * header = "content-length";
    char rspcpy[strlen(response)];
    strcpy(rspcpy, response);
    lowerstring(rspcpy);
    char * substr = strstr(rspcpy, header);
    char * delim = "\n";
    char * header_line = strtok(substr, delim);
    delim = ":";
    strtok(header_line, delim);

    char * len_str = strtok(NULL, delim);
    printf("lenstr: %s", len_str);

    return atoi(len_str);
}

int getChunkLength(char * response, int len) {
    char respcpy[len];
    memset(respcpy, 0, len);
    memcpy(respcpy, response, len);
}

int setUpListenSocket(int iResult, struct addrinfo hints, struct addrinfo * result, SOCKET *ListenSocket) {
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

//    freeaddrinfo(result);
    return 0;
}

int handleHttps(char * request) {

}

int encrypt(char * msg) {

}

int decrypt(char * msg) {

}

int sendKey() {

}

int acceptConnection(int key) {

}

int genKey() {
    // check for existing key
    RSA * key = 0;
    struct bignum_st * bn = 0;
    int err = 0;
    if (!(key = RSA_new())) return -1;
    if (!(bn = BN_new())) return -2;
    if (!(err = BN_set_word(bn,RSA_F4))) {
        BN_free(bn);
        return err;
    }

    if (!(err = RSA_generate_key_ex(key,2048,bn,NULL))) {
        BN_free(bn);
        RSA_free(key);
        return err;
    }

    RSA * private = RSAPrivateKey_dup(key);
    RSA * public = RSAPublicKey_dup(key);

    const unsigned char test[4] = "Test";
    u_char encrypted[RSA_size(key)];
    RSA_public_encrypt(4, test, encrypted, key, RSA_PKCS1_OAEP_PADDING);
    u_char decrypted[4];
    RSA_private_decrypt(256, encrypted, decrypted, key, RSA_PKCS1_OAEP_PADDING);


    FILE *fptr;
    fptr = fopen("C:\\Users\\Aviv\\private_server.pem","wb");
    fwrite(private, 1, 256, fptr);
    fclose(fptr);

    fptr = fopen("C:\\Users\\Aviv\\public_server.pem","wb");
    fwrite(public, 1, 256, fptr);
    fclose(fptr);

    return 0;
}

int keysExchange(SOCKET *ListenSocket, SOCKET *ClientSocketAuth, struct addrinfo hints) {
    int iResult = 0;

    printf("Listening... ");
    if (listen(*ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(*ListenSocket);
        WSACleanup();
        return -1;
    }

    *ClientSocketAuth = INVALID_SOCKET;
    // Accept a client socket
    *ClientSocketAuth = accept(*ListenSocket, NULL, NULL);
    if (*ClientSocketAuth == INVALID_SOCKET) {
        closesocket(*ListenSocket);
        WSACleanup();
        return -1;
    } else {
        printf("Connected. \n");
    }

    u_long netContentLength = 0;
    int contentLength;
    iResult = 0;
    while (iResult == 0) {
        iResult = recv(*ClientSocketAuth, &netContentLength, 4, 0);
    }

    contentLength = ntohl(netContentLength);
    char message[contentLength];
    memset(message, 0, strlen(message));
    printf("Content length: %d \n", contentLength);

    if (contentLength == 0) {
        printf("Connection terminated unexpectedly.");
        closesocket(*ClientSocketAuth);
        return -1;
    }

    iResult = 0;

    while (iResult <= 0) {
        iResult = recv(*ClientSocketAuth, message, contentLength, 0);
    }

    if (strstr(message, "get-key")) {

        FILE *fptr;
        long length;
//        RSA * keypair;

        fptr = fopen("C:\\Users\\Aviv\\public_server.pem","rb");
        if (fptr)
        {
            fseek (fptr, 0, SEEK_END);
            length = ftell (fptr);
            char buffer[length];
            rewind(fptr);
            if (buffer)
            {
                fread (buffer, 1, length, fptr);
            }
            fclose (fptr);
            send(*ClientSocketAuth, buffer, 256, 0);
//            closesocket(*ClientSocketAuth);
//            closesocket(*ListenSocket);
//            return 0;
        }

    } else {
        netContentLength = htonl(2);
        send(*ClientSocketAuth, &netContentLength, 4, 0);
        send(*ClientSocketAuth, "ok", 2, 0);
    }

    // RECEIVE KEY
    char publicKeyClient[KEY_LEN];

    recv(*ClientSocketAuth, publicKeyClient, KEY_LEN, 0);

    // cache key
    FILE *fptr;
    fptr = fopen("C:\\Users\\Aviv\\clientkey_server.pem","wb");
    if(fptr!=NULL){
        fwrite(publicKeyClient, 1, KEY_LEN, fptr);
        fclose(fptr);
        closesocket(*ListenSocket);
        closesocket(*ClientSocketAuth);
        return 0;
    } else {
        perror("file error");
    }
    int length;

}

int sessionAuth(char * token) {

}


// TODO: login

// TODO: encrypt.

// TODO: handle all kinds of http requests

int thread(SOCKET *ClientSocket, SOCKET *HttpSocket, SOCKET *ListenSocket, struct addrinfo hints, struct addrinfo * http_result) {

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
            goto listen;
        }

        int bytes_left = contentLength;
        int bytesRecv = 0;

        if (iResult > 0) {
            while (!received) {
                char recvbuf[DEFAULT_BUFLEN];

                // Initializing recvbuf to get rid of garbage mem.
                memset(recvbuf, 0, DEFAULT_BUFLEN);

                // If the length of the content in the current iteration
                // is smaller than the buffer size, the current "chunk" is the last.
                // Add handle connection exceptions
                if (bytes_left < DEFAULT_BUFLEN) {
                    iResult = recv(*ClientSocket, recvbuf, contentLength, 0);
                    memcpy(message + bytesRecv, recvbuf, iResult);
                    bytesRecv += iResult;

                    if (strcmp(recvbuf, "exit") == 0) {
                        printf("Closing connection... \n");
                        closesocket(*ClientSocket);
                        goto listen;
                    }

                    received = true;
                } else {
                    iResult = recv(*ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
                    // Add the current "chunk" to the full message.
                    memcpy(message + bytesRecv, recvbuf, iResult);

                    bytes_left -= DEFAULT_BUFLEN;
                    printf("ContentLength: %d \n", contentLength);

                }
                bytesRecv += iResult;

            }
            printf("%s", message);


            char messagecpy[bytesRecv];
            memcpy(messagecpy, message, strlen(message));
            char * hostaddress = getHostAddress(messagecpy);
            char hostaddresscopy[strlen(hostaddress)];
            char hostaddresscpy[strlen(hostaddress)];
            strcpy(hostaddresscpy, hostaddress);
            strcpy(hostaddresscopy, hostaddress);

            char * hostname = getHostName(hostaddresscpy);
            char * port = getPort(hostaddress);
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
                goto listen;
            }

            iResult = send(*HttpSocket,  message, contentLength + 1, 0);
            if (iResult == SOCKET_ERROR) {
                printf("Failed to send message to remote server. \n");
                return -1;
            } else {
                printf("Bytes sent to remote webserver: %d \n", iResult);
            }

            // RECEIVING RESPONSES FROM REMOTE WEBSERVER

            //allocate base size/length

            char *response = (char *) malloc(DEFAULT_BUFLEN);

            int cnt = 0;

            char buffer[DEFAULT_BUFLEN];
            memset(buffer, 0, DEFAULT_BUFLEN);

            memset(buffer, 0, DEFAULT_BUFLEN);
            memset(response, 0, DEFAULT_BUFLEN);

            iResult = DEFAULT_BUFLEN;

            // wait for the end of http headers

            // TODO: add time out (maybe retry after 5 seconds?)
            bytesRecv = 0;

            while (!strstr(buffer, "\r\n\r\n")) {
                memset(buffer, 0, DEFAULT_BUFLEN);

                iResult = recv(*HttpSocket, buffer, DEFAULT_BUFLEN, 0);
                response = (char *) realloc(response, bytesRecv + iResult);
                memset(response + bytesRecv, 0, iResult);

                //TODO: fix bytesrecv
                memcpy(response + bytesRecv, buffer, iResult);
                printf("Bytes received from Webserver: %d \n", iResult);
                if (iResult == 0) {
                    goto listen;
                }
                printf("Msg: %s \n", buffer);
                bytesRecv += iResult;
                if (iResult == SOCKET_ERROR)
                    return -1;
            }

            // get header length:
            char * terminators = strstr(response, "\r\n\r\n");
            int headers_len = (int)(terminators - response);

            char respcpy[bytesRecv];
            memcpy(respcpy, response, bytesRecv);
            int res = getlengthtype(response, bytesRecv);
            printf("res: %d", res);
            int len = 0;
            int total;

            // If the content-length header is there
            if (res == 0) {
                len = getContentLength(respcpy);
                total = headers_len + len + 4;
                bytes_left = total - bytesRecv;

                // TODO: change to default buflen
                while (total > bytesRecv) {
                    memset(buffer, 0, DEFAULT_BUFLEN);


                    if (bytes_left < DEFAULT_BUFLEN) {
                        iResult = recv(*HttpSocket, buffer, bytes_left, 0);
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, bytes_left);
                        memcpy(response + bytesRecv, buffer, bytes_left);
                        printf("Bytes received from Webserver: %d \n", iResult);
                    } else {
                        iResult = recv(*HttpSocket, buffer, DEFAULT_BUFLEN, 0);
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, iResult);
                        memcpy(response + bytesRecv, buffer, iResult);
                        printf("Bytes received from Webserver: %d \n", iResult);
                    }

                    if (iResult == 0) {
                        goto listen;
                    }
                    printf("Msg: %s \n", buffer);
                    bytesRecv += iResult;
                    bytes_left = total - bytesRecv;
                }
            } else { // no body
                total = headers_len + 4;
            }

            //TODO: handle chunked

            // total message length

            printf("Total: %d \n", total);

            printf("Full message: %s \n", response);
            FILE *fptr;
            fptr = fopen("C:\\Users\\Aviv\\program.gz","wb");
            fwrite(respcpy, 1, total, fptr);
            fclose(fptr);


            // Echo back the message in 512 byte chunks.
            received = false;
            int startIndex = 0;
            int endIndex = DEFAULT_BUFLEN;

            contentLength = total;
            int originalContentLength = contentLength;

            netContentLength = htonl(contentLength);
            send(*ClientSocket, &netContentLength, 4, 0);

            bytes_left = contentLength;

            //it's send actually.
            // TODO: account for null pointers. (sorry saji you were right)
            while (1) {
                if (bytes_left < DEFAULT_BUFLEN) {
                    endIndex = originalContentLength;
                }
                char curMessage[endIndex - startIndex];
                memset(curMessage, 0, DEFAULT_BUFLEN);
                // Allocating space for an array with a certain number of elements.
                // Copy the current chunk to curMessage
                memcpy(curMessage, &response[startIndex], endIndex - startIndex);
                // Move to the next chunk


                // Echo the buffer back to the sender
                // When there's still more than 512 bytes left,
                // subtract the maximum buflen to account for the number of bytes left and send to client.
                if (bytes_left > DEFAULT_BUFLEN) {
                    iResult = send(*ClientSocket, curMessage, DEFAULT_BUFLEN, 0);
                    startIndex = endIndex;
                    endIndex = endIndex + DEFAULT_BUFLEN;
                    bytes_left -= DEFAULT_BUFLEN;
                }
                    // Getting to a number smaller or equal to the maximum buflen,
                    // means we have reached the end of the message.
                else if (bytes_left <= DEFAULT_BUFLEN) {
                    iResult = send(*ClientSocket, curMessage, bytes_left, 0);
                    bytes_left -= iResult;
                    closesocket(*HttpSocket);
                    closesocket(*ClientSocket);
                    memset(response, 0, contentLength);
                    goto listen;
                }

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
    SOCKET ListenSocketAuth = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    SOCKET ClientSocketAuth = INVALID_SOCKET;
    SOCKET HttpSocket = INVALID_SOCKET;

    // Initialize Winsock. (Here iResult is the exit code for WSAStartup)
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Specifying information - protocol etc.
    struct addrinfo *result = NULL, hints, *http_result = NULL;

    // Settings for the socket - ipv4,
    ZeroMemory(&hints, sizeof (hints)); // Fills a block of memory with zeroes.
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;


    setUpListenSocket(iResult, hints, result, &ListenSocketAuth);
    OPENSSL_INIT_new();

    genKey();
    //Keys exchange: accept a new connection and send key
    // Listen for connections
    keysExchange(&ListenSocketAuth, &ClientSocketAuth, hints);

    ListenSocket = INVALID_SOCKET;
    ClientSocket = INVALID_SOCKET;

    setUpListenSocket(iResult, hints, result, &ListenSocket);

    //main thread, handles client requests and http.
    thread(&ClientSocket, &HttpSocket, &ListenSocket, hints, http_result);

 }