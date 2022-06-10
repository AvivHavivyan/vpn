#include <winsock2.h>
#include <stdbool.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <unistd.h>
//#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "utils.h"


#define DEFAULT_PORT "27015"
#define HTTP_PORT "443"
#define DEFAULT_BUFLEN 214
#define KEY_LEN 256
#define PEM_FILE_LEN 451
#define SESSION_ID_LEN 64
#define PRIVATE_KEY_PATH "private_server.pem"
#define PUBLIC_KEY_PATH "public_server.pem"
#define CLIENT_KEY_PATH "clientkey_server.pem"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")



//TODO: add comments
// Weird config stuff, only add if the compiler does not recognize the functions.

void WSAAPI freeaddrinfo( struct addrinfo* );

int WSAAPI getaddrinfo( const char*, const char*, const struct addrinfo*,
                        struct addrinfo** );

int WSAAPI getnameinfo( const struct sockaddr*, socklen_t, char*, DWORD,
                        char*, DWORD, int );

// takes the request and extracts the URL.
char * getURL(char * request) {
    char delimiter[] = " ";
    strtok(request, delimiter); // splits the string at the first space
    char * address = strtok(NULL, delimiter); // gets the pointer to the next char * token which is the URL
    return address;
}

char * lowerString(char * str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = (char)tolower((int)str[i]);
    }
    return str;
}

// gets a URL and extracts the host address
char * getHttpHostAddress(char * url) {
    char delimiter[] = "/"; // removes the http:// part of the URL
    strtok(url, delimiter); // split the string after the first /
    char * address = strtok(NULL, delimiter); // get the next token which is the address
    char addrcpy[strlen(address)];
    strcpy(addrcpy, address);
    address = strtok(address, ":"); // remove the
    if (strlen(addrcpy) == 0) return address;
    return address;
}


// extracts the host name from an address
char * getHostName(char * address) {
    char * name;
    char addrcpy[strlen(address)];
    strncpy(addrcpy, address, strlen(address));
    if (strstr("http", address)) { // if http then remove the port after
        char delimiter[] = ":";
        strtok(address, delimiter);
        name = (NULL, delimiter);
    } else {
        char delimiter[] = ":";
        name = strtok(address, delimiter);
    }
    return name;
}


// extracts the host from the address
char * getPort(char * address) {
    char delimiter[] = ":"; // the port appears after the :
    char * token = strtok(address, delimiter);
    char * port = strtok(NULL, delimiter);
    if (token == NULL) return NULL;
    return port;
}


int getLengthType(char * response, int len) {
    //check for transfer-encoding: chunked.
    char lower[len];
    memset(lower, 0, len);
    memcpy(lower, response, len);
    lowerString(lower);
    if (strstr(lower, "transfer-encoding: chunked")) {
        return 1;
    }
    if (strstr(lower, "content-length")) {
        return 0;
    }
    return -1;
}


int checkMethodType(char * request) {
    char * ret;
    ret = strstr(request, "CONNECT");
    if (ret) return 1;
    else return 0;
}


// gets the length of a response
int getContentLength(char * response) {
    char * header = "content-length";
    char rspcpy[strlen(response)];
    strcpy(rspcpy, response);
    lowerString(rspcpy); // make it all lowercase for ease of search
    char * substr = strstr(rspcpy, header); // search for the content-length header
    char * delim = "\n";
    char * header_line = strtok(substr, delim);
    delim = ":";
    strtok(header_line, delim); // get the number as a string

    char * len_str = strtok(NULL, delim);
    printf("lenstr: %s", len_str);

    return atoi(len_str); // convert to int
}

int setUpListenSocket(struct addrinfo hints, struct addrinfo * result, SOCKET *ListenSocket) {
    // Resolve the local address and port to be used by the server
    int iResult;
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

    return 0;
}


char * retrieveKey(int flag) {

    FILE * fptr;
    int length;

    if (flag == 0) { // public key
        fptr = fopen(PUBLIC_KEY_PATH,"rb");
        if (fptr)
        {
            fseek (fptr, 0, SEEK_END);
            length = ftell (fptr);
            char buffer[length];
            char * publicKey = malloc(PEM_FILE_LEN);
            rewind(fptr);
            if (buffer)
            {
                fread (buffer, 1, length, fptr);
                memcpy(publicKey, buffer, PEM_FILE_LEN);
            }
            fclose (fptr);
            return publicKey;
        }
    } else if (flag == 1) {
        // private key
        RSA * keyPair;

        length = 0;

        fptr = fopen(PRIVATE_KEY_PATH,"rb");
        RSA * privateKey = RSA_new();
        privateKey = PEM_read_RSAPrivateKey(fptr, &privateKey, NULL, NULL);
        if (privateKey == NULL) {
            return NULL;
        }
        RSA_size(privateKey);
        fclose(fptr);

        return (char *) privateKey;
    }

    return NULL;
}



int genKey() {
    // check for existing key
    FILE *fptr;
    fptr = fopen(PRIVATE_KEY_PATH, "rb");

    RSA * keyPair = RSA_new();
    keyPair = malloc(KEY_LEN);
    if (retrieveKey(1) != NULL) {
        memcpy(keyPair,  retrieveKey(1), KEY_LEN);

        if (RSA_check_key(keyPair)) { // if there's already a key
            fclose(fptr);
            return 0;
        }
    }


    fclose(fptr);
    RSA * key;
    struct bignum_st * bn;
    int err;
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

    RSA * public = RSAPublicKey_dup(key);

    const unsigned char test[4] = "Test";
    u_char encrypted[RSA_size(key)];
    RSA_public_encrypt(4, test, encrypted, public, RSA_PKCS1_OAEP_PADDING);
    u_char decrypted[4];
    RSA_private_decrypt(KEY_LEN, encrypted, decrypted, key, RSA_PKCS1_OAEP_PADDING);

    fptr = fopen(PRIVATE_KEY_PATH,"wb");

    if (!PEM_write_RSAPrivateKey(fptr, key, NULL, NULL,0, 0, NULL)) {
        printf("an error occured...");
    }
    fclose(fptr);

    fptr = fopen(PUBLIC_KEY_PATH,"wb");
    if (!PEM_write_RSA_PUBKEY(fptr, key)) {
        printf("an error occured...");
    }

    fclose(fptr);

    return 0;
}

RSA * keysExchange(SOCKET *ClientSocketAuth, char * sessionID) {
    int iResult = 0;
    int bytesRecv = 0;

    FILE *fptr;
    long length;

    // send key
    char * publicKey = retrieveKey(0);
    send(*ClientSocketAuth, publicKey, PEM_FILE_LEN, 0);


    // RECEIVE KEY
    char publicKeyClient[PEM_FILE_LEN];

    recv(*ClientSocketAuth, publicKeyClient, PEM_FILE_LEN, MSG_WAITALL);


    // cache key

    char * filename = malloc(SESSION_ID_LEN + 6);
    char * extension = ".time\0";

    memcpy(filename, sessionID, SESSION_ID_LEN);
    memcpy(filename + SESSION_ID_LEN, extension, 6);

    // cache the time generated

    time_t currentTime = time(NULL);
    fptr = fopen(filename, "wb");
    fwrite(time, 1, sizeof(time), fptr);
    fclose(fptr);

    // cache the ID

    char * filenameTxt = malloc(SESSION_ID_LEN + 5);
    char * extensionTxt = ".txt\0";

    memcpy(filenameTxt, sessionID, SESSION_ID_LEN);
    memcpy(filenameTxt + SESSION_ID_LEN, extensionTxt, 5);

    fptr = fopen(filenameTxt,"wb");

    if(fptr!=NULL){
        fwrite(publicKeyClient, 1, PEM_FILE_LEN, fptr);
        fclose(fptr);
    } else {
        perror("file error");
    }
    FILE * fptr2;

    fptr2 = fopen(filenameTxt,"rb");

    RSA * clientKey = RSA_new();
    EVP_PKEY * evp = EVP_PKEY_new();
    evp = PEM_read_PUBKEY(fptr2, &evp, NULL, NULL);
    clientKey = EVP_PKEY_get0_RSA(evp);
    fclose(fptr2);

    u_char * encryptedSessionID = malloc(KEY_LEN);
    u_char * sessionIDUnsigned = malloc(SESSION_ID_LEN);
    memcpy(sessionIDUnsigned, sessionID, SESSION_ID_LEN);
    RSA_public_encrypt(SESSION_ID_LEN, sessionIDUnsigned, encryptedSessionID, clientKey, RSA_PKCS1_OAEP_PADDING);

    send(*ClientSocketAuth, encryptedSessionID, KEY_LEN, 0);

    return clientKey;
}


char * generateSessionID() {
    int i;
    unsigned char sessionIDbytes[32];
    char * sessionIDstr = malloc(32 * 2 + 1);
    RAND_bytes(sessionIDbytes, 32);
    for (i = 0; i < 32; i++)
        sprintf(sessionIDstr + 2*i, "%02X", sessionIDbytes[i]);
    char * sessionID = malloc(SESSION_ID_LEN);
    memcpy(sessionID, sessionIDstr, SESSION_ID_LEN);
    return sessionID;
}

RSA * retrieveClientKey(char * sessionID) {
    FILE * fptr;
    char * filename = malloc(SESSION_ID_LEN + 5);
    char * extension = ".txt";
    memcpy(filename, sessionID, SESSION_ID_LEN);
    memcpy(filename + SESSION_ID_LEN, extension, 5);
    fptr = fopen(filename,"rb");
    RSA * clientKey = RSA_new();
    EVP_PKEY * evp = EVP_PKEY_new();
    evp = PEM_read_PUBKEY(fptr, &evp, NULL, NULL);
    clientKey = EVP_PKEY_get0_RSA(evp);
    fclose (fptr);
    return clientKey;
}


// TODO: check time
int validateID(char * sessionID) {
    FILE * fptr;
    char * filename = malloc(SESSION_ID_LEN + 6);
    char * extension = ".time";
    int length = 0;
    time_t timestampSeconds = 0;
    memcpy(filename, sessionID, SESSION_ID_LEN);
    memcpy(filename + SESSION_ID_LEN, extension, 6);
    fptr = fopen(filename,"rb");

    if (fptr) {
        fseek(fptr, 0, SEEK_END);
        length = ftell(fptr);
        char buffer[length];
        rewind(fptr);
        if (buffer) {
            fread(buffer, 1, length, fptr);
            timestampSeconds = (long long)buffer;
        }
        fclose(fptr);
    }

    time_t currentTime = time(NULL);
    if (timestampSeconds == 0) {
        return 1;
    }
    if (currentTime > timestampSeconds + 3600) {
        return 1;
    } else {
        return 0;
    }
    return 0;
}


//retrieves the user's public key
char * auth(SOCKET * ClientSocketAuth) {
    printf("authenticating... \n");
    genKey();
    int iResult = 0;

    char sessionBuff[SESSION_ID_LEN];

    iResult = recv(*ClientSocketAuth, sessionBuff, SESSION_ID_LEN, MSG_WAITALL);

    if (sessionBuff[0] == 0) {
        char * sessionID = generateSessionID();
        int strln = 13;
        u_long netContentLength = 0;
        netContentLength = htonl(13);
        send(*ClientSocketAuth, &netContentLength, 4, 0);

        send(*ClientSocketAuth, "key-exchange", 13, 0);
        printf("invalid session ID. exchanging keys... \n");
        RSA * clientKey = keysExchange(ClientSocketAuth, sessionID);
        return sessionID;
    } else { // already have a sessionID, validate, retrieve public key and return it
        printf("validating session ID... \n");
        printf("session ID: %s \n", sessionBuff);
        int valid = validateID(sessionBuff);
        printf("finished \n");

        if (valid == 0) {
            printf("valid session ID \n");
            u_long netContentLength = 0;
            netContentLength = htonl(3);
            send(*ClientSocketAuth, &netContentLength, 4, 0);
            char * response = "ok";

            send(*ClientSocketAuth, response, 3, 0);
            char * sessionID = malloc(SESSION_ID_LEN);
            memcpy(sessionID, sessionBuff, SESSION_ID_LEN);
//            printf("session buff: %s", sessionBuff);

//            printf("session ID: %s", sessionID);
            return sessionID;
        } else {
            char * sessionID = generateSessionID();
            int strln = 13;
            u_long netContentLength = 0;
            netContentLength = htonl(13);
            send(*ClientSocketAuth, &netContentLength, 4, 0);

            send(*ClientSocketAuth, "key-exchange\0", 13, 0);
            printf("invalid session ID. exchanging keys... \n");
            RSA * clientKey = keysExchange(ClientSocketAuth, sessionID);
            printf("the end of auth \n");

            return sessionID;
        }

    }

}


// TODO: handle all kinds of http requests

int server() {

    int iResult = 0;

    if (1 < 0) {

    }
    // Listen for connections
    SOCKET ListenSocketAuth = INVALID_SOCKET;
    struct addrinfo *result = NULL, hints, *http_result = NULL;

    // Settings for the socket - ipv4,
    ZeroMemory(&hints, sizeof (hints)); // Fills a block of memory with zeroes.
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    setUpListenSocket( hints, result, &ListenSocketAuth);
    SOCKET ClientSocket = INVALID_SOCKET;

    listen:


    printf("Listening... ");
    if (listen(ListenSocketAuth, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocketAuth);
        WSACleanup();
        return -1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocketAuth, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        closesocket(ListenSocketAuth);
        WSACleanup();
        return -1;
    } else {
        printf("Connected for authentication. \n");
    }

    printf("before auth \n");

    char * sessionID = auth(&ClientSocket);
    printf("after auth \n");

    RSA * pubkey = retrieveClientKey(sessionID);
    RSA * keyPair = (RSA *)retrieveKey(1);

    while (true) {
        bool received = false;
//        printf("Waiting... \n");

        int contentLength;
        u_char bytes[KEY_LEN];
        u_char buffer[KEY_LEN];
        u_char * decryptedBytes = malloc(4);
        memset(bytes, 0, KEY_LEN);
        iResult = 0;
        int bytesRecv = 0;

        u_long netcheckLen;
        int checkLen;
        char check[4];


        iResult = recv(ClientSocket, buffer, KEY_LEN, MSG_WAITALL);

        RSA_private_decrypt(KEY_LEN,buffer, decryptedBytes, keyPair, RSA_PKCS1_OAEP_PADDING);

        memcpy(&contentLength, decryptedBytes, 4);

        char message[contentLength];
        memset(message, 0, strlen(message));
        printf("Content length: %d \n", contentLength);

        if (contentLength == 0) {
            printf("Connection terminated unexpectedly.");
            closesocket(ClientSocket);
            goto listen;
        }

        int bytesLeft = contentLength;
        bytesRecv = 0;
        u_char encryptedMessage[KEY_LEN];

        if (iResult > 0) {

            while (!received) {
                char recvbuf[KEY_LEN];

                // Initializing recvbuf to get rid of garbage mem.
                memset(recvbuf, 0, DEFAULT_BUFLEN);

                // If the length of the content in the current iteration
                // is smaller than the buffer size, the current "chunk" is the last.
                // Add handle connection exceptions
                if (bytesLeft < DEFAULT_BUFLEN) {
                    u_char decryptedMessage[bytesLeft];

                    int bytesRecvBuf = 0;
                    while (bytesRecvBuf < KEY_LEN) {
                        iResult = recv(ClientSocket, buffer, KEY_LEN, 0);
                        memcpy(recvbuf + bytesRecvBuf, buffer, iResult);
                        bytesRecvBuf += iResult;
                    }

                    memcpy(encryptedMessage, recvbuf, KEY_LEN);

                    RSA_private_decrypt(KEY_LEN,encryptedMessage, decryptedMessage, keyPair, RSA_PKCS1_OAEP_PADDING);

                    memcpy(message + bytesRecv, decryptedMessage, bytesLeft);
                    bytesRecv += iResult;

                    received = true;
                } else {
                    u_char decryptedMessage[DEFAULT_BUFLEN];

                    int bytesRecvBuf = 0;
                    while (bytesRecvBuf < KEY_LEN) {
                        iResult = recv(ClientSocket, buffer, KEY_LEN, 0);
                        memcpy(recvbuf + bytesRecvBuf, buffer, iResult);
                        bytesRecvBuf += iResult;
                    }

                     memcpy(encryptedMessage, recvbuf, KEY_LEN);

                    RSA_private_decrypt(KEY_LEN,encryptedMessage, decryptedMessage, keyPair, RSA_PKCS1_OAEP_PADDING);

                    // Add the current "chunk" to the full message.
                    memcpy(message + bytesRecv, decryptedMessage, DEFAULT_BUFLEN);

                    bytesLeft -= DEFAULT_BUFLEN;
                    printf("bytes left: %d \n", bytesLeft);

                }
                bytesRecv += DEFAULT_BUFLEN;

            }
            printf("%s", message);


            char messagecpy[bytesRecv];
            memcpy(messagecpy, message, strlen(message));
            char * hostaddress = getURL(messagecpy);
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
            SOCKET HttpSocket = INVALID_SOCKET;
            HttpSocket = socket(http_result->ai_family, http_result->ai_socktype, http_result->ai_protocol);
            struct sockaddr_in  *sockaddr_ipv4;
            sockaddr_ipv4 = (struct sockaddr_in *) http_result->ai_addr;
            printf("\tIPv4 address %s\n", inet_ntoa(sockaddr_ipv4->sin_addr));
            iResult = connect(HttpSocket, http_result->ai_addr, http_result->ai_addrlen);

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
                memcpy(bytes, &contentLength, 4);
                send(ClientSocket, bytes, 4, 0);
                send(ClientSocket, connect, strlen(connect), 0);
                closesocket(ClientSocket);
                goto listen;
            }

            iResult = send(HttpSocket,  message, contentLength + 1, 0);
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

                // Peek before receiving, to see the end of the headers.
                iResult = recv(HttpSocket, buffer, DEFAULT_BUFLEN, MSG_PEEK);
                if (strstr(buffer, "\r\n\r\n")) {
                    // check the length until the CRLFCRLF sequence
                    char * bufferPointer = buffer;
                    char * end = strstr(buffer, "\r\n\r\n");
                    int lastChunkLen = end - bufferPointer + 4;
                    memset(buffer, 0, DEFAULT_BUFLEN);
                    iResult = recv(HttpSocket, buffer, lastChunkLen, 0);
                } else {
                    iResult = recv(HttpSocket, buffer, DEFAULT_BUFLEN, 0);
                }

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

            int headers_len = bytesRecv - 4;

            int lastBytesReceived = bytesRecv - headers_len - 4;

            char respcpy[bytesRecv];
            memcpy(respcpy, response, bytesRecv);
            int res = getLengthType(response, bytesRecv);
            printf("res: %d", res);
            int len = 0;
            int total;

            // If the content-length header is there
            if (res == 0) {
                len = getContentLength(respcpy);
                total = headers_len + len + 4;
                bytesLeft = total - bytesRecv;

                while (total > bytesRecv) {
                    memset(buffer, 0, DEFAULT_BUFLEN);

                    if (bytesLeft < DEFAULT_BUFLEN) {
                        iResult = recv(HttpSocket, buffer, bytesLeft, 0);
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, bytesLeft);
                        memcpy(response + bytesRecv, buffer, bytesLeft);
                    } else {
                        iResult = recv(HttpSocket, buffer, DEFAULT_BUFLEN, 0);
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, iResult);
                        memcpy(response + bytesRecv, buffer, iResult);
                    }

                    if (iResult == 0) {
                        goto listen;
                    }
                    bytesRecv += iResult;
                    bytesLeft = total - bytesRecv;
                }
            } else if (res == 1) {
                // read the first chunk len: read one byte each time.
                // until the length is 0.
                int chunkLen = -1;
                while (chunkLen != 0) {
                    char * lenChar = malloc(1);
                    char lenBuff[1];
                    int bytesRecvLen = 0; //reset number of bytes received.
                    //get chunk length
                    while (!strstr(lenChar, "\r\n")) {
                        iResult = 0;
                        while (iResult == 0) { //until a byte is received.
                            iResult = recv(HttpSocket, lenBuff, 1, 0);
                        }

                        //copy to response and to lenChar
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, iResult);
                        memcpy(response + bytesRecv, lenBuff, iResult);
                        lenChar = (char *) realloc(lenChar, bytesRecvLen + iResult);
                        memset(lenChar + bytesRecvLen, 0, iResult);
                        memcpy(lenChar + bytesRecvLen, lenBuff, iResult);

                        // increment values
                        bytesRecv += 1;
                        bytesRecvLen += 1;
                    }
                    char * endNum = strstr(lenChar, "\r\n");
                    chunkLen = strtol(lenChar, &endNum - 1, 16);
                    // get chunk:
                    char chunkBuf[chunkLen + 2];
                    char chunk[chunkLen + 2];
                    int bytesRecvChunk = 0;
                    while (bytesRecvChunk < chunkLen) {
                        iResult = recv(HttpSocket, chunkBuf, chunkLen + 2, 0);

                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, iResult);
                        memcpy(response + bytesRecv, chunkBuf, iResult);

                        memset(chunk + bytesRecvChunk, 0, iResult);
                        memcpy(chunk + bytesRecvChunk,  chunkBuf, iResult);
                        bytesRecvChunk += iResult;
                        bytesRecv += iResult;
                    }
                }

                total = bytesRecv;
            } else { // no body
                total = headers_len + 4;
            }

            //TODO: handle chunked

            // total message length

            printf("Total: %d \n", total);
            char responseOnly[total];
            memcpy(responseOnly, response, total);

            printf("Full message: %s \n", responseOnly);


            // Echo back the message in 215 byte chunks.
            received = false;
            int startIndex = 0;
            int endIndex = DEFAULT_BUFLEN;
            u_char bytesInt[4];
            u_char encryptedBytes[RSA_size(pubkey)];

            contentLength = total;

            memcpy(bytesInt, &contentLength, 4);
            RSA_public_encrypt(4, bytesInt, encryptedBytes, pubkey, RSA_PKCS1_OAEP_PADDING);

            send(ClientSocket, encryptedBytes, KEY_LEN, 0);

            bytesLeft = contentLength;

            while (1) {
                if (bytesLeft < DEFAULT_BUFLEN) {
                    endIndex = contentLength;
                }
                char curMessage[endIndex - startIndex];
                memset(curMessage, 0, DEFAULT_BUFLEN);
                // Allocating space for an array with a certain number of elements.
                // Copy the current chunk to curMessage
                memcpy(curMessage, &response[startIndex], endIndex - startIndex);
                // Move to the next chunk


                // Echo the buffer back to the sender
                // When there's still more than 214 bytes left,
                // subtract the maximum buflen to account for the number of bytes left and send to client.
                if (bytesLeft > DEFAULT_BUFLEN) {
                    u_char messageBytes[DEFAULT_BUFLEN];
                    memset(encryptedMessage, 0, RSA_size(pubkey));
                    memcpy(messageBytes, curMessage, DEFAULT_BUFLEN);

                    RSA_public_encrypt(DEFAULT_BUFLEN, messageBytes, encryptedMessage, pubkey, RSA_PKCS1_OAEP_PADDING);

                    iResult = send(ClientSocket, encryptedMessage, KEY_LEN, 0);
                    startIndex = endIndex;
                    endIndex = endIndex + DEFAULT_BUFLEN;
                }
                    // Getting to a number smaller or equal to the maximum buflen,
                    // means we have reached the end of the message.
                else if (bytesLeft <= DEFAULT_BUFLEN) {
                    u_char messageBytes[bytesLeft];
                    memcpy(messageBytes, curMessage, bytesLeft);

                    RSA_public_encrypt(bytesLeft, messageBytes, encryptedMessage, pubkey, RSA_PKCS1_OAEP_PADDING);

                    iResult = send(ClientSocket, encryptedMessage, KEY_LEN, 0);
                    bytesLeft -= iResult;
                    closesocket(HttpSocket);
                    closesocket(ClientSocket);
                    memset(response, 0, contentLength);
                    goto listen;
                }

                bytesLeft -= DEFAULT_BUFLEN;

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

//TODO: handle exceptions when the client unexpectedly disconnects.

int main() {

    WSADATA wsaData; // Contains info about the winsock implementation.
    int iResult; // Number of bytes received.

    // Sockets - server and client.
    SOCKET ListenSocket = INVALID_SOCKET;
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


    OPENSSL_INIT_new();

    ListenSocket = INVALID_SOCKET;
    ClientSocket = INVALID_SOCKET;

    //main server, handles client requests and http.
    server();

 }