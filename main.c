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

//check for transfer-encoding: chunked header in a response/response headers
int getLengthType(char * response, int len) {
    char lower[len];
    memset(lower, 0, len);
    memcpy(lower, response, len);
    lowerString(lower); // lowercase the string for ease of use.
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

    char * strLen = strtok(NULL, delim);
    printf("lenstr: %s", strLen);
    // convert to int
    return strtol(strLen, NULL, 10);
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

// Retrieve keys according to 2 flags:
// 0 - server public RSA key
// 1 - server private RSA key
char * retrieveKey(int flag) {

    FILE * fptr;
    int length;

    if (flag == 0) { // get public key from file
        fptr = fopen(PUBLIC_KEY_PATH,"rb");
        if (fptr)
        {
            fseek (fptr, 0, SEEK_END);
            length = ftell (fptr);
            char buffer[length];
            char * publicKey = malloc(PEM_FILE_LEN);
            rewind(fptr);
            fread (buffer, 1, length, fptr);
            memcpy(publicKey, buffer, PEM_FILE_LEN);
            fclose (fptr);
            return publicKey;
        }
    } else if (flag == 1) {
        // get private key from file
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

    RSA * keyPair;
    keyPair = malloc(KEY_LEN);
    if (retrieveKey(1) != NULL) {
        memcpy(keyPair,  retrieveKey(1), KEY_LEN);

        if (RSA_check_key(keyPair)) { // if there's already a key exit
            fclose(fptr);
            return 0;
        }
    }

    // if no key is found, generate one

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

// exchange keys with client and then send session ID to client
RSA * keysExchange(const SOCKET *ClientSocketAuth, char * sessionID) {

    FILE *fptr;

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
    char time[256];
    memset(time, 0, 256);
    sprintf(time, "%lld", currentTime);

    fwrite(time, 1, 256, fptr);
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

    // cache client public key
    RSA * clientKey;
    EVP_PKEY * evp = EVP_PKEY_new();
    evp = PEM_read_PUBKEY(fptr2, &evp, NULL, NULL);
    clientKey = EVP_PKEY_get0_RSA(evp);
    fclose(fptr2);

    // send session ID
    u_char * encryptedSessionID = malloc(KEY_LEN);
    u_char * sessionIDUnsigned = malloc(SESSION_ID_LEN);
    memcpy(sessionIDUnsigned, sessionID, SESSION_ID_LEN);
    RSA_public_encrypt(SESSION_ID_LEN, sessionIDUnsigned, encryptedSessionID, clientKey, RSA_PKCS1_OAEP_PADDING);

    send(*ClientSocketAuth, (char *)encryptedSessionID, KEY_LEN, 0);

    return clientKey;
}

// generate a cryptographically random, safe session ID
char * generateSessionID() {
    int i;
    unsigned char sessionIDbytes[32]; // length - 32 bytes
    char * sessionIDstr = malloc(32 * 2 + 1); // the HEX string
    RAND_bytes(sessionIDbytes, 32);
    // convert to HEX format
    for (i = 0; i < 32; i++)
        sprintf(sessionIDstr + 2*i, "%02X", sessionIDbytes[i]);
    char * sessionID = malloc(SESSION_ID_LEN);
    memcpy(sessionID, sessionIDstr, SESSION_ID_LEN);
    return sessionID;
}

// retrieves a client's public RSA key that corresponds to their ID
RSA * retrieveClientKey(char * sessionID) {
    // open the key file with the corresponding session ID name
    FILE * fptr;
    char * filename = malloc(SESSION_ID_LEN + 5);
    char * extension = ".txt";
    memcpy(filename, sessionID, SESSION_ID_LEN);
    memcpy(filename + SESSION_ID_LEN, extension, 5);
    fptr = fopen(filename,"rb");
    RSA * clientKey;
    EVP_PKEY * evp = EVP_PKEY_new();
    evp = PEM_read_PUBKEY(fptr, &evp, NULL, NULL);
    clientKey = EVP_PKEY_get0_RSA(evp);
    fclose (fptr);
    return clientKey;
}


// TODO: check time
// checks and validates a session ID - session IDs expire after an hour.
// if valid, return 0. else, return 1
int validateID(char * sessionID) {
    FILE * fptr;
    char * filename = malloc(SESSION_ID_LEN + 6);
    char * extension = ".time";
    int length;
    time_t timestampSeconds;
    memcpy(filename, sessionID, SESSION_ID_LEN);
    memcpy(filename + SESSION_ID_LEN, extension, 6);
    fptr = fopen(filename,"rb");

    // open the corresponding session time file
    if (fptr) {
        fseek(fptr, 0, SEEK_END);
        length = ftell(fptr);
        char buffer[length];
        rewind(fptr);
        fread(buffer, 1, length, fptr);
        timestampSeconds = strtoll(buffer, NULL, 10);
        fclose(fptr);
        time_t currentTime = time(NULL);
        if (timestampSeconds == 0) { // if no timestamp found return 1
            return 1;
        }
        if (currentTime > timestampSeconds + 3600) {
            // if an hour has passed since the generation of the session ID - it expired, returns 1.
            return 1;
        } else { // if passed all the checks return 0
            return 0;
        }
    }

    return 1;

}


//authenticates a user requesting to connect - checks for session ID, validates it,
// then exchanges keys if necessary, sends a new session ID and returns it.
char * auth(SOCKET * ClientSocketAuth) {
    printf("authenticating... \n");
    genKey();
    int iResult;

    char sessionBuff[SESSION_ID_LEN];

    iResult = recv(*ClientSocketAuth, sessionBuff, SESSION_ID_LEN, MSG_WAITALL);

    if (iResult <= 0) {
        return NULL;
    }

    // if null array, the client needs a new session ID and keys.
    if (sessionBuff[0] == 0) {
        char * sessionID = generateSessionID();
        u_long netContentLength = 0;
        netContentLength = htonl(13);
        // send length
        send(*ClientSocketAuth, (char *)&netContentLength, 4, 0);

        // send exchange message
        send(*ClientSocketAuth, "key-exchange", 13, 0);

        // exchange keys and return the new session ID
        printf("invalid session ID. exchanging keys... \n");
        keysExchange(ClientSocketAuth, sessionID);
        return sessionID;
    } else { // already have a sessionID, validate, retrieve public key and return it
        printf("validating session ID... \n");
        printf("session ID: %s \n", sessionBuff);
        int valid = validateID(sessionBuff);
        printf("finished \n");

        if (valid == 0) { // if the exit code is 0, the ID is valid.
            printf("valid session ID \n");
            u_long netContentLength = 0;
            netContentLength = htonl(3);

            // return an ok message to the client - first the length
            send(*ClientSocketAuth, (char *)&netContentLength, 4, 0);
            char * response = "ok";

            // send the "ok" string
            send(*ClientSocketAuth, response, 3, 0);
            char * sessionID = malloc(SESSION_ID_LEN);
            memcpy(sessionID, sessionBuff, SESSION_ID_LEN); // copy and return the session ID
            return sessionID;
        } else { // if invalid session ID, generate a new one and indicate that key exchange is necessary.
            char * sessionID = generateSessionID();
            u_long netContentLength = 0;
            netContentLength = htonl(13);

            // send key exchange message
            send(*ClientSocketAuth, (char *)&netContentLength, 4, 0);

            send(*ClientSocketAuth, "key-exchange\0", 13, 0);
            printf("invalid session ID. exchanging keys... \n");
            keysExchange(ClientSocketAuth, sessionID);

            return sessionID;
        }

    }

}


// TODO: handle all kinds of http requests
// main server function, handles the flow of the client program. calls various functions.
// executes authentication, interaction with client, accepts and decrypts requests, forwards
// requests to webserver and sends the webserver response encrypted to the client.
int server() {

    int iResult;

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


    // after each request is handled start the process again from this label
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

    // initiate authentication
    char * sessionID = auth(&ClientSocket);
    if (sessionID == NULL) {
        goto listen;
    }
    printf("after auth \n");

    // get server's private key and client's public key in order to decrypt/encrypt messages
    RSA * pubkey = retrieveClientKey(sessionID);
    RSA * keyPair = (RSA *)retrieveKey(1);

    while (true) {
        bool received = false;
        printf("Waiting... \n");

        // RECEIVING REQUEST FROM CLEINT //
        int contentLength;
        u_char bytes[KEY_LEN];
        u_char buffer[KEY_LEN];
        u_char * decryptedBytes = malloc(4);
        memset(bytes, 0, KEY_LEN);
        int bytesRecv;


        // get encrypted content length and decrypt
        iResult = recv(ClientSocket, (char *)buffer, KEY_LEN, MSG_WAITALL);

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

        // get the message contents
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
                        iResult = recv(ClientSocket, (char *)buffer, KEY_LEN, 0);
                        memcpy(recvbuf + bytesRecvBuf, buffer, iResult);
                        bytesRecvBuf += iResult;
                    }

                    memcpy(encryptedMessage, recvbuf, KEY_LEN);

                    RSA_private_decrypt(KEY_LEN,encryptedMessage, decryptedMessage, keyPair, RSA_PKCS1_OAEP_PADDING);

                    memcpy(message + bytesRecv, decryptedMessage, bytesLeft);
                    bytesRecv += iResult;

                    received = true;
                } else { // receive chunk from client, decrypt and append to message
                    u_char decryptedMessage[DEFAULT_BUFLEN];

                    int bytesRecvBuf = 0;
                    while (bytesRecvBuf < KEY_LEN) {
                        iResult = recv(ClientSocket, (char *)buffer, KEY_LEN, 0);
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

            // logging
            printf("%s", message);


            // get all different address "formats"
            char messagecpy[bytesRecv];
            memcpy(messagecpy, message, bytesRecv);
            char * hostaddress = getURL(messagecpy);
            char hostaddresscopy[strlen(hostaddress)];
            char hostaddresscpy[strlen(hostaddress)];
            strcpy(hostaddresscpy, hostaddress);
            strcpy(hostaddresscopy, hostaddress);

            char * hostname = getHostName(hostaddresscpy);
            char * port = getPort(hostaddress);
            hints.ai_flags = 0;

            // if the port is the HTTP port
            if (strcmp(port, "443") != 0) {
                port = "80";
                char * http_host_address = getHttpHostAddress(hostaddresscopy);
                printf("http host address: %s \n", http_host_address);
                iResult = getaddrinfo(http_host_address, port, &hints, &http_result);
                // if the getaddrinfo exited with a nonzero value, try the different address format
                if (iResult != 0) {
                    iResult = getaddrinfo(hostaddress, port, &hints, &http_result);
                    printf("http host address: %s \n", hostaddress);

                }
            } else { // else get hostname address info
                iResult = getaddrinfo(hostname, port, &hints, &http_result);
            }

            if (iResult != 0) {
                printf("Failed to retrieve address data. \n"); // TODO: notify client.
                goto listen;
            }

            // set values to connect to remote webserver and create a socket
            SOCKET HttpSocket = INVALID_SOCKET;
            HttpSocket = socket(http_result->ai_family, http_result->ai_socktype, http_result->ai_protocol);
            struct sockaddr_in  *sockaddr_ipv4;
            sockaddr_ipv4 = (struct sockaddr_in *) http_result->ai_addr;
            printf("\tIPv4 address %s\n", inet_ntoa(sockaddr_ipv4->sin_addr));

            // connect to remote webserver
            iResult = connect(HttpSocket, http_result->ai_addr, (int)http_result->ai_addrlen);

            if (iResult != 0) {
                printf("Failed to connect to remote server. \n");
                WSACleanup();
                return -1;
            } else {
                printf("Connected to remote server successfully on port %s. \n", port);
            }

//            if (checkMethodType(message) == 1) {
//                printf("CONNECT method. \n");
//                char * connect = "HTTP/1.1 200 Connection Established \r\n\r\n";
//                contentLength = strlen(connect);
//                memcpy(bytes, &contentLength, 4);
//                send(ClientSocket, bytes, 4, 0);
//                send(ClientSocket, connect, strlen(connect), 0);
//                closesocket(ClientSocket);
//                goto listen;
//            }

            iResult = send(HttpSocket,  message, contentLength + 1, 0);
            if (iResult == SOCKET_ERROR) {
                printf("Failed to send message to remote server. \n");
                return -1;
            } else {
                printf("Bytes sent to remote webserver: %d \n", iResult);
            }

            // RECEIVING RESPONSES FROM REMOTE WEBSERVER

            //allocate response base size/length
            char *response = (char *) malloc(DEFAULT_BUFLEN);

            char httpBuffer[DEFAULT_BUFLEN];

            // reset arrays
            memset(httpBuffer, 0, DEFAULT_BUFLEN);
            memset(response, 0, DEFAULT_BUFLEN);


            // wait for the end of http headers

            // TODO: add time out (maybe retry after 5 seconds?)
            bytesRecv = 0;

            while (!strstr(httpBuffer, "\r\n\r\n")) {
                memset(httpBuffer, 0, DEFAULT_BUFLEN);

                // Peek before receiving, to see the end of the headers.
                iResult = recv(HttpSocket, httpBuffer, DEFAULT_BUFLEN, MSG_PEEK);
                if (iResult == SOCKET_ERROR) // if a socket error occurs
                    goto listen;

                // get response headers
                if (strstr(httpBuffer, "\r\n\r\n")) { // if we have reached the
                    // CRLFCRLF sequence then we are at the end of the headers part.
                    // check the length until the CRLFCRLF sequence and receive that
                    // number of bytes from the webserver.
                    char * bufferPointer = httpBuffer;
                    char * end = strstr(httpBuffer, "\r\n\r\n");
                    int lastChunkLen = (int)(end - bufferPointer) + 4;
                    memset(httpBuffer, 0, DEFAULT_BUFLEN);
                    iResult = recv(HttpSocket, httpBuffer, lastChunkLen, 0);
                } else {
                    iResult = recv(HttpSocket, httpBuffer, DEFAULT_BUFLEN, 0);
                }

                response = (char *) realloc(response, bytesRecv + iResult);
                memset(response + bytesRecv, 0, iResult);

                memcpy(response + bytesRecv, httpBuffer, iResult);
                printf("Bytes received from Webserver: %d \n", iResult);
                if (iResult == 0) {
                    goto listen;
                }
                printf("Msg: %s \n", httpBuffer);
                bytesRecv += iResult;
                if (iResult == SOCKET_ERROR)
                    return -1;
            }

            // get headers part length:
            int headersLen = bytesRecv - 4;

            char respCpy[bytesRecv];
            memcpy(respCpy, response, bytesRecv);
            int res = getLengthType(response, bytesRecv);
            printf("res: %d", res);
            int len;
            int total;

            // If the content-length headersLen is there receive the entire body of the response
            if (res == 0) {
                // get the content length
                len = getContentLength(respCpy);
                total = headersLen + len + 4; // total length of the response
                bytesLeft = total - bytesRecv;

                // receive the body, make sure that all the bytes are there.
                while (total > bytesRecv) {
                    memset(httpBuffer, 0, DEFAULT_BUFLEN);

                    if (bytesLeft < DEFAULT_BUFLEN) {
                        iResult = recv(HttpSocket, httpBuffer, bytesLeft, 0);
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, bytesLeft);
                        memcpy(response + bytesRecv, httpBuffer, bytesLeft);
                    } else {
                        iResult = recv(HttpSocket, httpBuffer, DEFAULT_BUFLEN, 0);
                        response = (char *) realloc(response, bytesRecv + iResult);
                        memset(response + bytesRecv, 0, iResult);
                        memcpy(response + bytesRecv, httpBuffer, iResult);
                    }

                    if (iResult == 0) {
                        goto listen;
                    }
                    bytesRecv += iResult;
                    bytesLeft = total - bytesRecv;
                }
            } else if (res == 1) { // if the transfer-encoding: chunked headersLen is there
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
                    // adding two bytes to account for a CRLF sequence at the end of
                    // each chunk's length, and also at the end of each chunk
                    char chunkBuf[chunkLen + 2];

                    iResult = recv(HttpSocket, chunkBuf, chunkLen + 2, MSG_WAITALL);
                    response = (char *) realloc(response, bytesRecv + iResult);
                    memset(response + bytesRecv, 0, iResult);
                    memcpy(response + bytesRecv, chunkBuf, iResult);
                    bytesRecv += iResult;
                }

                total = bytesRecv; // the total length of the request is the number of bytes received.
            } else { // if there's no body to the response add the length of the CRLFCRLF sequence.
                total = headersLen + 4;
            }


            // total message length

            printf("Total: %d \n", total); // logging

            char responseOnly[total]; // copy only the relevant bytes - the actual response.
            memcpy(responseOnly, response, total);

            printf("Full message: %s \n", responseOnly); // logging

            // send back the message to the client in 214 byte chunks.
            received = false;
            int startIndex = 0;
            int endIndex = DEFAULT_BUFLEN;
            u_char bytesInt[4];
            u_char encryptedBytes[RSA_size(pubkey)];

            contentLength = total;

            // send the length of the response, encrypted, to the client first
            memcpy(bytesInt, &contentLength, 4);
            RSA_public_encrypt(4, bytesInt, encryptedBytes, pubkey, RSA_PKCS1_OAEP_PADDING);

            send(ClientSocket, (char *)encryptedBytes, KEY_LEN, 0);

            // to keep track of how many bytes are left to send
            bytesLeft = contentLength;

            while (1) {

                // if the final batch is reached, endIndex would be the content length.
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
                // subtract the maximum buflen to account for the number of bytes left,
                // encrypt and send to client.
                if (bytesLeft > DEFAULT_BUFLEN) {
                    u_char messageBytes[DEFAULT_BUFLEN];
                    memset(encryptedMessage, 0, RSA_size(pubkey));
                    memcpy(messageBytes, curMessage, DEFAULT_BUFLEN);

                    RSA_public_encrypt(DEFAULT_BUFLEN, messageBytes, encryptedMessage, pubkey, RSA_PKCS1_OAEP_PADDING);

                    iResult = send(ClientSocket, (char *)encryptedMessage, KEY_LEN, 0);
                    startIndex = endIndex;
                    endIndex = endIndex + DEFAULT_BUFLEN;
                }
                    // Getting to a number of bytes left that is smaller than or equal to the maximum buflen,
                    // means we have reached the end of the message. encrypt and send to server
                else if (bytesLeft <= DEFAULT_BUFLEN) {
                    u_char messageBytes[bytesLeft];
                    memcpy(messageBytes, curMessage, bytesLeft);

                    RSA_public_encrypt(bytesLeft, messageBytes, encryptedMessage, pubkey, RSA_PKCS1_OAEP_PADDING);

                    iResult = send(ClientSocket, (char *)encryptedMessage, KEY_LEN, 0);

                    if (iResult == SOCKET_ERROR) {
                        printf("send failed: %d\n", WSAGetLastError());
                        printf("The connection was terminated unexpectedly. Shutting down... \n");
                        goto listen;
                    }

                    closesocket(HttpSocket);
                    closesocket(ClientSocket);
                    memset(response, 0, contentLength);
                    goto listen;
                }

                bytesLeft -= DEFAULT_BUFLEN;

                // if a socket error occurs when sendingD
                if (iResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    printf("The connection was terminated unexpectedly. Shutting down... \n");
                    goto listen;
                }
            }

        } else { // if iResult returns an invalid/error code
            printf("The connection was terminated unexpectedly. Closing connection... \n");
            closesocket(ClientSocket);
            goto listen; // Go to the label accepting a new connection.
        }
    }
}

//TODO: handle exceptions when the client unexpectedly disconnects.

int main() {

    WSADATA wsaData; // Contains info about the winsock implementation.
    int iResult; // Number of bytes received.

    // Initialize Winsock. (Here iResult is the exit code for WSAStartup)
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Specifying information - protocol etc.
    struct addrinfo hints;

    // Settings for the socket - ipv4,
    ZeroMemory(&hints, sizeof (hints)); // Fills a block of memory with zeroes.
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    OPENSSL_INIT_new();

    //main server, handles client requests and http.
    server();

 }