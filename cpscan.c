#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <WS2tcpip.h>
#include <windns.h>
#include <winerror.h>
#include <process.h>

typedef enum Protocol {
    Tcp,
    Udp,
} Protocol;

typedef struct PACKET_CONTENTS {
    char *ipAddress;
    WORD port;
    Protocol pt;
    BOOL debug;
    long timeout;
} PACKET_CONTENTS, *PPACKET_CONTENTS;

void InitWinSock();
void ShowSyntax();
int ResolveDnsAddress(char *dnsQuery, Protocol pt, char **output, size_t bufferSize);
size_t SendSynPacket(PPACKET_CONTENTS config);
void ScanTarget(size_t portStart, size_t portEnd, char *domain, Protocol pt, BOOL debug, long timeout);

const long DEFAULT_TIMEOUT = 200;
const size_t DEFAULT_START_PORT = 1;
const size_t DEFAULT_END_PORT = 1024;
const size_t MAX_PORT = 65535;
const char *VERSION = "0.0.2";
const char *AUTHOR = "liquidlegs";

/*
Function initalizes the winsock2 library.
Params:
    None.
returns WSADATA.
*/
void InitWinSock() {
    WSADATA w;
    int err = WSAStartup(MAKEWORD(2,2), &w);
    if(err < 0) wprintf(L"Failed to initalize winsock\n");
}

/*
Function resolves dns domain names to ip addresses.
Params:
    char        *dnsQuery       -       [The domain name to query.]
    Protocol    pt              -       [The protocol to use.]
    char        **output        -       [The buffer to receive the result.]
    size_t      bufferSize      -       [The size of the receiving buffer.]
Returns int.
*/
int ResolveDnsAddress(char *dnsQuery, Protocol pt, char **output, size_t bufferSize) {
    DNS_STATUS err = 0;                                             // The return err;
    PDNS_RECORDA record = {0};                                      // Holds the dns results.
    struct in_addr ip;                                              // Holds the ip address in its network byte order.
    size_t queryType = 0x00000000;                                  // Standard dns queries use tcp and udp.

    if(strlen(dnsQuery) <= 0) return -1;                            // If the user enters an empty query, function fails and returns -1.
    if(pt == Tcp) pt = 0x00000002;                                  // A tcp only dns query.
    if(pt == Udp) return -1;                                        // Winapi doesnt support resolving address over udp only.

    err = DnsQuery_A (                                              // Makes a Dns query.
        dnsQuery,                                                   // The query string.
        0x0001,                                                     // The type of record [A].
        pt,                                                         // The type of query.
        NULL,                                                       // A reserved parameter.
        &record,                                                    // The results of the query.
        NULL                                                        // A reserved parameter.
    );

    if(record != NULL) {
        ip.S_un.S_addr = record->Data.A.IpAddress;                  // Stores the ip address in its network byte order.
        size_t ipBufSize = strlen(inet_ntoa(ip));                   // Gets the length of the ip address string.
        if(bufferSize < ipBufSize) return ipBufSize;                // Return buffer size if allocated memory isnt enough to store returned result.
        strcat_s(*output, 30, inet_ntoa(ip));                       // Fill the buffer with the ip address.
    }

    DnsRecordListFree(record, DnsFreeRecordList);                  // Free allocated memory of the dns results.
    return err;                                                    // Return result of the dns query.
}

/*
Function will attempt to connect to a server socket in hope that it may responnd.
Params:
    PPACKET_CONTENTS config     -       [Contains info to be sent on the socket.]
Returns size_t.
*/
size_t SendSynPacket(PPACKET_CONTENTS config) {
    size_t stream = SOCK_STREAM;                                    // Tcp stream.
    int protocol = IPPROTO_TCP;                                     // Tcp protocol.

    if(config->pt == Udp) {                                         // If the udp enum is found on the config param.
        stream = SOCK_DGRAM;                                        // then set the socket to use Udp.
        protocol = IPPROTO_UDP;
    }
    
    struct sockaddr_in server;                                      // Destination host information.
    server.sin_addr.S_un.S_addr = inet_addr(config->ipAddress);     // Ipaddress as network byte order.
    server.sin_family = AF_INET;                                    // Uses Ipv4.
    server.sin_port = htons(config->port);                          // Server port in network byte order.

    SOCKET s = INVALID_SOCKET;                                      // Socket object.
    s = WSASocketA(AF_INET, stream, protocol, NULL, 0, 0);          // Create the socket.
    if(s < 0) {
        printf("INVALID SOCKET\n");
        closesocket(s);                                             // Closesocket if invalid.
        return 1;
    }

    ULONG block = 1;                                                // Non blocking socket mode.
    int errBlock = ioctlsocket(s, FIONBIO, &block);                 // Set socket to block requests.
    if(errBlock < 0) {
        closesocket(s);                                             // Close socket if something goes wrong.
        return 1;
    }
                                                                   // Attempt to connect to server port.
    int err = connect(s, (struct sockaddr*)&server, sizeof(server));
    if(WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set w, e;                                                
        FD_ZERO(&w);                                                // Zero out structures.
        FD_ZERO(&e);
        FD_SET(s, &w);                                              // Allow socket to be written to.
        FD_SET(s, &e);                                              // Tell socket how to handle the connection if it fails.
        
        TIMEVAL timeout = {0};                                      // Setup timeout period for scanning ports.
        timeout.tv_sec = 0;
        timeout.tv_usec = config->timeout;                          // timeout is equal to microseconds*1000.
        
        size_t counter = 0;                                         // Counts how many times the connect function is called.
        size_t time = 0;                                            // Controls how many times the connect function can be called before it moves on.
        select(0, NULL, &w, &e, &timeout);                          // Applies timeout to socket.
        while(WSAGetLastError() != WSAEISCONN && time < 2) {        // Loop until the connectio succeeds or fails.
            err = connect(s, (struct sockaddr*)&server, sizeof(server));
            counter++;
            if(counter >= 10) {
                time++;
                counter = 0;
            }
        }

        if(WSAGetLastError() == WSAEISCONN) {                       // Report socket open if successful.
            printf("OPEN [%hu]\n", config->port);
            closesocket(s);                                         // Close the socket.
            return 0;                                               // Return status success.
        }
        else if(WSAGetLastError() != WSAEISCONN && time >= 1) {     // Report socket closed on failure.
            if(config->debug == TRUE) printf("CLOSED [%hu]\n", config->port);
            closesocket(s);                                         // Close the socket.
            return 1;                                               // Return status fail.
        }
    }

    closesocket(s);         // The function probably wont get this far.
    return 1;               // But if it does, close the socket and return failure.
}

/*
Function displays the help menu.
Params:
    None.
Returns nothing.
*/
void ShowSyntax() {
    printf(
            "\n"
            "           8  .o88b. d8888b. .d8888.  .o88b.  .d8b.  d8b   db 8\n"
            "           8 d8P  Y8 88  `8D 88'  YP d8P  Y8 d8' `8b 888o  88 8\n"
            "           8 8P      88oodD' `8bo.   8P      88ooo88 88V8o 88 8\n"
            "    C8888D   8b      88~~~     `Y8b. 8b      88~~~88 88 V8o88   C8888D\n"
            "           8 Y8b  d8 88      db   8D Y8b  d8 88   88 88  V888 8\n"
            "           8  `Y88P' 88      `8888Y'  `Y88P' YP   YP VP   V8P 8\n\n"
            "           Author:  [%s]\n"
            "           Version: [%s]\n\n"
            "___________________________________Help___________________________________\n\n"
            "           [ -p      ]              <Scan ports within a range>\n"
            "           [ -proto  ]              <The protocol you want to use>\n"
            "           [ -dbg    ]              <Show debug information>\n"
            "           [ -t      ]              <Set syn request timeout in ms>\n"
            "           [ -h      ]              <Show this menu>\n\n"
            "           [Examples]\n"
            "              stackmypancakes.com -proto tcp -p 1 1024\n"
            "              doogle.com -dbg -proto udp -p 22 65535\n"
            "              asdf.com -t 200 -proto tcp -p 440 450\n"
            "              friendface.com -t 50 -dbg -p 50 100 -proto tcp\n"
            "__________________________________________________________________________\n\n",
            AUTHOR, VERSION
    );
}

/*
Function runs the main loop for scanning and preparing ports to be scanned.
Params:
    size_t      portStart        -       [The start range to begin the port scan.]
    size_t      portEnd          -       [The end range to finish the port scan.]
    char        *domain          -       [The domain name to be resolved.]
    Protocol    pt               -       [The protocol to use in the scan. tcp/udp.]
    BOOL        debug            -       [Displays debug information such as closed ports]
    long        timeout          -       [The maxium amount of time a port should be scanned before moving on to the next.]
Returns nothing.
*/
void ScanTarget(size_t portStart, size_t portEnd, char *domain, Protocol pt, BOOL debug, long timeout) {
    char *dnsBuf = calloc(30, sizeof(char));                                                    // Buffer to receive the resolved dns name.
    PACKET_CONTENTS p;                                                                          // Stores information used for the socket.

    if(debug == TRUE) printf("Resolving domain name\n");                                        // Simple debug statements.
    int retErr = ResolveDnsAddress(domain, Tcp, &dnsBuf, 30);                                   // Resolve domain name to an ip address.
    if(retErr != 0) {                                                                           // If function fails, exit.
        printf("Error: Unable to resolve domain. Make sure it is spelt correctly.\n");
        return;
    }
    if(debug == TRUE) printf("Name resolved [%s]\n", dnsBuf);

    if(timeout <= 1) p.timeout = DEFAULT_TIMEOUT*1000;                                          // Sets the portscan timeout period.
    else p.timeout = timeout*1000;

    p.ipAddress = dnsBuf;                                                                       // Set the ip address.
    p.pt = pt;                                                                                  // Set the transport protocol.
    p.debug = debug;                                                                            // Set the debug mode.
    for(UINT index = portStart; index <= portEnd; index ++) {
        p.port = index;                                                                         // The port.
        int err = SendSynPacket(&p);                                                            // Send syn packets to each port.
        if(debug == TRUE) printf("SendPacket Status [%u]\n", err);
    }
    if(dnsBuf != NULL) free(dnsBuf);                                                            // Free the dns buffer from memory.
}

/*
Function checks if the port range makes sense.
Params:
    size_t arg1     -       [The starting port range.]
    size_t arg2     -       [The ending port range.]
Returns BOOL.
*/
BOOL arePortsCorrect(size_t arg1, size_t arg2) {
    if(arg1 > arg2) printf("[StartPort (%u) cannot be greater than EndPort (%u)]\n", arg1, arg2);
    else if(arg2 < arg1) printf("[StartPort (%u) cannot be less than EndPort (%u)]\n", arg2, arg1);
    else if(arg2 > 65535) printf("[EndPort (%u) You may not scan ports greater than %u]\n", arg2, MAX_PORT);
    else if(arg1 <= arg2 && arg2 >= arg1) return TRUE;
}

int main(int argc, char *argv[]) {
    long timeout_arg = DEFAULT_TIMEOUT;                                          // The default timeout value.
    size_t startPt = DEFAULT_START_PORT;                                         // The default start port.
    size_t endPt = DEFAULT_END_PORT;                                             // The default end port.
    BOOL ports = FALSE;                                                          // The default port flag.
    InitWinSock();                                                               // Initalizes the winsock2 library.
    
    if(argc <= 1) ShowSyntax();
    else if(argc == 2) {
        if(strlen(argv[1]) > 0 && stricmp("-h", argv[1]) == 0) ShowSyntax();
        else if(strlen(argv[1]) > 0 && stricmp("-h", argv[1]) != 0) {
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], Tcp, FALSE, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 3) {
        if(stricmp("-dbg", argv[2]) == 0) {
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], Tcp, TRUE, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 4) {
        if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0) {
            timeout_arg = atol(argv[3]);
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], Tcp, FALSE, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 5) {
        if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-dbg", argv[4]) == 0) {
            timeout_arg = atol(argv[3]);
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], Tcp, TRUE, timeout_arg);
        }
        else if(stricmp("-dbg", argv[2]) == 0 && stricmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0) {
            timeout_arg = atol(argv[4]);
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], Tcp, TRUE, timeout_arg);
        }
        else if(stricmp("-p", argv[2]) == 0 && strlen(argv[3]) > 0 && strlen(argv[4]) > 0) {
            startPt = atoll(argv[3]);
            endPt = atoll(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, FALSE, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 6) {
        if(stricmp("-dbg", argv[2]) == 0 && stricmp("-p", argv[3]) == 0 && strlen(argv[4]) > 0 && strlen(argv[5]) > 0) {
            startPt = atoll(argv[4]);
            endPt = atoll(argv[5]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, TRUE, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 7) {
        if(stricmp("-p", argv[2]) == 0 && strlen(argv[3]) > 0 && strlen(argv[4]) > 0 && stricmp("-proto", argv[5]) == 0 && stricmp("tcp", argv[6]) == 0) {
            startPt = atoll(argv[3]);
            endPt = atoll(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, FALSE, DEFAULT_TIMEOUT);
        }
        else if(stricmp("-p", argv[2]) == 0 && strlen(argv[3]) > 0 && strlen(argv[4]) > 0 && stricmp("-proto", argv[5]) == 0 && stricmp("udp", argv[6]) == 0) {
            startPt = atoll(argv[3]);
            endPt = atoll(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Udp, FALSE, DEFAULT_TIMEOUT);
        }
        else if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-p", argv[4]) == 0 && strlen(argv[5]) > 0 && strlen(argv[6]) > 0) {
            startPt = atoll(argv[5]);
            endPt = atoll(argv[6]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, FALSE, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 8) {
        if(stricmp("-dbg", argv[2]) && stricmp("-p", argv[3]) == 0 && strlen(argv[4]) > 0 && strlen(argv[5]) > 0 && stricmp("-proto", argv[6]) == 0 && 
        stricmp("tcp", argv[7]) == 0) {
            startPt = atoll(argv[4]);
            endPt = atoll(argv[5]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, TRUE, DEFAULT_TIMEOUT);
        }
        else if(stricmp("-dbg", argv[2]) && stricmp("-p", argv[3]) == 0 && strlen(argv[4]) > 0 && strlen(argv[5]) > 0 && stricmp("-proto", argv[6]) == 0 && 
        stricmp("udp", argv[7]) == 0) {
            startPt = atoll(argv[4]);
            endPt = atoll(argv[5]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Udp, TRUE, DEFAULT_TIMEOUT);
        }
        else if(stricmp("-dbg", argv[2]) == 0 && stricmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0 && stricmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 &&
        strlen(argv[7]) > 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, TRUE, timeout_arg);
        }
        else if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-dbg", argv[4]) == 0 && stricmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 &&
        strlen(argv[7]) > 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, TRUE, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 9) {
        if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-p", argv[4]) == 0 && strlen(argv[5]) > 0 && strlen(argv[6]) > 0 && stricmp("-proto", argv[7]) == 0 && 
        stricmp("tcp", argv[8]) == 0) {
            startPt = atoll(argv[5]);
            endPt = atoll(argv[6]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, FALSE, timeout_arg);
        }
        else if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-p", argv[4]) == 0 && strlen(argv[5]) > 0 && strlen(argv[6]) > 0 && stricmp("-proto", argv[7]) == 0 && 
        stricmp("udp", argv[8]) == 0) {
            startPt = atoll(argv[5]);
            endPt = atoll(argv[6]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Udp, FALSE, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 10) {
        if(stricmp("-dbg", argv[2]) == 0 && stricmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0 && stricmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        stricmp("-proto", argv[8]) == 0 && stricmp("tcp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, TRUE, timeout_arg);
        }
        else if(stricmp("-dbg", argv[2]) == 0 && stricmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0 && stricmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        stricmp("-proto", argv[8]) == 0 && stricmp("udp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Udp, TRUE, timeout_arg);
        }
        else if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-dbg", argv[4]) == 0 && stricmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        stricmp("-proto", argv[8]) == 0 && stricmp("tcp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Tcp, TRUE, timeout_arg);
        }
        else if(stricmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && stricmp("-dbg", argv[4]) == 0 && stricmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        stricmp("-proto", argv[8]) == 0 && stricmp("udp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == TRUE) ScanTarget(startPt, endPt, argv[1], Udp, TRUE, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc > 10) ShowSyntax();

    WSACleanup();                                              // Deallocates memory to the winsock2 library.
}