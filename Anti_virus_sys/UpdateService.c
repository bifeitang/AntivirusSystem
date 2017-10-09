#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "3490"
#define MAXDATASIZE 100   /* Maxsize of bytes we read per time */
#define UPDATEPORT "4950"
#define SERVERPORT  3490    /* Port to recevie TCP packages from server */
#define BUFFER_SIZE 1024
char* SERVER_IP = "127.0.0.1";

/* Get correspoinding IP address of server */
void *get_in_addr(struct sockaddr *sa)
{
    if(sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

/* Receive Virus Signature */
int receive_virus_signature(char *signature){
    //Init sockfd
    int sock_cli = socket(AF_INET,SOCK_STREAM, 0);

    //Init sockaddr_in
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVERPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    printf("Connecting to Threat Signature Server at %s:%d\n",
           SERVER_IP,SERVERPORT);

    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect");
        exit(1);
    }
    printf("Connection Established\n");
    recv(sock_cli, signature, sizeof(signature),0); //Receive Signature
    printf("Virus Signature Received from server: %s\n",signature);

    close(sock_cli);
    return 0;
}

/* Receive datagram from main program */
int listen_main_prog_request(){
    int sockfd;
    socklen_t addrlen;
    int address_status;
    ssize_t receive_bytes;
    char buf[MAXDATASIZE];
    int reuse_local_address = 1;
    struct addrinfo hints, *serverinfo, *p;
    struct sockaddr_storage main_addr;

    /* Initialize some features for listening: IPv4/6, UDP, local_host's IP */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    /* Make database_update_server listen on host's IP address on UPDATEPORT */
    if((address_status = getaddrinfo(NULL, UPDATEPORT,
                                     &hints, &serverinfo)) != 0){
        fprintf(stderr, "getaddrinfo:%s\n", gai_strerror(address_status));
        return EXIT_FAILURE;
    }

    /* Bind to the first valid serverinfo */
    for (p = serverinfo; p != NULL; p = p->ai_next) {

        /* Create socket with returned serverinfo, get socket_file_descriptor */
        if((sockfd = socket(p->ai_family, p->ai_socktype,
                            p->ai_protocol)) == -1){
            fprintf(stderr, "errro: %s\n", strerror(errno));
            continue;
        }

        /* Enable port reuse to avoid "Address in use" problem */
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                       &reuse_local_address, sizeof(int)) == -1) {
            fprintf(stderr, "errro: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        /* bind socket the prot we passed in serverinfo */
        if (bind(sockfd, p->ai_addr, p->ai_addrlen)) {
            close(sockfd);
            fprintf(stderr, "errro: %s\n", strerror(errno));
            continue;
        }
        break;
    }

    /* If there is no valid serverinfo */
    if(p == NULL){
        fprintf(stderr, "Update_listener: fail to bind\n");
        return EXIT_FAILURE;
    }

    freeaddrinfo(serverinfo); /*No longer needs serverinfo*/

    printf("Update_listener: waiting for update request from Main...\n");

    while (1) {
        /* Get request packet from main */
        if (-1 == (receive_bytes = recvfrom(sockfd, buf,
                                            MAXDATASIZE - 1, 0,
                                            (struct sockaddr *)&main_addr,
                                            &addrlen))) {
            fprintf(stderr, "errro: %s\n", strerror(errno));
        }
        /* Print the received packet information */
        buf[(int)receive_bytes] = '\0';
        printf("Update_listener: get request \"%s\" from main\n", buf);
    }

    close(sockfd);
    return 0;
}

/* Update DB text file*/

int main(int argc, const char * argv[])
{
    char signature[5];
    signature[4] = '\0';
    receive_virus_signature(signature);
    printf("received signature: %s\n", signature);
    return 0;
}


