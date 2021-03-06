#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAXDATASIZE 100   /* Maxsize of bytes we read per time */
#define UPDATEPORT  4950
#define SERVERPORT  3490    /* Port to recevie TCP packages from server */
#define BUFFER_SIZE 1024
char* SERVER_IP =   "127.0.0.1";

#define ERR_EXIT(m) \
do { \
perror(m); \
exit(EXIT_FAILURE); \
} while (0)

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

    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("connect");
        exit(1);
    }
    //printf("UpdateService: Connection Established\n");
    recv(sock_cli, signature, sizeof(signature),0); //Receive Signature
    printf("UpdateService: Virus Signature Received is %s\n",signature);

    close(sock_cli);
    return 0;
}

/* Receive datagram from main program */
int listen_main_prog_request(){
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(UPDATEPORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("UpdateService: start listening request at:%d\n", UPDATEPORT);
    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        ERR_EXIT("bind error");

    /* Start waiting for data from main program */
    char recvbuf[1024] = {0};
    struct sockaddr_in peeraddr;
    socklen_t peerlen;
    int n;

    while (1)
    {
        peerlen = sizeof(peeraddr);
        memset(recvbuf, 0, sizeof(recvbuf));
        n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                     (struct sockaddr *)&peeraddr, &peerlen);
        if (n <= 0)
        {

            if (errno == EINTR)
                continue;

            ERR_EXIT("recvfrom error");
        }
        else if(n > 0)
        {
            printf("UpdateService: Received request \n");
            char acknowlege_message[] =
            "UpdateService: ack, content received";
            sendto(sock, acknowlege_message, strlen(acknowlege_message), 0,
                   (struct sockaddr *)&peeraddr, peerlen);
            close(sock);
            return 10;
        }
    }
    return 0;
}

int append_signature(char *signature){
    int fd;
    char db_path[] = "threat_db.txt";
    fd = open(db_path, O_RDWR | O_APPEND | O_CREAT, 0700);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    char appendn[] = "\n";
    printf("UpdateService: Write into threat_db.txt with \"%s\"\n", signature);
    write(fd, signature, strlen(signature));
    write(fd, appendn, strlen(appendn));
    close(fd);
    return 0;
}

/* Update DB text file*/

int main(int argc, const char * argv[])
{
    printf("================ Start Update Signature Service ================\n");
    while (1) {
        int status = listen_main_prog_request();
        if(status == 10){
            char signature[5];
            signature[4] = '\0';
            receive_virus_signature(signature);
            append_signature(signature);
        }
    }
    return 0;
}

