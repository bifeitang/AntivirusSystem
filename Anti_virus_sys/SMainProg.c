#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define UPDATEPORT 4950
#define READPORT 4951
#define SCANPORT 4952
char *SERVERIP = "127.0.0.1";


#define ERR_EXIT(m) \
do { \
perror(m); \
exit(EXIT_FAILURE); \
} while (0)

/* Send Update Request to Database Update Service */
void US_request()
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(UPDATEPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    int ret;
    char *request_message = "Main: Request on port\n";
    char recvbuf[4] = {0};
    sendto(sock, request_message, strlen(request_message), 0,
           (struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("Main: Send request packet to the Threat Database Update Service\n");
    ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
    sleep(3);
    printf("Main: Receive updated information \"%s\"\n", recvbuf);
    if (ret == -1)
    {
        if (errno == EINTR)
            ERR_EXIT("recvfrom");
    }
    close(sock);
}

/* Send Request to File Read Server */
void FS_request()
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(READPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    int ret;
    char *request_message = "Main: Request on port\n";
    sendto(sock, request_message, strlen(request_message), 0,
           (struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("Main: Send request packet to the Threat Database Update Service\n");
    char recvbuf[1024] = {0};
    ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
    sleep(3);
    printf("Main: Receive updated information \"%s\"\n", recvbuf);
    if (ret == -1)
    {
        if (errno == EINTR)
            ERR_EXIT("recvfrom");
    }
    close(sock);
}
/* Send file path to File Read Service */
void FS_send_path(const char* file_path)
{

}

int MAIN_port_opened(int port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in temp_addr;
    bzero((char *)&temp_addr, sizeof(temp_addr));
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = INADDR_ANY;
    temp_addr.sin_port = htons(port);

    if (! bind(sockfd, (struct sockaddr *) &temp_addr, sizeof(temp_addr))) {
        close(sockfd);
        return 0;
    }
    else if (errno == EADDRINUSE){
        printf("Main: process at port %d has already opened", port);
        return 1;
    }
    else{
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return 1;
}

void MAIN_invoke(int port){
    pid_t US_pid, RS_pid, SS_pid;
    int US_status, RS_status, SS_status;
    switch (port) {
        case UPDATEPORT:
            US_pid = fork();
            if (US_pid < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
            if (US_pid == 0) {
                US_status = execl("./client &", NULL);
            }
            break;

        case READPORT:
            RS_pid = fork();
            if (RS_pid < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
            if (RS_pid == 0) {
                RS_status = execl("./client &", NULL);
            }
            break;

        case SCANPORT:
            SS_pid = fork();
            if (SS_pid < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
            if (SS_pid == 0) {
                SS_status = execl("./client &", NULL);
            }
            break;

        default:
            break;
    }
}

int main(int argc, const char * argv[])
{
    printf("Main: Start Update Service\n");

    if (argc < 2) {
        fprintf(stderr, "Main: please input a file to scan");
        exit(EXIT_FAILURE);
    }

    if (!MAIN_port_opened(UPDATEPORT)) {
        MAIN_invoke(UPDATEPORT);
    }

    if (!MAIN_port_opened(READPORT)) {
        MAIN_invoke(READPORT);
    }

    if (!MAIN_port_opened(SCANPORT)) {
        MAIN_invoke(SCANPORT);
    }


    sleep(2);
    US_request();

    FS_send_path(argv[1]);

    return 0;
}

