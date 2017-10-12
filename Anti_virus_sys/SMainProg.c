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

#define UPDATEPORT  4950
#define READPORT    4951
#define SCANPORT    4952
#define MAXFILENUM  10
char *SERVERIP =    "127.0.0.1";


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
    char recvbuf[512] = {0};
    sendto(sock, request_message, strlen(request_message), 0,
           (struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("Main: Send request packet to the Threat Database Update Service\n");
    ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
    sleep(3);
    printf("Main: Receive updated information \"%s\"\n\n", recvbuf);
    if (ret == -1)
    {
        if (errno == EINTR)
            ERR_EXIT("recvfrom");
    }
    close(sock);
}

/* Send Request to File Read Server */
void FS_request(char *request_message)
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(READPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    ssize_t ret;
    char recvbuf[1024] = {0};
    ret = sendto(sock, request_message, strlen(request_message), 0,
                 (struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("Main: Send request message to File Read Service\n");
    ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
    printf("Main: Receive Read Service ACK \"%s\"\n", recvbuf);
    if (ret == -1)
    {
        if (errno == EINTR)
            ERR_EXIT("recvfrom");
    }
    sleep(1);
    close(sock);
}
/* Send file path to File Read Service */
char **FS_receive_content(int *recv_mesg_num)
{
    int sock;
    char **contents;
    contents = (char**)malloc(MAXFILENUM * sizeof(char*));

    if (contents == NULL) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(READPORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("Main: Listening to contents from service at:%d\n",
           READPORT);

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        ERR_EXIT("bind error");

    /* Start waiting for data from main program */
    struct sockaddr_in peeraddr;
    socklen_t peerlen;
    peerlen = sizeof(peeraddr);
    ssize_t ret = 0;
    int num = 0;
    while (ret != 1) {
        contents[num] = (char *)malloc(sizeof(char) * 512);
        ret = recvfrom(sock, contents[num], 512, 0,
                       (struct sockaddr *)&peeraddr, &peerlen);
        printf("Main: Received file content \"%s\"\n", contents[num]);
        num++;
    }
    contents[num - 1] = NULL;
    *recv_mesg_num = num - 1;

    printf("Main: Finish receive with last byte \"%d\"\n\n", (int)ret);
    close(sock);
    sleep(3);
    return contents;
}

void SS_request(char *request_message)
{

    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");

    printf("Main: Start SS_request service\n");
    printf("Main: Sending %s to SS\n", request_message);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SCANPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    ssize_t ret;
    char recvbuf[1024] = {0};
    ret = sendto(sock, request_message, strlen(request_message), 0,
                 (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (ret == -1) {
        fprintf(stderr, "error: %s\n", strerror(errno));
    }
    printf("Main: Send request to Scan Service\n");
    ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
    printf("Main: Receive Scan Service ACK \"%s\"\n", recvbuf);
    if (ret == -1)
    {
        if (errno == EINTR)
            ERR_EXIT("recvfrom");
    }
    close(sock);
}

void SS_receive_content()
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SCANPORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("Main: Listening to contents from service at:%d\n",
           SCANPORT);

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        ERR_EXIT("bind error");

    /* Start waiting for data from main program */
    struct sockaddr_in peeraddr;
    socklen_t peerlen;
    peerlen = sizeof(peeraddr);
    char recvbuf[1024] = {0};
    ssize_t ret = 0;
    while (ret != 1) {
        memset(recvbuf, 0, 1024);
        ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                       (struct sockaddr *)&peeraddr, &peerlen);
        printf("Main: Received file content \"%s\"\n", recvbuf);
    }
    if (ret == 1) {
        printf("Main: Finish receive with last byte \"%d\"\n\n", (int)ret);
        close(sock);
    }
    return;
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

    if (errno == EADDRINUSE){
        printf("Main: process at port %d has already opened\n", port);
        return 1;
    }
    else{
        printf("Main: process at port %d has already opened\n", port);
        return 1;
    }
    return 1;
}

void MAIN_invoke(int port){
    pid_t US_pid, RS_pid, SS_pid;
    int US_status, RS_status, SS_status;
    switch (port) {
        case UPDATEPORT:
            printf("Main: Start Update Service\n");
            US_pid = fork();
            if (US_pid < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
            if (US_pid == 0) {
                US_status = execl("./client &", NULL);
            }
            break;

        case READPORT:
            printf("Main: Start Read Content Service\n");
            RS_pid = fork();
            if (RS_pid < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
            if (RS_pid == 0) {
                RS_status = execl("./client2 &", NULL);
            }
            break;

        case SCANPORT:
            printf("Main: Start Scan Threat Service\n");
            SS_pid = fork();
            if (SS_pid < 0) {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
            if (SS_pid == 0) {
                SS_status = execl("./client3 &", NULL);
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
        fprintf(stderr, "Main: please input a file to scan\n");
        exit(EXIT_FAILURE);
    }

    /* Start all the services */
    if (!MAIN_port_opened(UPDATEPORT)) {
        MAIN_invoke(UPDATEPORT);
    }
    if (!MAIN_port_opened(READPORT)) {
        MAIN_invoke(READPORT);
    }
    if (!MAIN_port_opened(SCANPORT)) {
        MAIN_invoke(SCANPORT);
    }

    /* Waiting for all services invoke */
    sleep(4);

    /* Send request to UpdateService */
    US_request();

    /* Send request and file names to File Read Service */
    char FS_request_message[] = "Main: ";
    int argnum = 1;
    while ((argv[argnum] != NULL) && (argv[argnum + 1] != NULL)) {
        strcat(FS_request_message, argv[argnum]);
        strcat(FS_request_message, ", ");
        argnum++;
    }
    strcat(FS_request_message, argv[argnum]);
    FS_request(FS_request_message);
    /* Receive contents from read service */
    int recv_mesg_num = 0;
    char **contents = FS_receive_content(&recv_mesg_num);
    /* Send request to Scan Service*/
    for (int i = 0; i < recv_mesg_num; i++) {
        printf("%d\n", i);
        SS_request(contents[i]);
        SS_receive_content();
        sleep(6);
    }

    for(int i = 0; i <recv_mesg_num; i++){
        free(contents[i]);
    }
    free(contents);

    printf("Main: All services finished\n");
    return 0;
}

