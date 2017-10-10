#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SCANPORT  4952
#define MAXFILENUM  10

char* SERVERIP = "127.0.0.1";

#define ERR_EXIT(m) \
do { \
perror(m); \
exit(EXIT_FAILURE); \
} while (0)

/* Listen to request from main service */
int SS_listen_main_prog_request(char *recvbuf, int buf_size)
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SCANPORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("ScanThreatService: Listening to requests from main at:%d\n",
           SCANPORT);

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        ERR_EXIT("bind error");

    /* Start waiting for data from main program */
    struct sockaddr_in peeraddr;
    socklen_t peerlen;

    while (1)
    {
        printf("ScanThreatService: Waiting for content\n");
        printf("ScanThreatService: Please send request follow \"Main: file1, content\"\n");

        peerlen = sizeof(peeraddr);
        ssize_t n;
        n = recvfrom(sock, recvbuf, buf_size, 0,
                     (struct sockaddr *)&peeraddr, &peerlen);
        printf("ScanThreatService: recevied buffer is %s\n", recvbuf);
        if (n <= 0)
        {

            if (errno == EINTR)
                continue;

            ERR_EXIT("ScanThreatService: recvfrom error");
        }
        else if(n > 0)
        {
            /* Threat: ack can be modified */
            char acknowlege_message[] =
            "ScanThreatService: ack, request received";
            printf("FileReadService: Received request \n");
            sendto(sock, acknowlege_message, strlen(acknowlege_message), 0,
                   (struct sockaddr *)&peeraddr, peerlen);
            close(sock);
            return 10;
        }
    }
    return 0;
}

char SS_scan_content(char* content){
    FILE *fd;
    char signature[512];
    memset(signature, 0, sizeof(signature));
    fd = fopen("file_db", "r");
    fgets(signature, sizeof(signature), fd);
    char *s = strstr(content, signature);       /* Determine infection */
    printf("%s\n", s);
    if (s == NULL) {
        return 'c';
    }
    else{
        return 'i';
    }
    return '!';
}

int SS_send_status(char * status, char *filename){
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SCANPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    ssize_t ret = 0;

    printf("ScanThreatService: Sending content to the main at:%d\n",
           SCANPORT);

    if (*status == 'F') {
        printf("ScanThreatService: EOF %d\n", (int)ret);
        ret = sendto(sock, "0", 1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        printf("ScanThreatService: bytes sent is %d\n", (int)ret);
    }
    else{
        if(*status == 'i'){
            strcat(filename,", infected");
            ret = sendto(sock, filename, strlen(filename), 0,
                         (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("ScanThreatService: bytes sent is %d\n", (int)ret);
        }
        else if (*status == 'c'){
            strcat(filename,", clean");
            ret = sendto(sock, filename, strlen(filename), 0,
                         (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("ScanThreatService: bytes sent is %d\n", (int)ret);
        }
        close(sock);
    }
    return 0;
}

int main(int argc, const char * argv[]){
    char recvbuf[1024];
    memset(recvbuf, 0, sizeof(recvbuf));
    printf("Start File Read Service.\n");
    while (1) {
        int reqeusted = SS_listen_main_prog_request(recvbuf, 1024);
        if(reqeusted == 10){
            char status = SS_scan_content(recvbuf);
            SS_send_status(status, recvbuf);
        }
        sleep(2);
    }
    return 0;
}
