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
            "ScanThreatService: ack, content received";
            printf("ScanThreatService: Received request \n");
            sendto(sock, acknowlege_message, strlen(acknowlege_message), 0,
                   (struct sockaddr *)&peeraddr, peerlen);
            close(sock);
            printf("ScanThreatService: ACK Sent. \n");
            return 10;
        }
    }
    return 0;
}

int SS_scan_content(char *content){
    printf("ScanThreatService: Scan content start\n");

    FILE *fp;
    char signature[512];
    memset(signature, 0, 512);

    if((fp = fopen("signature_db", "r")) == NULL){
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("ScanThreatService: File opened\n");

    char *s = NULL;
    int num = 0;

    while(fgets(signature, 512, fp)){
        signature[4] = '\0';
        s = strstr(content, signature);       /*Determine infection*/
        printf("[%d] Scan: Signature %s\n", num, signature);
        if (s == NULL) {
            printf("[%d] Scan: Clean\n", num);
        }
        else{
            printf("[%d] Scan: Infected, %s\n", num, s);
            return 11;
        }
        num++;
    }

    //printf("%s\n", s);

    if (s == NULL) {
        return 10;
    }

    return 1;
}

int SS_send_status(int *status, char *filename){
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

    if (*status == 100) {
        printf("ScanThreatService: EOF %d\n", (int)ret);
        ret = sendto(sock, "0", 1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        printf("ScanThreatService: bytes sent is %d\n", (int)ret);
    }
    else{
        if(*status == 11){
            strcat(filename,", infected");
            ret = sendto(sock, filename, strlen(filename), 0,
                         (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("ScanThreatService: send %s\n", filename);
            printf("ScanThreatService: bytes sent is %d\n", (int)ret);
        }
        else if (*status == 10){
            strcat(filename,", clean");
            ret = sendto(sock, filename, strlen(filename), 0,
                         (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("ScanThreatService: send %s\n", filename);
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
        int request;
        request = SS_listen_main_prog_request(recvbuf, 1024);
        printf("ScanThreatService: get status %d\n", request);
        printf("ScanThreatService: received buffer is %s\n", recvbuf);
        if(request == 10){
            printf("ScanThreatService: Start scan content\n");
            int status = SS_scan_content(recvbuf);
            sleep(3);
            SS_send_status(&status, recvbuf);
        }
        sleep(2);
        int eof = 100;
        SS_send_status(&eof, NULL);
        sleep(3);
    }
    return 0;
}
