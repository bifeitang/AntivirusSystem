#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
//#include <seccomp.h>


#define SCANPORT  4952
#define MAXFILENUM  10

char* SERVERIP = "127.0.0.1";

#define ERR_EXIT(m) \
do { \
perror(m); \
exit(EXIT_FAILURE); \
} while (0)

/* Set up seccomp filters */
/*
 void setup_filter(){
 int ret = 0;

 scmp_filter_ctx ctx;

 ctx = seccomp_init(SCMP_ACT_KILL);
 if(ctx == NULL){
 fprintf(stderr, "error: Initialization failed.\n");
 }

 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
 if(!ret)
 ret = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
 SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
 if(!ret)
 ret = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
 SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
 if(!ret)
 ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
 if(ret)
 fprintf(stderr, "error: Filter setting failed.\n");
 seccomp_load(ctx);
 }
 */

/* Listen to request from main service */
int SS_listen_main_prog_request(char *recvbuf, int buf_size)
{
    printf("\n");
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SCANPORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

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
            printf("ScanThreatService: ACK Sent.\n");
            return 10;
        }
    }
    printf("\n");
    return 0;
}

int SS_scan_content(char *content){
    printf("\n");
    printf("ScanThreatService: Scan content start\n");

    FILE *fp;
    char signature[512];
    memset(signature, 0, 512);

    if((fp = fopen("signature_db", "r")) == NULL){
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

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

    if (s == NULL) {
        return 10;
    }
    printf("\n");
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
        printf("ScanThreatService: sent EOF to Main%d\n", (int)ret);
        ret = sendto(sock, "0", 1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    }
    else{
        if(*status == 11){
            strcat(filename,", infected");
            ret = sendto(sock, filename, strlen(filename), 0,
                         (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("ScanThreatService: sent %s\n", filename);
        }
        else if (*status == 10){
            strcat(filename,", clean");
            ret = sendto(sock, filename, strlen(filename), 0,
                         (struct sockaddr *)&servaddr, sizeof(servaddr));
            printf("ScanThreatService: sent %s\n", filename);
        }
        close(sock);
    }
    return 0;
}

int main(int argc, const char * argv[]){
    //setup_filter();
    char recvbuf[1024];
    memset(recvbuf, 0, sizeof(recvbuf));
    printf("===================== Start Scan Service =====================\n");
    while (1) {
        int request;
        request = SS_listen_main_prog_request(recvbuf, 1024);
        printf("ScanThreatService: received buffer is %s\n", recvbuf);
        if(request == 10){
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

