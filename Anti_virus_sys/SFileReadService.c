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

#define READPORT  4951
#define MAXFILENUM  10

char* SERVERIP = "127.0.0.1";
static uid_t euid, ruid;

#define ERR_EXIT(m) \
do { \
perror(m); \
exit(EXIT_FAILURE); \
} while (0)

/* Create File Read Service Server and Waiting for Connections */
int listen_main_prog_request(char *recvbuf, int buf_size)
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(READPORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        ERR_EXIT("bind error");

    /* Start waiting for data from main program */
    struct sockaddr_in peeraddr;
    socklen_t peerlen;

    while (1)
    {
        printf("FileReadService: Please send request follow \"Main: file1, file2, ..., file10\"\n");

        peerlen = sizeof(peeraddr);
        ssize_t n;
        n = recvfrom(sock, recvbuf, buf_size, 0,
                     (struct sockaddr *)&peeraddr, &peerlen);
        printf("FileReadService: recevied buffer is %s\n", recvbuf);
        if (n <= 0)
        {

            if (errno == EINTR)
                continue;

            ERR_EXIT("recvfrom error");
        }
        else if(n > 0)
        {
            /* Threat: ack can be modified */
            char acknowlege_message[] =
            "FileReadService: ack, request received";
            printf("FileReadService: Received request \n");
            sendto(sock, acknowlege_message, strlen(acknowlege_message), 0,
                   (struct sockaddr *)&peeraddr, peerlen);
            close(sock);
            return 10;
        }
    }
    return 0;
}

/* Get the file name/path from the received packet */
char **SF_get_filename(char *recvbuf)
{
    char *delim = ":, ";
    int para_num = 0;
    char *parameter;
    char **parameters;

    parameters = (char**)malloc(MAXFILENUM * sizeof(char*));

    if (parameters == NULL) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    parameter = strtok(recvbuf, delim);
    while (parameter != NULL) {
        parameters[para_num] = parameter;
        para_num++;
        parameter = strtok(NULL, delim);
    }
    parameters[para_num] = NULL;
    return parameters;
}

void SF_read_content(char *content, char *filename){
    printf("\n");
    if (filename == NULL) {
        printf("FileReadService: Invalid file name\n");
        return;
    }
    printf("FileReadService: Filename %s\n", filename);
    int access_ok;
    printf("FileReadService: ruid %u, euid %u\n", ruid, euid);

    access_ok = access(filename, R_OK);
    printf("FileReadService: access to the file %d\n", access_ok);

    if(setreuid(0, 0)){
        fprintf(stderr, "error: %s\n", strerror(errno));
    }
    access_ok = access(filename, R_OK);
    printf("FileReadService: changed access to the file %d\n", access_ok);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        return;
    }
    int readbytes;
    readbytes = (int)read(fd, content, 512);
    content[readbytes-1] = '\0';
    printf("FileReadService: Bytes readed %d\n", readbytes);
    if (readbytes < 0) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        return;
    }
    if(setreuid(ruid, euid)){
        fprintf(stderr, "error: %s\n", strerror(errno));
    }
    access_ok = access(filename, R_OK);
    printf("FileReadService: changed access to the file %d\n", access_ok);
    printf("\n");
}

/* Send the content to the Main prog */
int SF_send_content(char *content, char *filename){
    printf("\n");
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(READPORT);
    servaddr.sin_addr.s_addr = inet_addr(SERVERIP);

    ssize_t ret = 0;
    printf("FileReadService: Sending content to the main at:%d\n",
           READPORT);

    if (content == NULL && filename == NULL) {
        printf("FileReadService: EOF %d\n", (int)ret);
        ret = sendto(sock, "0", 1, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    }
    else{
        char sendmessage[512] = {0};
        int sendsize = 0;
        strncpy(sendmessage, filename, strlen(filename));
        sendsize += strlen(filename);
        strcat(sendmessage,", ");
        sendsize += sendsize + 2;
        strcat(sendmessage, content);
        sendsize += sendsize + strlen(content);
        ret = sendto(sock, sendmessage, sendsize, 0,
                     (struct sockaddr *)&servaddr, sizeof(servaddr));
        printf("FileReadService: bytes sent is %d\n", (int)ret);
        close(sock);
    }
    return 0;
}


int main(int argc, const char * argv[]){
    ruid = getuid();
    euid = geteuid();
    char recvbuf[1024];
    char readbuf[1024];
    char *content = readbuf;
    char **parameters;
    memset(recvbuf, 0, sizeof(recvbuf));
    memset(readbuf, 0, sizeof(readbuf));
    printf("=================== Start File Read Service ===================\n");
    while (1) {
        int status = listen_main_prog_request(recvbuf, 1024);
        if(status == 10){
            parameters = SF_get_filename(recvbuf);
            int num = 1;
            sleep(2);
            while (parameters[num] != NULL) {
                SF_read_content(content, parameters[num]);
                SF_send_content(content, parameters[num]);
                memset(readbuf, 0, sizeof(readbuf));
                sleep(2);
                num++;
            }
        }
        sleep(2);
        SF_send_content(NULL, NULL);
        sleep(3);
    }
    return 0;
}

