
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>

#define UPDATEPORT 4950
char* SERVERIP = "127.0.0.1";


#define ERR_EXIT(m) \
do { \
perror(m); \
exit(EXIT_FAILURE); \
} while (0)

void echo_ser()
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket");


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(UPDATEPORT);
    servaddr.sin_addr.s_addr = inet_addr(UPDATEPORT);

    int ret;
    char *request_message = "Main: Request on port\n";
    char recvbuf[4] = {0};
    sendto(sock, request_message, strlen(request_message), 0,
           (struct sockaddr *)&servaddr, sizeof(servaddr));
    printf("Main: Send request packet to the Threat Database Update Service\n");
    ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
    printf("Main: Receive updated information \"%s\"\n", recvbuf);
    if (ret == -1)
    {
        if (errno == EINTR)
            ERR_EXIT("recvfrom");
    }
    close(sock);
}

int main(void)
{
    printf("Main: Start Update Service\n");


    pid_t pid;
    pid = fork();
    int status;

    if (pid == 0) {
        status = execl("./client", NULL);
    }
    else if (pid < 0){
        fprintf(stderr, "error: %s\n", strerror(errno));
    }
    else{
        echo_ser();
    }
    return 0;
}
