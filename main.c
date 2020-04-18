#include "common.h"
#include "tools.h"
#include "parse.h"

int main() {
    // variables
    int sd;
    int saddrSize;
    int dataSize;
    struct sockaddr saddr;
    unsigned char buffer[RECV_BUFFER_SIZE];
    snifferLog slog;
    char ifrName[15];

    memset(buffer, 0, sizeof(buffer));
    slog.log = fopen("log.txt", "w");
    fprintf(slog.log,"v===== LOG(%s %s) =====v\n", __DATE__, __TIME__);
    if (slog.log == NULL) {
        perror("fopen(): ");
        return EXIT_FAILURE;
    }
    slog.protocols = malloc(sizeof(allProtocols*));

    printf("Interface name:");
    scanf("%s", ifrName);

    sd = initSocket(ifrName, ip, 0);
    if (sd < 0) {
        perror("socket(): ");
        return EXIT_FAILURE;
    }
    initScreen();

    while(1) {
        saddrSize = sizeof(saddr);
        dataSize = recvfrom(sd, buffer, sizeof(buffer), 0, 
                            &saddr, (socklen_t*)&saddrSize);
        if (dataSize < 0) {
            close(sd);
            perror("recvfrom(): ");
            return EXIT_FAILURE;
        }
        parseFrame(buffer, dataSize, &slog);
    }

    deinitSocket(sd, ifrName);
    return EXIT_SUCCESS;
}