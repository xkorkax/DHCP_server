// gcc dhcp_server.c -o dhcp_server
// clang dhcp_server.c -o dhcp_server
// sudo ./dhcp_server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dhcp.h"

int main() {
    // 1. Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    printf("UDP socket created (fd=%d)\n", sockfd);

    // 2. Allow port reuse
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 3. Bind socket to port 67 on all interfaces
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Listening on port %d...\n", DHCP_SERVER_PORT);

    // 4. Packet receive loop
    char buffer[1024];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (1) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }
        printf("Received %d bytes from %s:%d\n", n, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    }

    close(sockfd);
    return 0;
}
