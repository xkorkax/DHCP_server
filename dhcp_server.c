// gcc dhcp_server.c -o dhcp_server
// clang dhcp_server.c -o dhcp_server
// sudo ./dhcp_server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dhcp.h"

// Parse DHCP options and return the value of a given option code
// Returns -1 if option not found
int get_dhcp_option(struct dhcp_packet *packet, int opt_code, uint8_t *out, int out_len) {
    int i = 0;
    while (i < DHCP_OPTIONS_LEN) {
        uint8_t code = packet->options[i];

        if (code == OPT_END)
            break;

        if (code == 0) {    // Padding option — skip
            i++;
            continue;
        }

        uint8_t len = packet->options[i + 1];

        if (code == opt_code) {
            if (len <= out_len)
                memcpy(out, &packet->options[i + 2], len);
            return len;
        }

        i += 2 + len;  // skip to next option: code(1) + len(1) + data(len)
    }
    return -1;
}

// Get DHCP message type (option 53). Returns -1 if not found
int get_dhcp_msg_type(struct dhcp_packet *packet) {
    uint8_t msg_type;
    if (get_dhcp_option(packet, OPT_MSG_TYPE, &msg_type, 1) > 0)
        return msg_type;
    return -1;
}

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

        // 5. Validate packet size
        if (n < (DHCP_HEADER_SIZE + DHCP_MAGIC_COOKIE_SIZE)) {
            printf("Packet too small, ignoring\n");
            continue;
        }

        // 6. Cast buffer to DHCP packet
        struct dhcp_packet *packet = (struct dhcp_packet *)buffer;

        // 7. Validate magic cookie
        if (ntohl(packet->magic_cookie) != DHCP_MAGIC_COOKIE) {
            printf("Invalid magic cookie, ignoring\n");
            continue;
        }

        // 8. Check if it's a client request
        if (packet->op != BOOTREQUEST) {
            printf("Not a BOOTREQUEST, ignoring\n");
            continue;
        }

        // 9. Get DHCP message type
        int msg_type = get_dhcp_msg_type(packet);
        printf("DHCP message type: %d\n", msg_type);

        switch (msg_type) {
            case DHCP_DISCOVER:
                printf("Received DHCP DISCOVER from %02x:%02x:%02x:%02x:%02x:%02x\n",
                       packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
                       packet->chaddr[3], packet->chaddr[4], packet->chaddr[5]);
                // TODO: send DHCP OFFER
                break;
            default:
                printf("Unhandled message type: %d\n", msg_type);
                break;
        }
    }

    close(sockfd);
    return 0;
}
