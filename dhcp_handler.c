#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "dhcp.h"

// Build and send DHCP OFFER in response to DISCOVER
void send_dhcp_offer(int sockfd, struct dhcp_packet *discover) {
    struct dhcp_packet offer;
    memset(&offer, 0, sizeof(offer));

    // Header fields
    offer.op = BOOTREPLY;
    offer.htype = discover->htype;
    offer.hlen = discover->hlen;
    offer.xid = discover->xid;          // copy transaction ID
    offer.flags = discover->flags;
    offer.yiaddr = allocate_ip();        // offered IP
    offer.siaddr = inet_addr(SERVER_IP); // server IP
    memcpy(offer.chaddr, discover->chaddr, 16);  // copy client MAC
    offer.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    // Build options
    int opt_offset = 0;

    // Option 53: DHCP Message Type = OFFER
    uint8_t msg_type = DHCP_OFFER;
    opt_offset = add_option(offer.options, opt_offset, OPT_MSG_TYPE, 1, &msg_type);

    // Option 54: Server Identifier
    uint32_t server_id = inet_addr(SERVER_IP);
    opt_offset = add_option(offer.options, opt_offset, OPT_SERVER_ID, 4, &server_id);

    // Option 51: Lease Time
    uint32_t lease = htonl(LEASE_TIME);
    opt_offset = add_option(offer.options, opt_offset, OPT_LEASE_TIME, 4, &lease);

    // Option 1: Subnet Mask
    uint32_t mask = inet_addr(SUBNET_MASK);
    opt_offset = add_option(offer.options, opt_offset, OPT_SUBNET_MASK, 4, &mask);

    // Option 3: Router
    uint32_t router = inet_addr(ROUTER_IP);
    opt_offset = add_option(offer.options, opt_offset, OPT_ROUTER, 4, &router);

    // Option 6: DNS
    uint32_t dns = inet_addr(DNS_IP);
    opt_offset = add_option(offer.options, opt_offset, OPT_DNS, 4, &dns);

    // End option
    offer.options[opt_offset] = OPT_END;

    // Send to broadcast on port 68
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_CLIENT_PORT);
    dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    if (sendto(sockfd, &offer, sizeof(offer), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto (offer)");
    } else {
        struct in_addr offered;
        offered.s_addr = offer.yiaddr;
        printf("Sent DHCP OFFER: %s to %02x:%02x:%02x:%02x:%02x:%02x\n",
               inet_ntoa(offered),
               offer.chaddr[0], offer.chaddr[1], offer.chaddr[2],
               offer.chaddr[3], offer.chaddr[4], offer.chaddr[5]);
    }
}
