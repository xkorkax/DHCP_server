#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "dhcp.h"

// Send a DHCP reply packet via broadcast on port 68
void send_dhcp_reply(int sockfd, struct dhcp_packet *reply) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_CLIENT_PORT);
    dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    if (sendto(sockfd, reply, sizeof(*reply), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    } else {
        struct in_addr offered;
        offered.s_addr = reply->yiaddr;
        printf("Sent reply to %02x:%02x:%02x:%02x:%02x:%02x -> %s\n",
               reply->chaddr[0], reply->chaddr[1], reply->chaddr[2],
               reply->chaddr[3], reply->chaddr[4], reply->chaddr[5],
               inet_ntoa(offered));
    }
}

// Build DHCP OFFER packet in response to DISCOVER
struct dhcp_packet build_dhcp_offer(struct dhcp_packet *discover) {
    struct dhcp_packet offer;
    memset(&offer, 0, sizeof(offer));

    // Header fields
    offer.op = BOOTREPLY;
    offer.htype = discover->htype;
    offer.hlen = discover->hlen;
    offer.xid = discover->xid;          // copy transaction ID
    offer.flags = discover->flags;
    offer.yiaddr = allocate_ip(discover->chaddr);  // offered IP
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

    return offer;
}

// Build DHCP ACK packet in response to REQUEST
struct dhcp_packet build_dhcp_ack(struct dhcp_packet *request) {
    struct dhcp_packet ack;
    memset(&ack, 0, sizeof(ack));

    // Header fields
    ack.op = BOOTREPLY;
    ack.htype = request->htype;
    ack.hlen = request->hlen;
    ack.xid = request->xid;
    ack.flags = request->flags;
    ack.siaddr = inet_addr(SERVER_IP);
    memcpy(ack.chaddr, request->chaddr, 16);
    ack.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    // Get requested IP from option 50
    uint32_t requested_ip;
    if (get_dhcp_option(request, OPT_REQUESTED_IP, (uint8_t *)&requested_ip, 4) > 0) {
        ack.yiaddr = requested_ip;
    } else {
        ack.yiaddr = request->ciaddr;  // fallback: use client's current IP
    }

    // Confirm the lease in the table
    confirm_lease(request->chaddr, ack.yiaddr);

    // Build options
    int opt_offset = 0;

    uint8_t msg_type = DHCP_ACK;
    opt_offset = add_option(ack.options, opt_offset, OPT_MSG_TYPE, 1, &msg_type);

    uint32_t server_id = inet_addr(SERVER_IP);
    opt_offset = add_option(ack.options, opt_offset, OPT_SERVER_ID, 4, &server_id);

    uint32_t lease = htonl(LEASE_TIME);
    opt_offset = add_option(ack.options, opt_offset, OPT_LEASE_TIME, 4, &lease);

    uint32_t mask = inet_addr(SUBNET_MASK);
    opt_offset = add_option(ack.options, opt_offset, OPT_SUBNET_MASK, 4, &mask);

    uint32_t router = inet_addr(ROUTER_IP);
    opt_offset = add_option(ack.options, opt_offset, OPT_ROUTER, 4, &router);

    uint32_t dns = inet_addr(DNS_IP);
    opt_offset = add_option(ack.options, opt_offset, OPT_DNS, 4, &dns);

    ack.options[opt_offset] = OPT_END;

    return ack;
}

// Build DHCP NAK packet in response to invalid REQUEST
struct dhcp_packet build_dhcp_nak(struct dhcp_packet *request) {
    struct dhcp_packet nak;
    memset(&nak, 0, sizeof(nak));

    nak.op = BOOTREPLY;
    nak.htype = request->htype;
    nak.hlen = request->hlen;
    nak.xid = request->xid;
    nak.flags = request->flags;
    // yiaddr = 0 (no IP for you)
    nak.siaddr = inet_addr(SERVER_IP);
    memcpy(nak.chaddr, request->chaddr, 16);
    nak.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    int opt_offset = 0;

    uint8_t msg_type = DHCP_NAK;
    opt_offset = add_option(nak.options, opt_offset, OPT_MSG_TYPE, 1, &msg_type);

    uint32_t server_id = inet_addr(SERVER_IP);
    opt_offset = add_option(nak.options, opt_offset, OPT_SERVER_ID, 4, &server_id);

    nak.options[opt_offset] = OPT_END;

    return nak;
}
