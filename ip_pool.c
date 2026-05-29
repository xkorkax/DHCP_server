#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "dhcp.h"

// Simple IP pool: next address to offer
static uint32_t next_ip;

// Initialize IP pool
void init_ip_pool() {
    next_ip = ntohl(inet_addr(IP_POOL_START));
}

// Get next available IP from pool
uint32_t allocate_ip() {
    uint32_t ip = next_ip;
    uint32_t pool_end = ntohl(inet_addr(IP_POOL_END));
    if (next_ip > pool_end) {
        printf("IP pool exhausted!\n");
        return 0;
    }
    next_ip++;
    return htonl(ip);
}
