#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include "dhcp.h"

// Lease table
static struct lease_entry leases[MAX_LEASES];

// Initialize lease table — assign each slot an IP from the pool
void init_lease_table() {
    uint32_t start = ntohl(inet_addr(IP_POOL_START));
    for (int i = 0; i < MAX_LEASES; i++) {
        leases[i].ip_addr = htonl(start + i);
        leases[i].lease_expiry = 0;
        memset(leases[i].chaddr, 0, 16);
    }
    printf("Lease table initialized: %d addresses available\n", MAX_LEASES);
}

// Check if a lease is expired or free
static int is_lease_free(int i) {
    if (leases[i].lease_expiry == 0)
        return 1;
    if (time(NULL) > leases[i].lease_expiry)
        return 1;
    return 0;
}

// Compare MAC addresses
static int mac_equal(uint8_t *a, uint8_t *b) {
    return memcmp(a, b, 6) == 0;
}

// Find existing lease for a client (by MAC). Returns IP or 0 if not found.
uint32_t find_existing_lease(uint8_t *chaddr) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (mac_equal(leases[i].chaddr, chaddr) && !is_lease_free(i)) {
            return leases[i].ip_addr;
        }
    }
    return 0;
}

// Allocate an IP for a client. Returns IP in network byte order, or 0 if pool exhausted.
uint32_t allocate_ip(uint8_t *chaddr) {
    // First: check if client already has a lease
    uint32_t existing = find_existing_lease(chaddr);
    if (existing != 0)
        return existing;

    // Second: find a free slot
    for (int i = 0; i < MAX_LEASES; i++) {
        if (is_lease_free(i)) {
            memcpy(leases[i].chaddr, chaddr, 16);
            leases[i].lease_expiry = time(NULL) + LEASE_TIME;
            printf("Allocated %s (slot %d)\n", inet_ntoa(*(struct in_addr *)&leases[i].ip_addr), i);
            return leases[i].ip_addr;
        }
    }

    printf("IP pool exhausted!\n");
    return 0;
}

// Confirm a lease (called after ACK is sent)
void confirm_lease(uint8_t *chaddr, uint32_t ip) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (mac_equal(leases[i].chaddr, chaddr) && leases[i].ip_addr == ip) {
            leases[i].lease_expiry = time(NULL) + LEASE_TIME;
            return;
        }
    }
}

// Check if a given IP belongs to this client (valid for ACK)
int is_lease_valid_for_client(uint8_t *chaddr, uint32_t ip) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (leases[i].ip_addr == ip) {
            // IP found — is it assigned to this client?
            if (mac_equal(leases[i].chaddr, chaddr) && !is_lease_free(i))
                return 1;
            // IP is free (expired or never used) — also OK to assign
            if (is_lease_free(i))
                return 1;
            // IP is taken by another client
            return 0;
        }
    }
    // IP not in our pool at all
    return 0;
}

// Release a lease (called on DHCP RELEASE)
void release_lease(uint8_t *chaddr) {
    for (int i = 0; i < MAX_LEASES; i++) {
        if (mac_equal(leases[i].chaddr, chaddr)) {
            printf("Released %s (slot %d)\n", inet_ntoa(*(struct in_addr *)&leases[i].ip_addr), i);
            memset(leases[i].chaddr, 0, 16);
            leases[i].lease_expiry = 0;
            return;
        }
    }
}
