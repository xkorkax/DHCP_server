#include <string.h>
#include <stdint.h>
#include <stdio.h> 
#include "dhcp.h"

// Parse DHCP options and return the value of a given option code
int get_dhcp_option(struct dhcp_packet *packet, int opt_code, uint8_t *out, int out_len) {
    int i = 0;
    while (i < DHCP_OPTIONS_LEN) {
        uint8_t code = packet->options[i];
        if (code == OPT_END) break;
        if (code == 0) { i++; continue; }

        if (i + 1 >= DHCP_OPTIONS_LEN) break; 
        uint8_t len = packet->options[i + 1];

        if (i + 2 + len > DHCP_OPTIONS_LEN) break; 

        if (code == opt_code) {
            if (len <= out_len) {
                memcpy(out, &packet->options[i + 2], len);
                return len;
            }
            return -1;
        }
        i += 2 + len;
    }
    return -1;
}

// Get DHCP message type (option 53)
int get_dhcp_msg_type(struct dhcp_packet *packet) {
    uint8_t msg_type;
    if (get_dhcp_option(packet, OPT_MSG_TYPE, &msg_type, 1) > 0)
        return msg_type;
    return -1;
}

// Add a DHCP option to the options buffer
int add_option(uint8_t *options, int offset, uint8_t code, uint8_t len, void *data) {

    if (offset + 2 + len >= DHCP_OPTIONS_LEN) {
        printf("Error: DHCP options buffer overflow detected\n");
        return offset; 
    }
    options[offset] = code;
    options[offset + 1] = len;
    memcpy(&options[offset + 2], data, len);
    return offset + 2 + len;
}
