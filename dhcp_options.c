#include <string.h>
#include <stdint.h>
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

// Add a DHCP option to the options buffer. Returns new offset.
int add_option(uint8_t *options, int offset, uint8_t code, uint8_t len, void *data) {
    options[offset] = code;
    options[offset + 1] = len;
    memcpy(&options[offset + 2], data, len);
    return offset + 2 + len;
}
