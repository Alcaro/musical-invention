//Musical Invention, main module
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include "musical-invention.h"
#include <sys/socket.h>

struct musical_rule rules[] = {
	{"example.com", 0,0, ~0, 0,65535, NULL, -1},
};
struct musical_config g_config = { rules, sizeof(rules)/sizeof(*rules), "MUSICAL", "ACCEPT", 0 };

static bool trace_callback(bool isresponse, const uint8_t* packet, size_t len, void* userdata)
{
	printf("dir=%s data=%lu(%.2X %.2X %.2X %.2X...)\n", isresponse?"response":"query", len, packet[0], packet[1], packet[2], packet[3]);
	return true;
}

uint8_t buf[4096] __attribute__ ((aligned));
int main(int argc, char* argv[])
{
	struct musical_trace * trace;
	
	struct musical_config * config = musical_config_parse(NULL, stderr);
	config = &g_config;
	
	trace = musical_trace_init(config->nfqueue, trace_callback, NULL);
	
	int rv;
	while ((rv = recv(trace->fd, buf, sizeof(buf), 0)) && rv >= 0) {
		musical_trace_packet(trace, buf, rv);
	}
	musical_trace_close(trace);
}
