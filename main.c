//Musical Invention, main module
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include "musical-invention.h"
#include <sys/socket.h>

struct rule rules[] = {
	{"example.com", 0,0, ~0, 0,65535, NULL, -1},
};
struct config g_config = { rules, sizeof(rules)/sizeof(*rules), "MUSICAL", "ACCEPT", 0 };

static bool get_direction(struct trace_packet* packet)
{
	if (packet->direction == input) return true;
	if (packet->direction == output) return false;
	if (packet->dstport == 53) return false;
	if (packet->srcport == 53) return true;
	return false; // this shouldn't hit, default to query because query opens less
}

static bool tr_callback(struct trace_packet* packet, void* userdata)
{
	if (packet->direction == internal) packet->direction = get_direction(packet);
	
	printf("dir=%i proto=%i ", packet->direction, packet->proto);
	printf("src=%i.%i.%i.%i:%i ", packet->src[12], packet->src[13], packet->src[14], packet->src[15], packet->srcport);
	printf("dst=%i.%i.%i.%i:%i ", packet->dst[12], packet->dst[13], packet->dst[14], packet->dst[15], packet->dstport);
	
	struct dns * q = dns_parse(packet->data, packet->datalen);
	if (!q) return false;
	
	bool ret=true;
	
	dns_free(q);
	return ret;
}

uint8_t buf[4096] __attribute__((aligned));
int main(int argc, char* argv[])
{
	struct config * cfg = config_parse(NULL, stderr);
	cfg = &g_config;
	
	struct trace * tr = trace_init(cfg->nfqueue, tr_callback, NULL);
	
	int rv;
	while ((rv = recv(tr->fd, buf, sizeof(buf), 0)) && rv >= 0) {
		trace_handle(tr, buf, rv);
	}
	trace_close(tr);
}
