//Musical Invention, header
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

//config.c
struct musical_rule {
	const char * domain;
	
	uint32_t ip_mask; // If (ip&mask)!=match, reject.
	uint32_t ip_match;
	
	int proto; // 1 - TCP, 2 - UDP, 4 - ICMP
	
	uint16_t port_min; // ICMP is considered port 0.
	uint16_t port_max;
	
	const char * user; // NULL - any
	
	int delay; // -1 - DNS TTL
};

struct musical_config {
	struct musical_rule * rules;
	size_t numrules;
	
	const char * chain;
	const char * chain_out;
	int nfqueue;
};

struct musical_config * musical_config_parse(FILE* input, FILE* errors);
void musical_config_free(struct musical_config * config);


//dns.c
struct musical_dns {
	bool isresponse;
	
	uint16_t id;
	
	const char * domain;
	uint32_t ip;
};
struct musical_dns * musical_dns_parse(const void * packet, size_t len);
void musical_dns_free(struct musical_dns * query);



//main.c - contains only main()


//trace.c
//Return value is whether to accept the packet.
//Data should be checked against the whitelist in both directions.
//TODO: Can I protect against a rogue actor sending bogus replies with data in the IP field?
struct musical_trace_packet;
typedef bool(*musical_trace_callback)(struct musical_trace_packet* packet, void* data);

struct musical_trace {
	struct nfq_handle * nfq;
	struct nfq_q_handle * nfqq;
	int fd;
	
	musical_trace_callback callback;
	void* userdata;
};

enum { tcp=6, udp=17, icmp=1 };
struct musical_trace_packet {
	enum { input, output, internal } direction; // refers to iptables INPUT/OUTPUT chains; internal means it's on loopback
	
	uint8_t src[16];
	uint8_t dst[16];
	
	uint8_t proto;
	
	uint16_t srcport;
	uint16_t dstport;
	
	const uint8_t * data;
	size_t datalen;
};

struct musical_trace * musical_trace_init(int chain, musical_trace_callback callback, void* userdata);
void musical_trace_handle(struct musical_trace * h, const void* data, size_t len);
void musical_trace_close(struct musical_trace * h);


static inline void printhex(const void * p, size_t n)
{
	const uint8_t * p8 = p;
	printf("%.2X", p8[0]);
	for (size_t i=1;i<n;i++) printf(" %.2X", p8[i]);
}
