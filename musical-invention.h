//Musical Invention, header
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

//config.c
struct rule {
	const char * domain;
	
	uint32_t ip_mask; // If (ip&mask)!=match, reject.
	uint32_t ip_match;
	
	int proto; // 1 - TCP, 2 - UDP, 4 - ICMP
	
	uint16_t port_min; // ICMP is considered port 0.
	uint16_t port_max;
	
	const char * user; // NULL - any
	
	int delay; // -1 - DNS TTL
};

struct config {
	struct rule * rules;
	size_t numrules;
	
	const char * chain;
	const char * chain_out;
	int nfqueue;
};

struct config * config_parse(FILE* input, FILE* errors);
void config_free(struct config * config);


//dns.c
struct dns {
	bool isresponse;
	
	uint16_t id;
	
	char * domain;
	uint8_t ip[16];
};
struct dns * dns_parse(const void * packet, size_t len);
void dns_free(struct dns * query);



//main.c - contains only main()


//trace.c
//Return value is whether to accept the packet.
//Data should be checked against the whitelist in both directions.
//TODO: Can I protect against a rogue actor sending bogus replies with data in the IP field?
struct trace_packet;
typedef bool(*trace_callback)(struct trace_packet* packet, void* data);

struct trace {
	struct nfq_handle * nfq;
	struct nfq_q_handle * nfqq;
	int fd;
	
	trace_callback callback;
	void* userdata;
};

enum { tcp=6, udp=17, icmp=1 };
struct trace_packet {
	enum { input, output, internal } direction; // refers to iptables INPUT/OUTPUT chains; internal means it's on loopback
	
	uint8_t src[16];
	uint8_t dst[16];
	
	uint8_t proto;
	
	uint16_t srcport;
	uint16_t dstport;
	
	const uint8_t * data;
	size_t datalen;
};

struct trace * trace_init(int chain, trace_callback callback, void* userdata);
void trace_handle(struct trace * h, const void* data, size_t len);
void trace_close(struct trace * h);


static inline void printhex(const void * p, size_t n)
{
	const uint8_t * p8 = p;
	printf("%.2X", p8[0]);
	for (size_t i=1;i<n;i++) printf(" %.2X", p8[i]);
}
