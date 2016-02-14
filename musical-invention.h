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
//TODO


//main.c - contains only main()


//trace.c
typedef bool(*musical_trace_callback)(bool isresponse, const uint8_t* packet, size_t len, void* data);

struct musical_trace {
	struct nfq_handle * nfq;
	struct nfq_q_handle * nfqq;
	int fd;
	
	musical_trace_callback callback;
	void* userdata;
};

struct musical_trace * musical_trace_init(int chain, musical_trace_callback callback, void* userdata);
void musical_trace_packet(struct musical_trace * h, const void* data, size_t len);
void musical_trace_close(struct musical_trace * h);
