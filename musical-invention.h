//Musical Invention, header
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct musical_rule {
	//This affects whether the query is allowed.
	const char * domain;
	
	//These (and the above) affect whether the response is allowed.
	
	uint32_t ip_mask;
	uint32_t ip_match;
	
	//These (and the DNS response) affect what iptables rule to add.
	
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

//config.c
bool musical_config_parse(FILE* file, struct musical_config * config, FILE* errors);

//dns.c

//trace.c
struct musical_trace {
	struct nfq_handle * h;
	void(*callback)(bool response, const uint8_t* packet, size_t len);
};

struct musical_trace * musical_trace_init(int chain, bool(*callback)(bool response, const uint8_t* packet, size_t len));
void musical_trace_packet(struct musical_trace * h, const uint8_t* data, size_t len);
void musical_trace_close(struct musical_trace * h);

//main.c - contains only main()

