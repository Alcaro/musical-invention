//Musical Invention, netfilter module
//Author: Alcaro, based on <http://www.netfilter.org/projects/libnetfilter_queue/doxygen/nfqnl__test_8c_source.html>
//Licence: GPL v3.0 or higher

#include "musical-invention.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

static unsigned int get_lo()
{
	static unsigned int lo = 0;
	if (lo == 0)
	{
		struct nlif_handle * h = nlif_open();
		nlif_query(h);
		
		while (true)
		{
			char name[IFNAMSIZ];
			name[0]=0;
			
			nlif_index2name(h, ++lo, name);
			if (!strcmp(name, "lo")) break;
		}
		
		nlif_close(h);
	}
	return lo;
}

static bool unpack_ipv4(struct trace_packet * pack)
{
	if (pack->datalen < 20) return false; // IPv4 packets are 20 bytes plus data
	if ((pack->data[0]>>4) != 4) return false;
	
	if ((pack->data[0]&15) != 5) return false; // Internet Header Length, seems like it should never be used
	
	if ((pack->data[6]&0x20)!=0) return false; // fragmented, not last
	if ((pack->data[6]&0x1F)!=0 || pack->data[7]!=0) return false; // fragmented, not first
	
	static const uint8_t ipv6_v4_prefix[16-4]={0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
	memcpy(pack->src, ipv6_v4_prefix, 12);
	memcpy(pack->src+12, pack->data+12, 4);
	memcpy(pack->dst, ipv6_v4_prefix, 12);
	memcpy(pack->dst+12, pack->data+16, 4);
	
	pack->proto = pack->data[9];
	
	pack->data += 20;
	pack->datalen -= 20;
	
	return true;
}

static bool unpack_udp(struct trace_packet * pack)
{
	if (pack->proto != udp) return false;
	if (pack->datalen < 8) return false; // UDP packets are 8 bytes plus data
	
	pack->srcport = pack->data[0]<<8 | pack->data[1];
	pack->dstport = pack->data[2]<<8 | pack->data[3];
	
	pack->data += 8;
	pack->datalen -= 8;
	
	return true;
}

static bool process(struct nfq_data * nfa, struct trace * tr)
{
	uint8_t * data;
	int len = nfq_get_payload(nfa, &data);
	
	struct trace_packet pack;
	memset(&pack, 0, sizeof(pack));
	
	if (nfq_get_indev(nfa)!=0)
	{
		if (nfq_get_indev(nfa) != get_lo()) pack.direction = input;
		else return true;//already processed
	}
	else
	{
		if (nfq_get_outdev(nfa) != get_lo()) pack.direction = output;
		else pack.direction = internal;
	}
	
	//this data is an IP packet
	//the packet is assumed to be valid; I'll reject things with rare options, but I'll ignore lengths and checksums
	
	int dev = nfq_get_indev(nfa);
	if (!dev) dev = nfq_get_outdev(nfa); // haven't found anything set zero or both of those
	
	pack.data = data;
	pack.datalen = len;
	
	if(0);
	else if (unpack_ipv4(&pack)) {}
	else return false;
	
	//now 'data' points to a UDP/etc packet
	
	if(0);
	else if (unpack_udp(&pack)) {}
	else return false;
	
	//now it's a payload, probably DNS
	
	bool accept = tr->callback(&pack, tr->userdata);
	
	return accept;
}

static int cb(struct nfq_q_handle * qh, struct nfgenmsg * nfmsg,
              struct nfq_data * nfa, void * userdata)
{
	bool accept = process(nfa, userdata);
	
	uint32_t id=0;
	struct nfqnl_msg_packet_hdr * ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) id = ntohl(ph->packet_id);
	nfq_set_verdict(qh, id, accept?NF_ACCEPT:NF_DROP, 0, NULL);
	return 0;
}

struct trace * trace_init(int chain, trace_callback callback, void* userdata)
{
	struct trace * tr = malloc(sizeof(*tr));
	if (!tr) return NULL;
	memset(tr, 0, sizeof(*tr));
	
	tr->nfq = nfq_open();
	if (!tr->nfq) goto fail;
	if (nfq_unbind_pf(tr->nfq, AF_INET) < 0) goto fail;
	if (nfq_bind_pf(tr->nfq, AF_INET) < 0) goto fail;
	tr->nfqq = nfq_create_queue(tr->nfq, chain, &cb, tr);
	if (!tr->nfqq) goto fail;
	if (nfq_set_mode(tr->nfqq, NFQNL_COPY_PACKET, 0xffff) < 0) goto fail;
	tr->fd = nfq_fd(tr->nfq);
	
	tr->callback = callback;
	tr->userdata = userdata;
	
	return tr;
	
fail:
	trace_close(tr);
	return NULL;
}

void trace_handle(struct trace * tr, const void* data, size_t len)
{
	nfq_handle_packet(tr->nfq, (char*)data, len);
}

void trace_close(struct trace * tr)
{
	if (tr->nfqq) nfq_destroy_queue(tr->nfqq);
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	//nfq_unbind_pf(tr->nfq, AF_INET);
	if (tr->nfq) nfq_close(tr->nfq);
	free(tr);
}
