//Musical Invention, netfilter module
//Author: Alcaro, based on <http://www.netfilter.org/projects/libnetfilter_queue/doxygen/nfqnl__test_8c_source.html>
//Licence: GPL v3.0 or higher

#include "musical-invention.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

static int cb(struct nfq_q_handle * qh, struct nfgenmsg * nfmsg,
              struct nfq_data * nfa, void * userdata)
{
	struct musical_trace * trace = userdata;
	uint8_t * data;
	int len = nfq_get_payload(nfa, &data);
	
	int outdev = nfq_get_outdev(nfa);
	bool isresponse = (outdev==2); // TODO: figure out if this is safe
	if (outdev!=1 && outdev!=2)
	{
		printf("PANIC: outdev not in { 1, 2 }\n");
		exit(1);
	}
	
	bool accept = trace->callback(isresponse, data, len, trace->userdata);
	
	uint32_t id=0;
	struct nfqnl_msg_packet_hdr * ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) id = ntohl(ph->packet_id);
	return nfq_set_verdict(qh, id, accept?NF_ACCEPT:NF_DROP, 0, NULL);
}

struct musical_trace * musical_trace_init(int chain, musical_trace_callback callback, void* userdata)
{
	struct musical_trace * trace = malloc(sizeof(*trace));
	if (!trace) return NULL;
	memset(trace, 0, sizeof(*trace));
	
	trace->nfq = nfq_open();
	if (!trace->nfq) goto fail;
	if (nfq_unbind_pf(trace->nfq, AF_INET) < 0) goto fail;
	if (nfq_bind_pf(trace->nfq, AF_INET) < 0) goto fail;
	trace->nfqq = nfq_create_queue(trace->nfq, chain, &cb, trace);
	if (!trace->nfqq) goto fail;
	if (nfq_set_mode(trace->nfqq, NFQNL_COPY_PACKET, 0xffff) < 0) goto fail;
	trace->fd = nfq_fd(trace->nfq);
	
	trace->callback = callback;
	trace->userdata = userdata;
	
	return trace;
	
fail:
	musical_trace_close(trace);
	return NULL;
}

void musical_trace_packet(struct musical_trace * trace, const void* data, size_t len)
{
	nfq_handle_packet(trace->nfq, (char*)data, len);
}

void musical_trace_close(struct musical_trace * trace)
{
	if (trace->nfqq) nfq_destroy_queue(trace->nfqq);
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	//nfq_unbind_pf(trace->nfq, AF_INET);
	if (trace->nfq) nfq_close(trace->nfq);
	free(trace);
}
