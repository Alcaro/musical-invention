//Musical Invention, DNS parsing module
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include "musical-invention.h"
#include <stdlib.h>
#include <string.h>

//'out' must be 256 characters or more. Return value is how long that name is.
static size_t get_domain(char* out, const uint8_t * packet, size_t len, const uint8_t * start)
{
	int outpos=0;
	int ret=0;
	size_t remaining=256;
	const uint8_t * end = packet+len;
	const uint8_t * read = start;
	while (true)
	{
		uint8_t byte = *read++;
		if (byte==0) break;
		else if (byte<=63)
		{
			if (byte >= remaining || read+byte > end) return 0;
			memcpy(out+outpos, read, byte);
			remaining-=byte;
			outpos+=byte;
			read+=byte;
			out[outpos++] = '.';
		}
		//else if (byte==0xC0)
		//{
		//	if (!ret) ret=read-start;
		//	read=packet+*read;
		//}
		else return 0;
	}
	if (!ret) ret=read-start;
	if (!outpos) return 0;
	out[outpos-1]='\0';
	return ret;
}

struct dns * dns_parse(const void * packet_, size_t len)
{
	if (len<12) return NULL;
	
	const uint8_t * packet=packet_;
	struct dns * ret = malloc(sizeof(*ret));
	memset(ret, 0, sizeof(*ret));
	
	ret->id = packet[0]<<8 | packet[1];
	ret->isresponse = packet[2]&0x80;
	if ((packet[2]&0x78) != 0) goto fail; // opcode != QUERY
	
	const uint8_t * question = packet+12;
	size_t questionlen = len-12;
	//const uint8_t * answer;
	//const uint8_t * authority;
	//const uint8_t * additional;
	
	char name[256];
printf("raw=");
	printhex(question, questionlen);
	get_domain(name, packet, len, question);
printf("\ntxt=%s\n", name);
	return ret;
	
fail:
	dns_free(ret);
	return NULL;
}

void dns_free(struct dns * query)
{
	if (query->domain) free(query->domain);
	free(query);
}
