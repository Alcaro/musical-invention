//Musical Invention, DNS parsing module
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include "musical-invention.h"
#include <stdlib.h>
#include <string.h>

struct dns * dns_parse(const void * packet_, size_t len)
{
	const uint8_t * packet=packet_;
	struct dns * ret = malloc(sizeof(*ret));
	memset(ret, 0, sizeof(*ret));
	
	//ret->
	
	printf("data=%lu(", len);
	printhex(packet, len);
	puts(")");
	return ret;
}

void dns_free(struct dns * query)
{
	free(query);
}
