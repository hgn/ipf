#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "ipf.h"



int ipf_init(struct ipf_ctx_init_opts *opts, struct ipf_ctx **ctx)
{
	assert(opts);
	assert(*ctx);

	return 0;
}

int ipf_destroy(struct ipf_ctx *ctx)
{
	free(ctx);
}

int ipf_is_fragment(int layer2_type, char *packet, unsigned int size)
{
	assert(layer2_type == L1_TYPE_ETHER);

	return 1;
}

struct ipf_pkt_ctx *ipf_pkt_ctx(struct ipf_ctx *ctx, int layer2_type, char *packet, unsigned int size)
{
	assert(ctx);
	assert(layer2_type == L1_TYPE_ETHER);
	assert(packet);
}

#define MIN_ETHER_HEADER_LEN 23

int ipf_alloc_pkt_context(struct ipf_pkt_ctx **pkt_ctx)
{
	struct ipf_pkt_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (!pkt_ctx)
		return -ENOMEM;

	memset(ctx, 0, sizeof(*ctx));

	*pkt_ctx = ctx;

	return 0;
}

void ipf_free_pkt_context(struct ipf_pkt_ctx *pkt_ctx)
{
	if (!pkt_ctx)
		return;

	if (pkt_ctx->packet)
		free(pkt_ctx->packet);

	free(pkt_ctx);
}

int ipf_insert_pkt(struct ipf_pkt_ctx *pkt_ctx, int type, char *pkt, unsigned int len)
{
	assert(pkt_ctx);
	assert(type == L1_TYPE_ETHER);
	assert(pkt);

	if (len < MIN_ETHER_HEADER_LEN)
		return -ENOTTY;

	return 0;
}

int ipf_gc(struct ipf_ctx *ipf_ctx)
{
	assert(ipf_ctx);

	return 0;
}

int ipf_stats(struct ipf_ctx *ctx, struct ipf_statistics *stats)
{
	assert(ctx);
	assert(stats);

	return 0;
}
