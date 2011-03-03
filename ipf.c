#define	__USE_BSD

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>

#include <net/ethernet.h> /* ETHER_HDR_LEN */

#include "ipf.h"

static int pkt_ctx_cmp(const void *a, const void *b)
{
	int cmp = 0; /* not equal */
	const struct ipf_pkt_ctx *a_ctx, *b_ctx;

	a_ctx = a;
	b_ctx = b;

	if ((a_ctx->type != b_ctx->type))
		return 0;

	switch (a_ctx->type) {
		case AF_INET:
			/* FIXME: some ECN bits must be controlled too */
			if ((a_ctx->uu.ipv4.src_ip == b_ctx->uu.ipv4.src_ip) &&
			    (a_ctx->uu.ipv4.dst_ip == b_ctx->uu.ipv4.dst_ip) &&
			    (a_ctx->uu.ipv4.id == b_ctx->uu.ipv4.id))
				cmp = 1;
			break;
		case AF_INET6:
			assert(0);
			break;
		default:
			cmp = 0;
			break;
	}

	return cmp;
}

static void pkt_free_pkt_ctx(void *p)
{
	ipf_free_pkt_context(p);
}

static int frag_cmp(const void *a, const void *b)
{
	return a == b;
}

static void frag_free(void *a)
{
	free(a);
}

int ipf_init(struct ipf_ctx_init_opts *opts, struct ipf_ctx *ctx)
{
	assert(opts);
	assert(ctx);

	ctx->pkt_ctx_list = list_create(pkt_ctx_cmp, pkt_free_pkt_ctx);
	/* FIXME: catch error */

	return 0;
}

int ipf_destroy(struct ipf_ctx *ctx)
{
	free(ctx);

	return 0;
}

#define IPF_IP_MF 0x2000
#define IPF_IP_OF 0x1FFF


static int is_ipv4_fragment(char *packet, unsigned int size)
{
	struct iphdr *iphdr = (struct iphdr *)(packet + ETHER_HDR_LEN);

	(void) size;

	//fprintf(stderr, "  received IPv4 packet\n");

	/* I place the guard here, hopefully this rare effent
	 * is implemented some day --HGN */
	if (iphdr->ihl != 5) {
		/* FIXME: not implemented */
		fprintf(stderr, "ipv4 header with options, skipping");
		return 0;
	}

	if (iphdr->frag_off & htons(IPF_IP_MF | IPF_IP_OF)) {
		return 1;
	}


	return 0;
}

static int is_ipv6_fragment(char *packet, unsigned int size)
{
	/* struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + ETHER_HDR_LEN); */

	(void) packet;
	(void) size;

	fprintf(stderr, "  received IPv6 packet [not supported]\n");

	return 0;
}

/* this function returns 1 if the packet is fragmented. Or 0 if not fragmented
 * or the format is not known (e.g. no IP packet) */
int ipf_is_fragment(int layer2_type, char *packet, unsigned int size)
{
	struct ether_header *eth;

	assert(layer2_type == L1_TYPE_ETHER);
	assert(packet);
	assert(size > 34); /* eth(14) + ipv4(20) */

	eth = (struct ether_header *)packet;

	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			return is_ipv4_fragment(packet, size);
			break;
		case ETHERTYPE_IPV6:
			return is_ipv6_fragment(packet, size);
			break;
		default:
			return 0;
			break;
	}

	return 0;
}


static int pkt_ctx_insert_frag(struct ipf_pkt_ctx *pkt_ctx, struct ipf_fragment_container *fragment_container)
{
	int ret;

	fprintf(stderr, "enqueue fragment into packet context list\n");

	/* FIXME: ok, here we go ...
	 *
	 * The tricky parts starts here! We must make sure that we enqueue the
	 * fragment in the correct fragment order. We must make sure that the
	 * packet is not corrupted and memory does not overlap */

	ret = list_insert_tail(pkt_ctx->ipf_fragment_container_list, (void *)fragment_container);
	if (ret != CLIST_SUCCESS) {
		fprintf(stderr, "Cannot enqueue packet context into list\n");
		return -ENOMEM;
	}

	/* fragments still missing */
	pkt_ctx->packet_complete = 0;

	return 0;
}

struct ipf_pkt_ctx *ipf_ctx_frag_in(struct ipf_ctx *ctx,
		int layer2_type, char *packet, unsigned int size)
{
	int ret;
	struct ipf_fragment_container *fragment_container;
	struct ipf_pkt_ctx pkt_ctx, *pkt_ctx_ptr;
	struct ether_header *eth;
	struct iphdr *iphdr;

	assert(ctx);
	assert(layer2_type == L1_TYPE_ETHER);
	assert(packet);
	assert(size > 34); /* eth(14) + ipv4(20) */

	memset(&pkt_ctx, 0, sizeof(pkt_ctx));


	/* FIXME: save header processing overhead (two time: here and is_fragment() */
	eth = (struct ether_header *)packet;
	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			iphdr = (struct iphdr *)(packet + ETHER_HDR_LEN);

			pkt_ctx.type           = AF_INET;
			pkt_ctx.uu.ipv4.src_ip = iphdr->saddr;
			pkt_ctx.uu.ipv4.dst_ip = iphdr->daddr;
			pkt_ctx.uu.ipv4.id     = iphdr->id;

			break;
		case ETHERTYPE_IPV6:
			assert(0);
			break;
		default:
			return NULL;
			break;
	}

	pkt_ctx_ptr = &pkt_ctx;

	ret = list_lookup(ctx->pkt_ctx_list, (void **)&pkt_ctx_ptr);
	if (ret == CLIST_SUCCESS) {
		fprintf(stderr, "packet context already created\n");
	} else {
		/* FIXME: this block should be a separate function
		 * and the cleanup routine in a case of an error must
		 * be checked - especially memory must be freed */

		fprintf(stderr, "create packet context\n");
		pkt_ctx_ptr = malloc(sizeof(*pkt_ctx_ptr));
		if (!pkt_ctx_ptr) {
			fprintf(stderr, "out of mem\n");
			return NULL;
		}
		memcpy(pkt_ctx_ptr, &pkt_ctx, sizeof(pkt_ctx));

		pkt_ctx_ptr->ipf_fragment_container_list = list_create(frag_cmp, frag_free);
		if (!pkt_ctx_ptr->ipf_fragment_container_list) {
			fprintf(stderr, "out of mem\n");
			return NULL;
		}

		/* take time */
		ret = gettimeofday(&pkt_ctx_ptr->first_fragment_arrived_time, NULL);
		if (ret < 0) {
			fprintf(stderr, "gettimeofday error\n");
			return NULL;
		}

		/* and finaly register the packet context in the global list */
		ret = list_insert_tail(ctx->pkt_ctx_list, (void *)pkt_ctx_ptr);
		if (ret != CLIST_SUCCESS) {
			fprintf(stderr, "Cannot enqueue packet context into list\n");
			return NULL;
		}
	}

	fragment_container = malloc(sizeof(*fragment_container));
	if (!fragment_container) {
		fprintf(stderr, "out of mem\n");
		return NULL;
	}

	fragment_container->packet = packet;
	fragment_container->packet_size = size;
	fragment_container->iphdr = iphdr;

	ret = pkt_ctx_insert_frag(pkt_ctx_ptr, fragment_container);
	if (ret < 0) {
		fprintf(stderr, "Cannot add frag into packet context\n");
		return NULL;
	}

	if (pkt_ctx_ptr->packet_complete) {
		/* yes, we got all required fragments. Now we
		 * reassembly the fragments. Construct the packet
		 * and return pkt_ctx_ptr to signal our callee that
		 * the packet is ready */

		return pkt_ctx_ptr;
	}

	return NULL;
}

#define MIN_ETHER_HEADER_LEN 34

void ipf_free_pkt_context(struct ipf_pkt_ctx *pkt_ctx)
{
	if (!pkt_ctx)
		return;

	/* XXX: iterate over frag list */

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

int ipf_get_reassembled(struct ipf_pkt_ctx *pkt_ctx, char **pkt, unsigned int *pkt_len)
{
	*pkt     = pkt_ctx->packet;
	*pkt_len = pkt_ctx->packet_size;

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
