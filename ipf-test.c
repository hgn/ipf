#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

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

#include "ipf.h"

struct ctx {
	int packet_fd;
	struct ipf_ctx ipf_ctx;
};

static void die(const char *str)
{
	fprintf(stderr, "ERROR: - %s\n", str);
	exit(666);
}


static void die_sys(const char *str)
{
	fprintf(stderr, "ERROR: - %s (%s)\n",
			str, strerror(errno));
	exit(666);
}


static int open_packet_fd(struct ctx *ctx)
{
	ctx->packet_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (ctx->packet_fd < 0) {
		die_sys("cannot open PF_PACKET socket");
		return -1;
	}

	return 0;

}

void packet_in(struct ctx *ctx, char *packet, int len)
{
	if (ipf_is_fragment(L1_TYPE_ETHER, packet, len)) {
		char *new_packet;
		unsigned int *new_size = NULL;
		struct ipf_pkt_ctx *pkt_ctx;
		int ret;

		fprintf(stderr, "packet is fragmented, enqueue it\n");

		pkt_ctx = ipf_ctx_frag_in(&ctx->ipf_ctx, L1_TYPE_ETHER, packet, len);
		if (pkt_ctx != NULL) {
			/* all fragments arrived, the packet is allready
			 * constructed, now it is time to feed the next
			 * component whith this shinny new packet */
			ret = ipf_get_reassembled(pkt_ctx, &new_packet, new_size);
			if (ret < 0) {
				fprintf(stderr, "should not happended\n");
			}

			/* Do what you want with new_packet, new_size */

			/* Do what you want with all fragments */

			/* remove fragments, newly created packet and finally
			 * the structure as well */
		}
	fprintf(stderr, "\n\n");
	}

}

static void loop(struct ctx *ctx)
{
	int packet_len;
	char packet[2048];

	while (666) {
		packet_len = recvfrom(ctx->packet_fd, packet, sizeof(packet), 0, NULL, NULL);
		if (packet_len < 42) /* eth (14), ip (20), udp header (8) */
			continue;

		//fprintf(stderr, "received a packet of len %d byte\n", packet_len);

		packet_in(ctx, packet, packet_len);
	}
}

int main(void)
{
	int ret;
	struct ctx ctx;
	struct ipf_ctx_init_opts opts;

	memset(&opts, 0, sizeof(opts));

	opts.max_packet_contextes = 100;
	opts.max_frags_per_packet_context = 20;

	opts.do_ipv4_checksum_test = 0;

	opts.reassembly_timeout = 30000; /* 30 sec */

	opts.packet_pace_value = 0; /* instantly */

	ret = ipf_init(&opts, &ctx.ipf_ctx);
	if (ret < 0)
		die("Cannot intialize ipf context\n");


	ret = open_packet_fd(&ctx);
	if (ret < 0)
		die("cannot data source\n");

	loop(&ctx);

	return 0;
}
