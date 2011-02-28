#ifndef IPH_H
#define IPH_H

#include <netinet/in.h> /* IPPROTO_* */

struct ipf_ctx_init_opts {
        int max_contextes;

	/* default 30 seconds, has nothing to do with mm/gc processing.
	 * In turn this value is of interest to age a context. For example
	 * it may be possible that a specific fragment is never reassembled
	 * and thus no  */
        int max_time;

        /* if memory is over high threshold we iterate over the list
	 * until the low thresold is reached. */
        int high_threshold;
        int low_threshold;
        int max_fragments_per_pkt_context;
        int do_ipv4_checksum_test; /* this option SHOULD be enabled */
        int reassembly_timeout;

	/* to minize burst effects after all fragments arrives and all
	 * fragments are re-injected into the network this pace_value
	 * in milliseconds can be used to pace delay each fragment */
        int pace_value;
};

struct ipf_ctx {
        /* sorted in first fragment arrival order: thus
	 * first_fragment_arrived_time is strict increasing order.
	 * The garbage collector build on this concept by removing
	 * from the tail of the list until the first_fragment_arrived_time
	 * is lesser as the limit. */
        struct list *ipf_pkt_ctx;
};

struct ipf_pkt_ctx {
        int type; /* AF_INET or AF_INET6 */
	int proto; /* IPPROTO_UDP, IPPROTO_TCP, IPPROTO_SCTP, ... */
        union {
                struct {
                        uint32_t src_ip;
                        uint32_t dst_ip;
                        uint16_t id;
                } ipv4;
                struct {
                        uint32_t src_ip[4];
                        uint32_t dst_ip[4];
                } ipv6;
        } ;

        struct list *fragment_list; /* this list is _already_ ordered, fragment  */

        char *packet; /* reassemblied packet, the memory is allocated if packet is contructed */
        unsigned int packet_size;

        struct timespec first_fragment_arrived_time;

        /* plus data about fragment count et cetera */
};


int ipf_init(struct ipf_ctx_init_opts *opts, struct ipf_ctx **ctx);
int ipf_destroy(struct ipf_ctx *ctx);
int ipf_is_fragment(int layer2_type, char *packet, unsigned int size);
struct ipf_pkt_ctx *ipf_pkt_ctx(struct ipf_ctx *ctx, int layer2_type, char *packet, unsigned int size);
int ipf_alloc_pkt_context(struct ipf_pkt_ctx **pkt_ctx);
void ipf_free_pkt_context(struct ipf_pkt_ctx *);


enum {
	IPF_STATUS_COMPLETE,
	IPF_STATUS_INCOMPLETE,
};

/* returns IPF_STATUS_INCOMPLETE, IPF_STATUS_COMPLETE */
int ipf_status(struct ipf_pkt_ctx);


enum {
	L1_TYPE_ETHER,
};

/* L1_TYPE_ETHER, L1_TYPE_ATM, ...
 * Returns 0 if all was ok, -ENOBUFS if no memory is available or
 * -EIO if the packet checksum is corrupted, -ENOTTY if the packet
 *  is weird.
 *
 * NOTE: this function verify the IP packet checksum. If the packet
 * checksum is wrong then the   then ipf_pkt_ctx is still intact
 * except. Note that we CANNOT feed the packet classifier with this
 * packet because the IP header is clearly defect. Defect packet are
 * forwarded to the local network stack! Why? Because we don't want to
 * modify the internal packet processing. For example, the SNMP IP MIB
 * should be notified. The user should be noticed via SNMP MIB about
 * corrupted packets.   */
int ipf_insert_pkt(struct ipf_pkt_ctx *, int type, char *pkt, unsigned int len);

/* this functions frees memory by iterating over all fragment list and
 * free memory if diff(first_fragment_arrived_time, current_time) >
 * reassembly_timeout. This function can be called if OOM conditions
 * occur or in regular intervalls */
int ipf_gc(struct ipf_ctx *ipf_ctx);

struct ipf_statistics {
	unsigned int total_fragments;
};

/* return statistics about memory usage and other things */
int ipf_stats(struct ipf_ctx *ctx, struct ipf_statistics *stats);

#endif /* IPH_H */