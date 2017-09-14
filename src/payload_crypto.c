#include <include/linux/skbuff.h>
#include <include/linux/errno.h>
#include <include/uapi/asm-generic/errno-base.h>
#include <include/asm-generic/bug.h>
#include <include/uapi/linux/in.h>
#include <include/uapi/linux/ip.h>
#include <include/uapi/linux/ipv6.h>
#include <include/uapi/linux/tcp.h>
#include <include/uapi/linux/udp.h>
#include <include/net/gre.h>
#include <include/net/ipv6.h>

#include "payload_crypto.h"

static struct ipv6_transport_info {
	u8 protocol;
	unsigned int offset;
};

static inline struct ipv6_transport_info ipv6_move_to_transport(struct ipv6hdr *header) {
	//TODO
	while(ipv6_ext_hdr(header->nexthdr)) {

	}
	return struct ipv6_transport_info {
		.protocol = ;
		.offset = ;
	};
}

static inline bool check_l4_protocol(struct iphdr *l3_ip4_header, struct ipv6hdr *l3_ip6_header, bool direction, u8 protocol) {
	/* The transport layer does not has to be raw in order to encrypt ip payload */
	if (ENCRYPT == direction && IPPROTO_RAW == protocol)
		return true;
	if (l3_ip4_header != NULL)
		return l3_ip4_header->protocol == protocol;
	if (l3_ip6_header != NULL) {
		return ipv6_move_to_transport(l3_ip6_header).protocol == protocol; //FIXME: this is wrong
	}
}

int transform_skb(sk_buff *skb, const struct crypt_info *ti, bool direction, u8 protocol) {
	/* beginning and end of encryption/decryption */
	unsigned char *payload = NULL;
	unsigned char *tail = skb->tail;
	/* layer 3 headers */
	struct iphdr   *l3_ip4_header = NULL;
	struct ipv6hdr *l3_ip6_header = NULL;
	/* layer 4 headers */
	struct tcphdr       *l4_tcp_header = NULL;
	struct udphdr       *l4_udp_header = NULL;
	struct iphdr        *l4_ip4_header = NULL;
	struct ipv6hdr      *l4_ip6_header = NULL;
	struct gre_full_hdr *l4_gre_header = NULL;

	/* get layer 3 header */
	l3_ip4_header = (struct iphdr   *)skb_network_header(skb);
	l3_ip6_header = (struct ipv6hdr *)skb_network_header(skb);
	if (4 == l3_ip4_header->version)
		l3_ip6_header = NULL;
	else
		l3_ip4_header = NULL;

	/* validate layer 4 protocol */
	check_l4_protocol(l3_ip4_header, l3_ip6_header, direction, protocol);

	/* get layer 4 header and payload pointer */
	if (!skb_transport_header_was_set(skb)) {
		//FIXME: instead of reporting an error, we can actually set the transport header
		printk(KERN_ERR "shadowpayload: set transport header first\n");
		return -EINVAL;
	}
	switch (protocol) {
	case IPPROTO_RAW:
		payload = skb_transport_header(skb);
		break;
	case IPPROTO_TCP:
		l4_tcp_header = (struct tcphdr *)skb_transport_header(skb);
		payload = (unsigned char *)l4_tcp_header + l4_tcp_header->doff * 4;
		break;
	case IPPROTO_UDP:
		l4_udp_header = (struct l4_udp_header *)skb_transport_header(skb);
		payload = (unsigned char *)l4_udp_header + sizeof(struct udphdr);
		break;
	case IPPROTO_IPIP:
		l4_ip4_header = (struct iphdr *)skb_transport_header(skb);
		payload = (unsigned char *)l4_ip4_header + l4_ip4_header->ihl * 4;
		break;
	case IPPROTO_IPV6:
		l4_ip6_header = (struct ipv6hdr *)skb_transport_header(skb);
		payload = (unsigned char *)l4_ip6_header + ipv6_move_to_transport(l4_ip6_header).offset;
		break;
	case IPPROTO_GRE:
		l4_gre_header = (struct gre_full_hdr *)skb_transport_header(skb);
		payload = NULL; //TODO
		break;
	default:
		return -ENOTSUPP;
	}

	/* encrypt/decrypt payload */

	/* repair headers */
	switch(protocol) {
	case IPPROTO_RAW:
		break;
	case IPPROTO_TCP:
		break;
	case IPPROTO_UDP:
		break;
	case IPPROTO_IPIP:
		break;
	case IPPROTO_GRE:
		break;
	default:
		BUG();
	}
	return 0;
}
