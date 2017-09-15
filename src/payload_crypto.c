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

static struct transport_info {
	bool is_fragment;
	u8 protocol;
	unsigned char *transport_header;
};

static inline struct transport_info move_to_transport(struct iphdr *header4, struct ipv6hdr *header6) {
	if (header4) {
		u8 protocol = header4->protocol;
		if (header6) BUG();
		return struct transport_info {
			.is_fragment = ip_is_fragment(header4),
			.protocol = protocol,
			.transport_header = (unsigned char *)header4 + header4->ihl * 4,
		};
	}

	if (header6) {
		bool is_fragment = false;
		u8 nexthdr = header6->nexthdr;
		u8 *header = (u8 *)header6 + sizeof(struct ipv6hdr);

		while(ipv6_ext_hdr(nexthdr) && nexthdr != NEXTHDR_AUTH && nexthdr != NEXTHDR_NONE) {
			struct ipv6_opt_hdr *hp = (struct ipv6_opt_hdr *) header;
			int hdrlen;  /* header length in octets */

			switch(nexthdr) {
			case NEXTHDR_HOP:
			case NEXTHDR_DEST:
			case NEXTHDR_ROUTING:
				hdrlen = ipv6_optlen(hp);
				break;
			case NEXTHDR_FRAGMENT:
				is_fragment = true;
				hdrlen = 8;
				break;
			}

			nexthdr = hp->nexthdr
			header += hdrlen / 2;
		}
		return struct transport_info {
			.is_fragment = is_fragment,
			.protocol = nexthdr,
			.transport_header = header,
		};
	}

	BUG();
}

static inline bool check_l4_protocol(const struct transport_info *ti, crypto_option opt) {
	if (DECRYPT_NETWORK == opt && IPPROTO_RAW != ti->protocol) {
		printk(KERN_ERR "shadowpayload: protocol must be raw in order to decrypt network layer payload.");
		return false;
	}
	if ((ENCRYPT_TRANSPORT == opt || DECRYPT_TRANSPORT == opt) && IPPROTO_RAW == ti->protocol) {
		printk(KERN_ERR "shadowpayload: raw data does not have a transport layer.");
		return false;
	}
	if (ti->is_fragment && IPPROTO_RAW != ti->protocol) {
		printk(KERN_ERR "shadowpayload: transport layer encryption/decryption does not support fragmented packet.");
		return false;
	}
	return true;
}

int transform_skb(sk_buff *skb, const struct crypto_info *ci, crypto_option opt) {
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

	/* get layer 4 header and payload pointer */
	struct transport_info ti = move_to_transport(l3_ip4_header, l3_ip6_header);
	if (!check_l4_protocol(&ti, opt))
		return -EINVAL;
	switch (ti.protocol) {
	case IPPROTO_RAW:
		payload = ti.transport_header;
		break;
	case IPPROTO_TCP:
		l4_tcp_header = (struct tcphdr *)ti.transport_header;
		payload = (unsigned char *)l4_tcp_header + l4_tcp_header->doff * 4;
		break;
	case IPPROTO_UDP:
		l4_udp_header = (struct l4_udp_header *)ti.transport_header;
		payload = (unsigned char *)l4_udp_header + sizeof(struct udphdr);
		break;
	case IPPROTO_IPIP:
		l4_ip4_header = (struct iphdr *)ti.transport_header;
		payload = move_to_transport(l4_ip4_header, NULL).transport_header;
		break;
	case IPPROTO_IPV6:
		l4_ip6_header = (struct ipv6hdr *)ti.transport_header;
		payload = move_to_transport(NULL, l4_ip6_header).transport_header;
		break;
	case IPPROTO_GRE:
		l4_gre_header = (struct gre_full_hdr *)ti.transport_header;
		payload = NULL; //TODO
		break;
	default:
		return -ENOTSUPP;
	}

	/* encrypt/decrypt payload */

	/* repair headers */
	// disallow fragmentation
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
