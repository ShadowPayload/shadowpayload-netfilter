#include <include/linux/skbuff.h>
#include <include/uapi/linux/in.h>
#include <include/linux/errno.h>
#include <include/asm-generic/bug.h>
#include "payload_crypto.h"

int transform_skb(sk_buff *skb, const struct crypt_info *ti, bool direction, unsigned short protocol) {
	unsigned char *payload;
	unsigned char *tail = skb->tail;
	/* Get IP header */
	/* Get payload pointer */
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
		goto unsupported;
	}
	/* Encrypt/Decrypt payload */
	/* Repair payload header */
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

unsupported:
	return -ENOTSUPP;
}
