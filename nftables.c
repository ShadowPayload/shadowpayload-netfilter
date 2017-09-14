#include <net/netfilter/nf_tables.h>
#include <linux/tcp.h>
#include "shadowpayload.h"

#define SHADOWPAYLOAD_TEXT_SIZE 128
struct nft_shadowpayload {
	char text[SHADOWPAYLOAD_TEXT_SIZE];
	int len;
};

static inline bool match_packet(struct nft_shadowpayload *priv, struct sk_buff *skb) {
	struct tcphdr *tcph = tcp_hdr(skb);
	char *user_data = (char *)((char *)tcph + (tcph->doff * 4));
	char *tail = skb_tail_pointer(skb);
	char *p;
	/* TODO: do something */
}

static const struct nla_policy nft_shadowpayload_policy[NFTA_SHADOWPAYLOAD_MAX + 1] = {
	[NFTA_SHADOWPAYLOAD_TEXT]		= { .type = NLA_STRING, .len = SHADOWPAYLOAD_TEXT_SIZE },
};

static void nft_shadowpayload_eval(const struct nft_expr *expr, struct nft_regs *regs, const struct nft_pktinfo *pkt) {
	struct nft_shadowpayload *priv = nft_expr_priv(expr);
	struct sk_buff *skb = pkt->skb;
	if(match_packet(priv, skb))
		regs->verdict.code = NFT_CONTINUE;
	else
		regs->verdict.code = NFT_BREAK;
}

static int nft_shadowpayload_init(const struct nft_ctx *ctx, const struct nft_expr *expr, const struct nlattr * const tb[]) {
	struct nft_shadowpayload *priv = nft_expr_priv(expr);
	if (tb[NFTA_SHADOWPAYLOAD_TEXT] == NULL)
		return -EINVAL;
	nla_strlcpy(priv->text, tb[NFTA_SHADOWPAYLOAD_TEXT], SHADOWPAYLOAD_TEXT_SIZE);
	priv->len = strlen(priv->text);
	return 0;
}

static int nft_shadowpayload_dump(struct sk_buff *skb, const struct nft_expr *expr) {
	const struct nft_shadowpayload *priv = nft_expr_priv(expr);
	if (nla_put_string(skb, NFTA_SHADOWPAYLOAD_TEXT, priv->text))
		return -1;
	return 0;
}

static struct nft_expr_type nft_shadowpayload_type;
static const struct nft_expr_ops nft_shadowpayload_op = {
	.eval = nft_shadowpayload_eval,
	.size = sizeof(struct nft_shadowpayload),
	.init = nft_shadowpayload_init,
	.dump = nft_shadowpayload_dump,
	.type = &nft_shadowpayload_type,
};
static struct nft_expr_type nft_shadowpayload_type __read_mostly =  {
	.ops = &nft_shadowpayload_op,
	.name = "shadowpayload",
	.owner = THIS_MODULE,
	.policy = nft_shadowpayload_policy,
	.maxattr = NFTA_shadowpayload_MAX,
};

static int __init nft_shadowpayload_module_init(void) {
	return nft_register_expr(&nft_shadowpayload_type);
}
static void __exit nft_shadowpayload_module_exit(void) {
	nft_unregister_expr(&nft_shadowpayload_type);
}

module_init(nft_shadowpayload_module_init);
module_exit(nft_shadowpayload_module_exit);

MODULE_AUTHOR("Shadow Payload");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Shadow payload");
