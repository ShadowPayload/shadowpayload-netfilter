#ifndef _SHADOWPAYLOAD_H
#define _SHADOWPAYLOAD_H

enum nft_shadowpayload_attributes {
	NFTA_SHADOWPAYLOAD_UNSPEC,
	NFTA_SHADOWPAYLOAD_TEXT,
	__NFTA_SHADOWPAYLOAD_MAX,
};

#define NFTA_SHADOWPAYLOAD_MAX (__NFTA_SHADOWPAYLOAD_MAX - 1)

#endif /* _SHADOWPAYLOAD_H */
