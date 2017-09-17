#ifndef _PAYLOAD_CRYPTO_H
#define _PAYLOAD_CRYPTO_H

struct crypto_options {
	/* direction, i.e. encrypt or decrypt */
	bool is_encrypt;  /* true: encrypt, false: decrypt */

	/* the layer that payload transformation happens */
	bool on_network;  /* true: network layer , false: transport layer */

	/* For IP, IPIP and GRE, once its payload is encrypted, the encrypted payload
	 * can no longer be interpreted as the original protocol as in its header. If
	 * this is the case, the following options applies:
	 *
	 * @modify_protocol: whether to change the protocol field in the header
	 * to a new value (for example, change the ip header's protocol field from
	 * TCP to RAW). If this option is turned on, then the old protocol field will
	 * be prepended before the payload and encrypted together, as shown in the
	 * example below:
	 * [ip hdr][tcp hdr][data] --> [new ip hdr][original protocol][tcp hdr][data]
	 *                         --> [new ip hdr][---------encrypted data---------]
	 *
	 * @new_ip_protocol, @new_gre_protocol: the new value of protocol field in
	 * header. This is only valid when @modify_protocol is set to true.
	 *
	 * @insert_fake_header: whether to prepend a fake header before the encrypted
	 * data. The type of this header will be kept consistent with the protocol
	 * in upper layer header field. As shown in the following example:
	 * [ip hdr][tcp hdr][data] --> [ip hdr][fake tcp hdr][tcp hdr][data]
	 *                         --> [ip hdr][fake tcp hdr][--encrypted--]
	 * If both @modify_protocol and @insert_fake_header are set, then things will
	 * work as the example below:
	 * [ip hdr][ip hdr][data] --> [new ip hdr][original protocol][ip hdr][data]
	 * --> [new ip hdr][fake TCP hdr][original protocol][ip hdr][data]
	 * --> [new ip hdr][fake TCP hdr][--------encrypted data---------]
	 *
	 * @fake_header: pointer towards the fake header
	 */
	bool modify_protocol;
	union {
		__u8 new_ip_protocol;
		__be16 new_gre_protocol;
	};
	bool insert_fake_header;
	void *fake_header;
};

int transform_skb(sk_buff *skb, const struct crypto_info *opt);

#endif
