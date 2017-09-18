#ifndef _AEAD_API_H
#define _AEAD_API_H

#include <linux/crypto.h>

#define CCM_AAD_LEN	32

struct crypto_aead *aead_key_setup_encrypt(const u8 key[],
						    size_t key_len,
						    size_t tag_len);
int aead_encrypt(struct crypto_aead *tfm, u8 *b_0, u8 *aad, size_t aad_len,
				 u8 *data, size_t data_len, u8 *tag, size_t tag_len);
int aead_decrypt(struct crypto_aead *tfm, u8 *b_0, u8 *aad, size_t aad_len,
				 u8 *data, size_t data_len, u8 *tag, size_t tag_len);
void aead_key_free(struct crypto_aead *tfm);

#endif /* _AEAD_API_H */
