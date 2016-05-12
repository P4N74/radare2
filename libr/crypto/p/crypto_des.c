/* radare - LGPL - Copyright 2015-2016 - pancake */

#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

struct des_state {
	ut64 key;
	int key_size;
};

static struct des_state st;
static int flag = 0;

static void des_encrypt(struct des_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut64 enc_text;
	memcpy (&enc_text, inbuf, 8);
	int i = 0;
	for (i = 1; i <= 16; i++) {
//		printf ("%ld\n",r_des_get_roundkey(state->key,i,1));
		ut64 kk = r_des_get_roundkey(state->key,i,1);
		ut64 kkk = ((((kk>>0)&0xff)<<56) | (((kk>>8)&0xff)<<48)  | (((kk>>16)&0xff)<<40) | (((kk>>24)&0xff)<<32) | (((kk>>32)&0xff)<<24) | (((kk>>40)&0xff)<<16) | (((kk>>48)&0xff)<<8) | (((kk>>56)&0xff)<<0) );
		printf ("%lx\n", (kkk >> 16) & 0x00ffffffffffffff);
		//memcpy(&kkk, kk, 8);
		enc_text = r_des_round (enc_text, (kkk >> 16) & 0x00ffffffffffffff);
	}
	memcpy (outbuf, &enc_text, 8);
	return;
}

static int des_set_key (RCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 64 / 8)) {
		return false;
	}
	ut64 key_ut64;
	memcpy (&key_ut64, key, 8);
	st.key = key_ut64 & 0xff;
	st.key = (st.key << 8) | ((key_ut64 >> 8) & 0xff);
	st.key = (st.key << 8) | ((key_ut64 >> 16) & 0xff);
	st.key = (st.key << 8) | ((key_ut64 >> 24) & 0xff);
	st.key = (st.key << 8) | ((key_ut64 >> 32) & 0xff);
	st.key = (st.key << 8) | ((key_ut64 >> 40) & 0xff);
	st.key = (st.key << 8) | ((key_ut64 >> 48) & 0xff);
	st.key = (st.key << 8) | ((key_ut64 >> 56) & 0xff);
	st.key_size = 8;
	flag = direction;
	return true;
}

static int des_get_key_size (RCrypto *cry) {
	return st.key_size;
}

static bool des_use (const char *algo) {
	return !strcmp (algo, "des");
}

#define BLOCK_SIZE 16

static int update (RCrypto *cry, const ut8 *buf, int len) {
	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len;
	const int blocks = size / BLOCK_SIZE;

	ut8 *const obuf = calloc (1, size);
	if (!obuf) return false;

	ut8 *const ibuf = calloc (1, size);
	if (!ibuf) {
		free (obuf);
		return false;
	}

	memset(ibuf, 0, size);
	memcpy (ibuf, buf, len);
	// Padding should start like 100000...
//	if (diff) {
//		ibuf[len] = 8; //0b1000;
//	}

	// printf("*** State:\n
	//         Key: %s\n
	//         key_size: %d\n
	//         columns: %d\n
	//         rounds: %d\n", st.key, st.key_size, st.columns, st.rounds);
	int i;
	if (flag == 0) {
//		for (i = 0; i < blocks; i++) {
			// printf("Block: %d\n", i);
//			des_encrypt (&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
//			printf ("%x\n" des_encrypt 
			// printf("Block finished: %d\n", i);
//		}
		des_encrypt (&st, ibuf, obuf);
//		printf ("%s\n", obuf);
	} else if (flag == 1) {
		for (i = 0; i < blocks; i++) {
//			des_decrypt (&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
		}
	}

	// printf("%128s\n", obuf);

	r_crypto_append (cry, obuf, size);
	free (obuf);
	free (ibuf);
	return 0;
}

static int final (RCrypto *cry, const ut8 *buf, int len) {
	return update (cry, buf, len);
}

RCryptoPlugin r_crypto_plugin_des = { 
	.name = "des",
	.set_key = des_set_key,
	.get_key_size = des_get_key_size,
	.use = des_use,
	.update = update,
	.final = final
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = { 
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_des,
	.version = R2_VERSION
};
#endif
