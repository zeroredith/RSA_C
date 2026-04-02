#ifndef CHACHA20_H
#define CHACHA20_H


#ifndef TYPES_H
	#include "types.h"
#else
	#include <stdint.h>
	typedef uint64_t u64;
	typedef uint32_t u32;
	typedef uint8_t  u8;
#endif

#define rotate_left(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define quarter_round(a, b, c, d) \
	a += b; d ^= a; d = rotate_left(d, 16); \
	c += d; b ^= c; b = rotate_left(b, 12); \
	a += b; d ^= a; d = rotate_left(d, 8); \
	c += d; b ^= c; b = rotate_left(b, 7);

void
chacha20_block(u32 state[16], u8 output[64]) {
	u32 x[16];
	for (u32 i = 0; i < 16; i++) x[i] = state[i];

	for (u32 i = 0; i < 10; i++) {
		// column rounds
		quarter_round(x[0], x[4], x[8],  x[12]);
		quarter_round(x[1], x[5], x[9],  x[13]);
		quarter_round(x[2], x[6], x[10], x[14]);
		quarter_round(x[3], x[7], x[11], x[15]);
		// diagonal rounds
		quarter_round(x[0], x[5], x[10], x[15]);
		quarter_round(x[1], x[6], x[11], x[12]);
		quarter_round(x[2], x[7], x[8],  x[13]);
		quarter_round(x[3], x[4], x[9],  x[14]);
	}

	for (u32 i = 0; i < 16; i++) x[i] += state[i];
	// little endian
	for (u32 i = 0; i < 16; i++) {
		output[i*4+0] = x[i] & 0xff;
		output[i*4+1] = (x[i] >> 8) & 0xff;
		output[i*4+2] = (x[i] >> 16) & 0xff;
		output[i*4+3] = (x[i] >> 24) & 0xff;
	}
}

#define chacha20_decrypt_alloc chacha20_encrypt_alloc
u8*
chacha20_encrypt_alloc(u8* input, u64 count, u32 key[8], u32 nonce[3]) {
	u8* output = malloc(count); // TODO: change it to be able to use your own allocator
	// constant of 4 words of 32 bytes [expa|nd 3|2-by|te k] used in standard chacha20
	u32 state[16] = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
		0,
		nonce[0], nonce[1], nonce[2]
	};

	u8 keystream[64];
	u64 i = 0;
	while (i < count) {
		chacha20_block(state, keystream);
		state[12]++;
		u64 block_len = (count - i) < 64 ? (count - i) : 64;
		for (u64 j = 0; j < block_len; j++)
		output[i + j] = input[i + j] ^ keystream[j];
		i += block_len;
	}
	return output;
}

void
chacha20_generate_key(u32 key[8], u32 nonce[3]) {
	// NOTE: using srand with time is not the best secure method to generate keys
	// Probably you will want to make your own rand() function based in the machine it gonna run on.
	srand((u64)time(null) ^ (u64)clock());
	for (int i = 0; i < 8; i++) key[i] = ((u32)rand() << 16) ^ rand();
	for (int i = 0; i < 3; i++) nonce[i] = ((u32)rand() << 16) ^ rand();
}



typedef struct ChaCha20_Message ChaCha20_Message;
struct ChaCha20_Message {
	u32 nonce[3];
	u64 count;
	u8* data;
};


ChaCha20_Message
chacha20_encrypt_msg(u8* input, u64 count, u32 key[8]) {
	ChaCha20_Message msg;
	u32 nonce[3];
	for (int i = 0; i < 3; i++) nonce[i] = ((u32)rand() << 16) ^ rand();

	msg.nonce[0] = nonce[0];
	msg.nonce[1] = nonce[1];
	msg.nonce[2] = nonce[2];
	msg.count  = count;
	msg.data = chacha20_encrypt_alloc(input, count, key, nonce);
	return msg;
}

ChaCha20_Message
chacha20_decrypt_msg(ChaCha20_Message msg, u32 key[8]) {
	ChaCha20_Message out;
	out.count  = msg.count;
	out.data = chacha20_decrypt_alloc(msg.data, msg.count, key, msg.nonce);
	return out;
}


#endif

#ifdef CHACHA_MAIN

int
connect_chacha_test(int argc, char *argv[]) {
	char* try_message = argv[1];
	u32 key[8];
	u32 first_nonce[3];
	chacha20_generate_key(key, first_nonce);

	ChaCha20_Message encrypted_msg = chacha20_encrypt_msg(try_message, strlen(try_message), key);
	for(int i= 0; i < encrypted_msg.count; i++) printf("%d", encrypted_msg.data[i]);

	ChaCha20_Message decrypted_msg = chacha20_decrypt_msg(encrypted_msg, key);
	printf("\n%.*s", decrypted_msg.count, decrypted_msg.data);
	return 0;
}

int main(int argc, char *argv[]) {
	return connect_chacha_test();
}

#endif