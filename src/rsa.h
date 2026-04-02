#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "types.h"
#include "typedef_gen.h"
#include "base.c"
#include "arrays.c"
#include "chacha20.h"

#define _PRIME_NUMBERS_SIZE 2048

internal inline void
mpz_rand_num(mpz_t prime, u32 bits)
{
	mpz_t rand_num;
	gmp_randstate_t state;

	mpz_init(rand_num);
	gmp_randinit_default(state);

	u64 seed = (u64)time(null) ^ (u64)clock();
	gmp_randseed_ui(state, seed);

	mpz_urandomb(rand_num, state, bits);

	mpz_nextprime(prime, rand_num);

	mpz_clear(rand_num);
	gmp_randclear(state);
}

internal inline void
carmichael(mpz_t result, mpz_t prime1, mpz_t prime2)
{
	/*
    Since n = pq
    Carmichael_funciton(n) = lem(Carmichael_funciton(prime1), Carmichael_funciton(prime2))
    p & q are prime so lem(p-1,q-1)
    */
	mpz_t prime1_minus_one, prime2_minus_one, gcd;
	mpz_inits(prime1_minus_one, prime2_minus_one, gcd, null);

	mpz_sub_ui(prime1_minus_one, prime1, 1);
	mpz_sub_ui(prime2_minus_one, prime2, 1);

	mpz_gcd(gcd, prime1_minus_one, prime2_minus_one);
	mpz_mul(result, prime1_minus_one, prime2_minus_one);
	mpz_div(result, result, gcd);

	mpz_clear(prime1_minus_one);
	mpz_clear(prime2_minus_one);
}

internal inline void
generate_keys(mpz_t keys[3])
{
	mpz_t prime1, prime2, modulus, carmichael_n, public, public_check, private;

	mpz_inits(prime1, prime2, modulus, carmichael_n, public, public_check, private, null);

	mpz_init_set_ui(public, 65537);

	mpz_rand_num(prime1, _PRIME_NUMBERS_SIZE);
	mpz_rand_num(prime2, _PRIME_NUMBERS_SIZE);

	mpz_mul(modulus, prime1, prime2);

	carmichael(carmichael_n, prime1, prime2);

	mpz_gcd(public_check, carmichael_n, public);
	while(mpz_cmp_ui(public_check, 1)!=0)
	{
		mpz_gcd(public_check, carmichael_n, public);
		mpz_nextprime(public, public);
	}

	mpz_invert(private, public, carmichael_n);

	mpz_init_set(keys[0], modulus);
	mpz_init_set(keys[1], public);
	mpz_init_set(keys[2], private);

	mpz_clears(prime1, prime2, private, modulus, carmichael_n, public, public_check, null);
}


typedef struct RSA_Keys
{
	mpz_t modulus; // n
	mpz_t public;  // e
	mpz_t private; // d

} RSA_Keys;

internal inline void
init_rsa_keys(RSA_Keys *keys)
{
	mpz_inits(keys->modulus, keys->public, keys->private, null);
}

internal inline void
clear_rsa_keys(RSA_Keys *keys)
{
	mpz_clears(keys->modulus, keys->public, keys->private, null);
}

internal inline void
get_rsa_keys(RSA_Keys *keys)
{
	mpz_t temp_keys[3];
	mpz_inits(temp_keys[0], temp_keys[1], temp_keys[2], null);

	generate_keys(temp_keys);

	mpz_set(keys->modulus, temp_keys[0]);
	mpz_set(keys->public, temp_keys[1]);
	mpz_set(keys->private, temp_keys[2]);

	mpz_clear(temp_keys[0]);
	mpz_clear(temp_keys[1]);
	mpz_clear(temp_keys[2]);
}

mpz_t*
encrypt_message(char *message, u64 len, RSA_Keys *keys) {
	mpz_t *encrypted = (mpz_t*)malloc(len * sizeof(mpz_t));

	for (u64 i = 0; i < len; i++) {
		mpz_init(encrypted[i]);
		mpz_t m;
		mpz_init_set_ui(m, (u8)message[i]);
		mpz_powm(encrypted[i], m, keys->public, keys->modulus);
		mpz_clear(m);
	}

	return encrypted;
}

char*
decrypt_message(mpz_t *encrypted, u64 len, RSA_Keys *keys) {
	char *decrypted = (char*)malloc((len + 1) * sizeof(char));

	for (u64 i = 0; i < len; i++) {
		mpz_t m;
		mpz_init(m);
		mpz_powm(m, encrypted[i], keys->private, keys->modulus);
		u64 val = mpz_get_ui(m);
		decrypted[i] = (char)val;
		mpz_clear(m);
	}
	decrypted[len] = '\0';

	return decrypted;
}

void
encrypt_data(mpz_t result, u8* data, u64 len, RSA_Keys keys) {
	mpz_t m;
	mpz_init(m);
	mpz_import(m, len, 1, sizeof(u8), 0, 0, data);
	mpz_powm(result, m, keys.public, keys.modulus);
  mpz_clear(m);
}

void
sign_data(mpz_t result, u8* data, u64 len, RSA_Keys keys) {
	mpz_t m;
	mpz_init(m);
	mpz_import(m, len, 1, sizeof(u8), 0, 0, data);
	mpz_powm(result, m, keys.private, keys.modulus);
  mpz_clear(m);
}

void
encrypt_mpz(mpz_t result, mpz_t data, RSA_Keys keys) {
	mpz_powm(result, data, keys.public, keys.modulus);
}

void
sign_mpz(mpz_t result, mpz_t data, RSA_Keys keys) {
	mpz_powm(result, data, keys.private, keys.modulus);
}

// decrypt public use private keys to decrypt, and vice versa.
void
design_data(mpz_t result, mpz_t encrypted, RSA_Keys keys) {
  mpz_powm(result, encrypted, keys.public, keys.modulus);
}

void
decrypt_mpz(mpz_t result, mpz_t encrypted, RSA_Keys keys) {
  mpz_powm(result, encrypted, keys.private, keys.modulus);
}

char*
mpz_to_string(mpz_t data, u64* out_count) {
  u64 count = 0;
  u8* bytes;
  bytes = mpz_export(null, &count, 1, sizeof(u8), 0, 0, data);
	*out_count = count;
  return bytes;
}

typedef struct Array_u8 Array_u8;
struct Array_u8 {
	u64 count;
	u8* data;
};

typedef struct Data_And_Signature Data_And_Signature;
struct Data_And_Signature {
	Array_u8 data;
	Array_u8 signature;
};

// NOTE: al serializar no estamos teniendo en cuenta el endianess que se esta utilizando.
// Es posible que no funcione con distintos endianess.
Array_u8
sign_and_encrypt(RSA_Keys keys_alice, RSA_Keys keys_bob, Array_u8 data) {
	mpz_t signature, encrypted_data_mpz, tmp_d;
	mpz_inits(tmp_d, signature, encrypted_data_mpz, null);

	sign_data(signature, data.data, data.count, keys_alice);

	Array_u8 signature_exported = {0};
	Array_u8 packed = {0};
	Array_u8 encrypted_data = {0};

	signature_exported.data = mpz_export(null, &signature_exported.count, 1, sizeof(u8), 0, 0, signature);


	encrypt_data(encrypted_data_mpz, data.data, data.count, keys_bob);
	encrypted_data.data = mpz_export(null, &encrypted_data.count, 1, sizeof(u8), 0, 0, encrypted_data_mpz);

	packed.count = 16 + encrypted_data.count + signature_exported.count;
	packed.data = malloc(packed.count);

	memcpy(packed.data, &signature_exported.count, 8);
	memcpy(packed.data + 8, &encrypted_data.count, 8);
	memcpy(packed.data + 16, signature_exported.data, signature_exported.count);
	memcpy(packed.data + 16 + signature_exported.count, encrypted_data.data, encrypted_data.count);

	return packed;
}

Data_And_Signature
decrypt(RSA_Keys keys_alice, RSA_Keys keys_bob, u8* encrypted_data, u64 encrypted_count) {
	mpz_t decrypted_mpz, encrypted_mpz, sign_mpz, designed_mpz;
	mpz_inits(decrypted_mpz, encrypted_mpz, sign_mpz, designed_mpz, null);

	mpz_import(encrypted_mpz, *(u64*)(encrypted_data+8), 1, sizeof(u8), 0, 0, encrypted_data + 16 + *(u64*)encrypted_data);
	decrypt_mpz(decrypted_mpz, encrypted_mpz, keys_bob);

	Array_u8 decrypted = {0};
	decrypted.data = mpz_export(null, &decrypted.count, 1, sizeof(u8), 0, 0, decrypted_mpz);

	mpz_import(designed_mpz, *(u64*)encrypted_data, 1, sizeof(u8), 0, 0, encrypted_data+16);
	design_data(designed_mpz, designed_mpz, keys_alice);
	Array_u8 designed = {0};
	designed.data = mpz_export(null, &designed.count, 1, sizeof(u8), 0, 0, designed_mpz);
	return (Data_And_Signature){.data = decrypted, .signature = designed};
}

// :tests
#ifndef RSA_H_IMPLEMENTATION

static char* buffer_logs[256];
static u64 buffer_logs_count = 0;

void
_rsa_log(char* text) {
	char* new_string = malloc(strlen(text));
	buffer_logs[buffer_logs_count] = new_string;
	buffer_logs_count += 1;
}

void
_print_logs() {
	for (int i = 0; i < buffer_logs_count; i++) {
		printf("\nLOG:[%s]\n", buffer_logs[i]);
	}
}

bool
encrypt_decrypt_rsa_test(char *arg) {
	RSA_Keys keys_alice;
	RSA_Keys keys_bob;

	init_rsa_keys(&keys_alice);
	get_rsa_keys(&keys_alice);

	init_rsa_keys(&keys_bob);
	get_rsa_keys(&keys_bob);

	u8* packed_and_encrypted_data;
	u64 packed_and_encrypted_count;

	Array_u8 try_string_u8 = {.data = arg, .count = strlen(arg)};
	Array_u8 encrypted = sign_and_encrypt(keys_alice, keys_bob, try_string_u8);

	// sending ...

	Data_And_Signature data_and_signature = decrypt(keys_alice, keys_bob, encrypted.data, encrypted.count);
	fflush(stdout);
	if (data_and_signature.data.count != data_and_signature.signature.count || memcmp(data_and_signature.data.data, data_and_signature.signature.data, data_and_signature.data.count) != 0) {
		_rsa_log("signature does not coincide in encrypt_decrypt_rsa_test\n");
		return false;
	}
	return true;
}

bool
connect_chacha_with_rsa_test(char* arg) {
	// printf("====== connect_chacha_with_rsa_test ====== \n");
	RSA_Keys keys_rsa_alice;
	RSA_Keys keys_rsa_bob;

	init_rsa_keys(&keys_rsa_alice);
	get_rsa_keys(&keys_rsa_alice);

	init_rsa_keys(&keys_rsa_bob);
	get_rsa_keys(&keys_rsa_bob);

	mpz_t result;
	mpz_init(result);

	u32 chacha_key[8];
	u32 first_nonce[3];
	chacha20_generate_key(chacha_key, first_nonce);

	// packing the key and the nonce

	u32 chacha_key_and_nonce[11];
	memcpy(chacha_key_and_nonce, chacha_key, sizeof(u32) * 8);
	memcpy(chacha_key_and_nonce + 8, first_nonce, sizeof(u32) * 3);

	Array_u8 chacha_key_and_nonce_array = {.data = (u8*)chacha_key_and_nonce, .count = sizeof(u32) * 11};

	Array_u8 encrypted_key = sign_and_encrypt(keys_rsa_alice, keys_rsa_bob, chacha_key_and_nonce_array);

	// sending ...

	Data_And_Signature decrypted_key = decrypt(keys_rsa_alice, keys_rsa_bob, encrypted_key.data, encrypted_key.count);

	if (decrypted_key.data.count != decrypted_key.signature.count || memcmp(decrypted_key.data.data, decrypted_key.signature.data, decrypted_key.data.count) != 0) {
		_rsa_log("signature does not coincide in connect_chacha_with_rsa_test\n");
		return false;
	}

	u32 chacha_key_and_nonce_received[11];
	for (int i = 0; i < 11; i++) chacha_key_and_nonce_received[i] = ((u32*)decrypted_key.data.data)[i];

	// printf("message [%s]\n", arg);
	ChaCha20_Message encrypted_message = chacha20_encrypt_msg(arg, strlen(arg), chacha_key_and_nonce_received);

	// sending ...

	ChaCha20_Message decrypted_message = chacha20_decrypt_msg(encrypted_message, chacha_key_and_nonce_received);

	// printf("encrypted message recieved [%.*s]\n", decrypted_message.count, decrypted_message.data);
	fflush(stdout);
	return true;
}

#define ANSI_COLOR_RED          "\x1b[31m"
#define ANSI_COLOR_GREEN        "\x1b[32m"
#define ANSI_RESET_ALL          "\x1b[0m"

void log_test(bool result, char* function_name) {
	if (!result) printf(ANSI_COLOR_RED "\nFAILED" ANSI_RESET_ALL " %s\n", function_name);
	if (result) printf(ANSI_COLOR_GREEN "\nPASSED" ANSI_RESET_ALL " %s\n", function_name);
	_print_logs();
}

int
main(void) {
	char* arg = "abracadabra";
	for (int i = 0; i < 5; i++) {
		log_test(encrypt_decrypt_rsa_test(arg), "encrypt_decrypt_rsa_test");
		log_test(connect_chacha_with_rsa_test(arg), "connect_chacha_with_rsa_test");
	}


}
#endif
