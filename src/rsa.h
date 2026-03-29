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

	mpz_init(prime1_minus_one);
	mpz_init(prime2_minus_one);
	mpz_init(gcd);


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

	mpz_init(prime1);
	mpz_init(prime2);
	mpz_init(modulus);
	mpz_init(carmichael_n);
	mpz_init(private);
	mpz_init(public_check);

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

	mpz_clear(prime1);
	mpz_clear(prime2);
	mpz_clear(private);
	mpz_clear(modulus);
	mpz_clear(carmichael_n);
	mpz_clear(public);
	mpz_clear(public_check);
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
	mpz_init(keys->modulus);
	mpz_init(keys->public);
	mpz_init(keys->private);
}

internal inline void
clear_rsa_keys(RSA_Keys *keys)
{
	mpz_clear(keys->modulus);
	mpz_clear(keys->public);
	mpz_clear(keys->private);
}

internal inline void
get_rsa_keys(RSA_Keys *keys)
{
	mpz_t temp_keys[3];
	mpz_init(temp_keys[0]);
	mpz_init(temp_keys[1]);
	mpz_init(temp_keys[2]);

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

typedef struct Public_Key Public_Key;
struct Public_Key {
  mpz_t modulus;
  mpz_t public;
};

Public_Key
export_public_key(RSA_Keys keys) {
	Public_Key key_out;
	mpz_init_set(key_out.modulus, keys.modulus);
	mpz_init_set(key_out.public,  keys.public);
	return key_out;
}

int
command_line(int argc, char* argv[]) {
	if(argc != 2) {
		printf("Error: argument needed\nUse: <rsa> <text to encrypt>\n");
		exit(0);
	}

	clock_t start = clock();

	RSA_Keys keys;
	init_rsa_keys(&keys);

	get_rsa_keys(&keys);
	clock_t end = clock();
	f64 time_taken = ((f64)(end - start)) / CLOCKS_PER_SEC;
	f64 t1 = time_taken;

	u64 len = strlen(argv[1]);

	mpz_t encrypted;
	mpz_t decrypted;
	mpz_init(encrypted);
	mpz_init(decrypted);

	start = clock();

	encrypt_data(encrypted, argv[1], len, keys);

	end = clock();
	time_taken = ((f64)(end - start)) / CLOCKS_PER_SEC;
	f64 t2 = time_taken;

	start = clock();
	design_data(decrypted, encrypted, keys);
	end = clock();
	time_taken = ((f64)(end - start)) / CLOCKS_PER_SEC;

	u64 count = 0;
	char* decrypted_str = mpz_to_string(decrypted, &count);
	if (strncmp(decrypted_str, argv[1], len) != 0) printf("\n   ERROR len command_line \n ");
	if (strncmp(decrypted_str, argv[1], count) != 0) printf("\n ERROR count command_line \n ");

	Public_Key public_key = export_public_key(keys);
	mpz_clear(encrypted);
	clear_rsa_keys(&keys);

	return 0;
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
sign_pack_and_encrypt(RSA_Keys keys_alice, RSA_Keys keys_bob, Array_u8 data) {
	mpz_t signature, encrypted_data_mpz;

	mpz_t tmp_d;
	mpz_init(tmp_d);

	mpz_init(signature);
	mpz_init(encrypted_data_mpz);

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
unpack_decrypt_and_check_signature(RSA_Keys keys_alice, RSA_Keys keys_bob, u8* encrypted_data, u64 encrypted_count) {
	mpz_t decrypted_mpz;
	mpz_t encrypted_mpz;
	mpz_t sign_mpz;
	mpz_t designed_mpz;
	mpz_init(decrypted_mpz);
	mpz_init(designed_mpz);
	mpz_init(encrypted_mpz);
	mpz_init(sign_mpz);

	mpz_import(encrypted_mpz, *(u64*)(encrypted_data+8), 1, sizeof(u8), 0, 0, encrypted_data + 16 + *(u64*)encrypted_data);
	decrypt_mpz(decrypted_mpz, encrypted_mpz, keys_bob);

	Array_u8 decrypted = {0};
	decrypted.data = mpz_export(null, &decrypted.count, 1, sizeof(u8), 0, 0, decrypted_mpz);
	printf("decrypted[%.*s] count = %d\n", decrypted.count, decrypted.data, decrypted.count);

	mpz_import(designed_mpz, *(u64*)encrypted_data, 1, sizeof(u8), 0, 0, encrypted_data+16);
	design_data(designed_mpz, designed_mpz, keys_alice);
	Array_u8 designed = {0};
	designed.data = mpz_export(null, &designed.count, 1, sizeof(u8), 0, 0, designed_mpz);
	printf("designed[%.*s]\n", designed.count, designed.data);
	return (Data_And_Signature){.data = decrypted, .signature = designed};
}

int
encrypt_decrypt_rsa_test(char *argv[]) {
	printf("\n======== encrypt_decrypt_rsa_test ========\n");
	RSA_Keys keys_alice;
	RSA_Keys keys_bob;

	init_rsa_keys(&keys_alice);
	get_rsa_keys(&keys_alice);

	init_rsa_keys(&keys_bob);
	get_rsa_keys(&keys_bob);

	char* try_string = argv[1];

	u8* packed_and_encrypted_data;
	u64 packed_and_encrypted_count;

	Array_u8 try_string_u8 = {.data = try_string, .count = strlen(try_string)};
	Array_u8 encrypted = sign_pack_and_encrypt(keys_alice, keys_bob, try_string_u8);

	// sending ...

	Data_And_Signature data_and_signature = unpack_decrypt_and_check_signature(keys_alice, keys_bob, encrypted.data, encrypted.count);
	fflush(stdout);
	if (data_and_signature.data.count != data_and_signature.signature.count) return 0;
	else if (memcmp(data_and_signature.data.data, data_and_signature.signature.data, data_and_signature.data.count) == 0) return 1;
	else return 0;
}

int
connect_test(int argc, char *argv[]) {
	printf("======== connect_test ========\n");
	RSA_Keys keys_alice;
	RSA_Keys keys_bob;

	init_rsa_keys(&keys_alice);
	get_rsa_keys(&keys_alice);

	init_rsa_keys(&keys_bob);
	get_rsa_keys(&keys_bob);

	char* try_message = argv[1];

	mpz_t result;
	mpz_init(result);

	// alice encrypt with her own private keys and bob public keys
	sign_data(result, try_message, strlen(try_message), keys_alice);
	encrypt_mpz(result, result, keys_bob);

	// bob decrypt

	design_data(result, result, keys_bob);
	decrypt_mpz(result, result, keys_alice);

	// Array_u8 bytes = mpz_to_string(result);
	// printf("\n\n%.*s\n\n", bytes.count, bytes.data);
	// gmp_printf("Decrypted: %s\n", result_string);

	// if(strlen(try_message) != bytes.count) {
	// 	printf("\ntry_message [%s], result [%s]\n", try_message, result);
	// }
	// assert(strncmp(try_message, mpz_to_string(result), strlen(try_message)) == 0);
	fflush(stdout);
 	printf("================================\n");
  return 0;
}

int
connect_chacha_with_rsa_test(int argc, char *argv[]) {
	printf("====== connect_chacha_with_rsa_test ====== \n");
	RSA_Keys keys_rsa_alice;
	RSA_Keys keys_rsa_bob;

	init_rsa_keys(&keys_rsa_alice);
	get_rsa_keys(&keys_rsa_alice);

	init_rsa_keys(&keys_rsa_bob);
	get_rsa_keys(&keys_rsa_bob);

	mpz_t result;
	mpz_init(result);

	char* try_message = argv[1];
	u32 chacha_key[8];
	u32 first_nonce[3];
	chacha20_generate_key(chacha_key, first_nonce);

	// packing the key and the nonce

	u32 chacha_key_and_nonce[11];
	memcpy(chacha_key_and_nonce, chacha_key, sizeof(u32) * 8);
	memcpy(chacha_key_and_nonce + 8, first_nonce, sizeof(u32) * 3);

	Array_u8 chacha_key_and_nonce_array = {.data = (u8*)chacha_key_and_nonce, .count = sizeof(u32) * 11};

	Array_u8 encrypted_key = sign_pack_and_encrypt(keys_rsa_alice, keys_rsa_bob, chacha_key_and_nonce_array);

	// sending ...

	Data_And_Signature decrypted_key = unpack_decrypt_and_check_signature(keys_rsa_bob, keys_rsa_alice, encrypted_key.data, encrypted_key.count);

	if (decrypted_key.data.count != decrypted_key.signature.count) return 0; // TODO: Cambiar para que use un log personalizado.

	u32 chacha_key_and_nonce_received[11];
	for (int i = 0; i < 11; i++) chacha_key_and_nonce_received[i] = ((u32*)decrypted_key.data.data)[i];

	chacha20_encrypt_msg();


	// // assert(count <= 44);
	// // // the last 44 bytes are the chacha_key and the nonce. They are saved in little endian
	// // TODO: 44 is hardcoded as the size of chacha keys and count is not being used,
	// // for some reason count sometimes is greater than 44 and some trash is located before (little endian)
	// // I should debug it but for now it should not be a problem.
	// memcpy(received_chacha_key_and_nonce, raw_received, 44);


	// ChaCha20_Message encrypted_msg = chacha20_encrypt_msg(try_message, strlen(try_message), received_chacha_key_and_nonce);
	// ChaCha20_Message decrypted_msg = chacha20_decrypt_msg(encrypted_msg, received_chacha_key_and_nonce);

	// printf("\n%.*s \n", decrypted_msg.len, decrypted_msg.data);
	// printf("==================================\n");
	// assert(strncmp(try_message, decrypted_msg.data, decrypted_msg.len) == 0);

	// fflush(stdout);
	// free(encrypted_msg.data);
	// free(decrypted_msg.data);
	// mpz_clear(result);
	// clear_rsa_keys(&keys_rsa_alice);
	// clear_rsa_keys(&keys_rsa_bob);
	return 0;
}

int
main(int argc, char *argv[]) {
	assert(argv[1] != null);
	for (int i = 0; i < 2; i++) {
		// connect_test(argc, argv);
		int result = encrypt_decrypt_rsa_test(argv);
		if (result == 1) printf("\nTEST PASSED\n");
		if (result == 0) printf("\nTEST FAILED\n");
		result = connect_chacha_with_rsa_test(argc, argv);
		// command_line(argc, argv);
		// connect_chacha_with_rsa_test(argc, argv);
	}

}
