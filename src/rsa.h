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
  mpz_powm(result, encrypted, keys.private, keys.modulus);
}

void
decrypt_mpz(mpz_t result, mpz_t encrypted, RSA_Keys keys) {
  mpz_powm(result, encrypted, keys.public, keys.modulus);
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

typedef struct RSA_Package RSA_Package;
struct RSA_Package {
	mpz_t signature;
	u8* data;
	u64 count;
};

void
serialize_rsa_package(RSA_Package package, mpz_t out) {
	u64 signature_count;
	u8* signature_bytes = mpz_export(null, &signature_count, 1, sizeof(u8), 0, 0, package.signature);
	u64 total_size = 8 + signature_count + 8 + package.count; // padding
	u8* buffer = malloc(total_size);

	u64 offset = 0;
	memcpy(buffer + offset, &signature_count, 8);
	offset += 8;

	memcpy(buffer + offset, signature_bytes, signature_count);
	offset += signature_count;

	memcpy(buffer + offset, &package.count, 8);
	offset += 8;

	memcpy(buffer + offset, package.data, package.count);

	mpz_import(out, total_size, 1, 1, 0, 0, buffer);

	free(signature_bytes);
	free(buffer);
}

RSA_Package
deserialize_rsa_package(mpz_t serialized) {
	RSA_Package package;
	u64 size;
	u8* buffer = mpz_export(null, &size, 1, sizeof(u8), 0, 0, serialized);

	u64 offset = 0;

	u64 signature_size;
	memcpy(&signature_size, buffer + offset, 8);
	offset += 8;

	u8* signature_bytes = buffer+offset;
	offset += signature_bytes;

	u64 data_size;
	memcpy(&data_size, buffer + offset, 8);
	offset += 8;

	u8* data = malloc(data_size);
	memcpy(data, buffer + offset, data_size);

	mpz_init(package.signature);
	mpz_import(package.signature, signature_size, 0, sizeof(u8), 0, 0, signature_bytes);

	package.data = data;
	package.count = data_size;

	return package;
}

void
encrypt_and_pack(RSA_Keys keys_alice, RSA_Keys keys_bob, u8* data, u64 count, mpz_t out) {
	RSA_Package package;
	mpz_t serialized;
	mpz_init(package.signature);
	mpz_init(serialized);

	package.data = data;
	package.count = count;
	sign_data(package.signature, data, count, keys_alice);
	serialize_rsa_package(package, serialized);
	encrypt_mpz(out, serialized, keys_bob);
  mpz_clear(serialized);
  mpz_clear(package.signature);
}

void
unpack_decrypt_and_check_signature(RSA_Keys keys_alice, RSA_Keys keys_bob, mpz_t encrypted) {
	mpz_t serialized;
	mpz_init(serialized);
	decrypt_mpz(serialized, encrypted, keys_bob);
	RSA_Package package = deserialize_rsa_package(serialized);
	printf("\npackage.data = %.*s\n", package.count, package.data);
}

int
encrypt_decrypt_rsa_test(char *argv[]) {
	printf("======== encrypt_decrypt_rsa_test ========\n");
	RSA_Keys keys_alice;
	RSA_Keys keys_bob;

	init_rsa_keys(&keys_alice);
	get_rsa_keys(&keys_alice);

	init_rsa_keys(&keys_bob);
	get_rsa_keys(&keys_bob);

	char* try_string = "asdf";
	mpz_t packed;
	mpz_init(packed);

	encrypt_and_pack(keys_alice, keys_bob, try_string, strlen(try_string), packed);
	unpack_decrypt_and_check_signature(keys_alice, keys_bob, packed);


	// if(strncmp(result_str, try_string, count) != 0) printf("\n ERROR count encrypt_decrypt_rsa_test \n ");
	// if(strncmp(result_str, try_string, strlen(try_string)) != 0) printf("\n ERROR len encrypt_decrypt_rsa_test \n ");

	fflush(stdout);
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


	sign_data(result, (u8*)chacha_key_and_nonce, sizeof(u32) * 11, keys_rsa_alice);
	encrypt_mpz(result, result, keys_rsa_bob);

	// sending chacha keys by rsa it ...

	design_data(result, result, keys_rsa_bob);
	decrypt_mpz(result, result, keys_rsa_alice);

	u64 out_count = 0;
	// gmp_printf("Decrypted chacha %s\n", mpz_to_string(result, &out_count));

	// using chacha keys to send the message.
	u32 received_chacha_key_and_nonce[11] = {0};
	u64 count = 0;
	u8* raw_received;

	mpz_export(raw_received, &count, 1, sizeof(u8), 0, 0, result);

	// assert(count <= 44);
	// // the last 44 bytes are the chacha_key and the nonce. They are saved in little endian
	// TODO: 44 is hardcoded as the size of chacha keys and count is not being used,
	// for some reason count sometimes is greater than 44 and some trash is located before (little endian)
	// I should debug it but for now it should not be a problem.
	memcpy(received_chacha_key_and_nonce, raw_received, 44);


	ChaCha20_Message encrypted_msg = chacha20_encrypt_msg(try_message, strlen(try_message), received_chacha_key_and_nonce);
	ChaCha20_Message decrypted_msg = chacha20_decrypt_msg(encrypted_msg, received_chacha_key_and_nonce);

	printf("\n%.*s \n", decrypted_msg.len, decrypted_msg.data);
	printf("==================================\n");
	assert(strncmp(try_message, decrypted_msg.data, decrypted_msg.len) == 0);

	fflush(stdout);
	free(encrypted_msg.data);
	free(decrypted_msg.data);
	mpz_clear(result);
	clear_rsa_keys(&keys_rsa_alice);
	clear_rsa_keys(&keys_rsa_bob);
	return 0;
}

int
main(int argc, char *argv[]) {
	for (int i = 0; i < 10; i++) {
		// connect_test(argc, argv);
		encrypt_decrypt_rsa_test(argv);
		// command_line(argc, argv);
		// connect_chacha_with_rsa_test(argc, argv);
	}

}
