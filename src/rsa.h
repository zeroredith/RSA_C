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
encrypt_data_public(mpz_t result, u8* data, u64 len, RSA_Keys keys) {
	mpz_t m;
	mpz_init(m);
	mpz_import(m, len, 1, sizeof(u8), 0, 0, data);
	mpz_powm(result, m, keys.public, keys.modulus);
  mpz_clear(m);
}

void
encrypt_data_private(mpz_t result, u8* data, u64 len, RSA_Keys keys) {
	mpz_t m;
	mpz_init(m);
	mpz_import(m, len, 1, sizeof(u8), 0, 0, data);
	mpz_powm(result, m, keys.private, keys.modulus);
  mpz_clear(m);
}

void
encrypt_mpz_public(mpz_t result, mpz_t data, RSA_Keys keys) {
	mpz_powm(result, data, keys.public, keys.modulus);
}

void
encrypt_mpz_private(mpz_t result, mpz_t data, RSA_Keys keys) {
	mpz_powm(result, data, keys.private, keys.modulus);
}

// decrypt public use private keys to decrypt, and vice versa.
void
decrypt_public(mpz_t result, mpz_t encrypted, RSA_Keys keys) {
  mpz_powm(result, encrypted, keys.private, keys.modulus);
}

void
decrypt_private(mpz_t result, mpz_t encrypted, RSA_Keys keys) {
  mpz_powm(result, encrypted, keys.public, keys.modulus);
}

char*
mpz_to_string(mpz_t data, u64 len) {
  char *out = malloc(len + 1);
  u64 count;
  mpz_export(out, &count, 1, sizeof(u8), 0, 0, data);
  out[count] = '\0';
  return out;
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

	gmp_printf("n: %Zd\n", keys.modulus);
	gmp_printf("e: %Zd\n", keys.public);
	gmp_printf("d: %Zd\n", keys.private);

	u64 len = strlen(argv[1]);

	mpz_t encrypted;
	mpz_t decrypted;
	mpz_init(encrypted);
	mpz_init(decrypted);

	start = clock();

	encrypt_data_public(encrypted, argv[1], len, keys);

	end = clock();
	time_taken = ((f64)(end - start)) / CLOCKS_PER_SEC;
	f64 t2 = time_taken;

  gmp_printf("Encrypted: %Zd\n", encrypted);

	start = clock();
	decrypt_public(decrypted, encrypted, keys);
	end = clock();
	time_taken = ((f64)(end - start)) / CLOCKS_PER_SEC;

  gmp_printf("Decrypted: %s\n", mpz_to_string(decrypted, len));
	printf("Time for generate RSA keys: %f seconds\n", t1);
	printf("Time for encrypt the message: %f seconds\n", t2);
	printf("Time for decrypt the message: %f seconds\n", time_taken);

	Public_Key public_key = export_public_key(keys);
  gmp_printf("public_key: public[%Zd] modulus[%Zd]\n", public_key.public, public_key.modulus);

	mpz_clear(encrypted);
	clear_rsa_keys(&keys);

	return 0;
}

#define mpz_len(mpz) (mpz_sizeinbase(mpz, 2) + 7) / 8

int
connect_test() {
	RSA_Keys keys_alice;
	RSA_Keys keys_bob;

	init_rsa_keys(&keys_alice);
	get_rsa_keys(&keys_alice);

	init_rsa_keys(&keys_bob);
	get_rsa_keys(&keys_bob);

	char* try_message = "Hola bob!";

	mpz_t result;
	mpz_init(result);

	// alice encrypt with her own private keys and bob public keys
	encrypt_data_private(result, try_message, strlen(try_message), keys_alice);
	encrypt_mpz_public(result, result, keys_bob);

	// bob decrypt

	decrypt_public(result, result, keys_bob);
	decrypt_private(result, result, keys_alice);

  gmp_printf("Decrypted: %s\n", mpz_to_string(result, mpz_len(result)));

 	assert(strncmp("Hola bob!", mpz_to_string(result, mpz_len(result)), mpz_len(result)) == 0);
  return 0;
}

int
main(int argc, char *argv[]	) {
	return connect_test();

	// return command_line(argc, argv);
}
