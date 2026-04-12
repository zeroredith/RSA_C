#ifndef RRM_RSA_H
#define RRM_RSA_H

#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>



#ifdef RSA_TESTS

#include "types.h"
#include "typedef_gen.h"
#include "base.c"
#include "arrays.c"
#include "chacha20.h"

#else

typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef float f32;
typedef double f64;

#define internal static
#define global static
#define null NULL

#endif


#define _PRIME_NUMBERS_SIZE 2048

typedef struct RSA_Keys {
	mpz_t modulus; // n
	mpz_t public;  // e
	mpz_t private; // d

	mpz_t prime1;
	mpz_t prime2;
	mpz_t d_prime1; // d mod (p-1)
	mpz_t d_prime2; // d mod (q-1)
	mpz_t garner;
} RSA_Keys;

typedef struct Prime_Gen_Args Prime_Gen_Args;
struct Prime_Gen_Args {
	mpz_t result;
	u64 bits;
};

typedef struct _Array_u8 _Array_u8;
struct _Array_u8 {
	u64 count;
	u8* data;
};

typedef struct Data_And_Signature Data_And_Signature;
struct Data_And_Signature {
	_Array_u8 data;
	_Array_u8 signature;
};

#ifdef RSA_IMPLEMENTATION

internal inline void
mpz_rand_num(mpz_t prime, u32 bits) {
	mpz_t rand_num;
	gmp_randstate_t state;

	mpz_init(rand_num);
	gmp_randinit_default(state);

	u64 seed = (u64)time(null) ^ (u64)clock() ^ (u64)pthread_self(); // used for thread independece security
	gmp_randseed_ui(state, seed);

	mpz_urandomb(rand_num, state, bits);

	mpz_nextprime(prime, rand_num);

	mpz_clear(rand_num);
	gmp_randclear(state);
}

internal inline void
carmichael(mpz_t result, mpz_t prime1, mpz_t prime2) {
	/*
    Since n = pq
    Carmichael_funciton(n) = lem(Carmichael_funciton(prime1), Carmichael_funciton(prime2))
    p & q are primes so lem(p-1,q-1)
  */
	mpz_t prime1_minus_one, prime2_minus_one, gcd;
	mpz_inits(prime1_minus_one, prime2_minus_one, gcd, null);

	mpz_sub_ui(prime1_minus_one, prime1, 1);
	mpz_sub_ui(prime2_minus_one, prime2, 1);

	mpz_gcd(gcd, prime1_minus_one, prime2_minus_one);
	mpz_mul(result, prime1_minus_one, prime2_minus_one);
	mpz_divexact(result, result, gcd);

	mpz_clear(prime1_minus_one);
	mpz_clear(prime2_minus_one);
}

internal inline void
init_rsa_keys(RSA_Keys *keys) {
	mpz_inits(keys->modulus, keys->public, keys->private, keys->prime1, keys->prime2, keys->d_prime1, keys->d_prime2, keys->garner, null);
}



void*
prime_gen_thread(void* arg) {
	Prime_Gen_Args* args = arg;
	mpz_rand_num(args->result, args->bits);
	return null;
}

RSA_Keys
rsa_generate_keys(void) {
	RSA_Keys keys;
	mpz_t carmichael_result, public_check, prime1, prime2;
	mpz_inits(carmichael_result, public_check, prime1, prime2, null);
	init_rsa_keys(&keys);
	mpz_init_set_ui(keys.public, 65537);

	Prime_Gen_Args args1, args2;
	mpz_init(args1.result);
	mpz_init(args2.result);
	args1.bits = _PRIME_NUMBERS_SIZE; // @TODO: Cambiar para que sea por parametro.
	args2.bits = _PRIME_NUMBERS_SIZE;

	pthread_t t1, t2;
	pthread_create(&t1, null, prime_gen_thread, &args1);
	pthread_create(&t2, null, prime_gen_thread, &args2);
	pthread_join(t1, null);
	pthread_join(t2, null);

	mpz_set(keys.prime1, args1.result);
	mpz_set(keys.prime2, args2.result);

	mpz_mul(keys.modulus, keys.prime1, keys.prime2);
	carmichael(carmichael_result, keys.prime1, keys.prime2);

	mpz_gcd(public_check, carmichael_result, keys.public);
	while(mpz_cmp_ui(public_check, 1) != 0) {
		mpz_nextprime(keys.public, keys.public);
		mpz_gcd(public_check, carmichael_result, keys.public);
	}

	mpz_invert(keys.private, keys.public, carmichael_result);

	// Importante usar keys.prime1 y keys.prime2 despues de haber calculado modulus y carmichael.
	mpz_sub_ui(prime1, keys.prime1, 1);
	mpz_sub_ui(prime2, keys.prime2, 1);
	mpz_mod(keys.d_prime1, keys.private, prime1);
	mpz_mod(keys.d_prime2, keys.private, prime2);
	mpz_invert(keys.garner, keys.prime2, keys.prime1);

	mpz_clears(carmichael_result, prime1, prime2, public_check, args1.result, args2.result, null);
	return keys;
}

internal inline void
clear_rsa_keys(RSA_Keys *keys) {
	mpz_clears(keys->modulus, keys->public, keys->private, null);
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

void
decrypt_crt(mpz_t result, mpz_t encrypted, RSA_Keys keys) {
	mpz_t m1, m2, h;
	mpz_inits(m1, m2, h, null);

	mpz_powm(m1, encrypted, keys.d_prime1, keys.prime1);
	mpz_powm(m2, encrypted, keys.d_prime2, keys.prime2);

	mpz_sub(h, m1, m2);

	if (mpz_sgn(h) < 0) mpz_add(h, h, keys.prime1);
	mpz_mul(h, keys.garner, h);
	mpz_mod(h, h, keys.prime1);

	mpz_mul(result, h, keys.prime2);
	mpz_add(result, result, m2);

	mpz_clears(m1, m2, h, null);
}

void
sign_crt(mpz_t result, u8* data, u64 len, RSA_Keys keys) {
	mpz_t m;
	mpz_init(m);
	mpz_import(m, len, 1, sizeof(u8), 0, 0, data);
	decrypt_crt(result, m, keys);
	mpz_clear(m);
}

char*
mpz_to_string(mpz_t data, u64* out_count) {
  u64 count = 0;
  u8* bytes;
  bytes = mpz_export(null, &count, 1, sizeof(u8), 0, 0, data);
	*out_count = count;
  return bytes;
}



// NOTE: al serializar no estamos teniendo en cuenta el endianess que se esta utilizando.
// Es posible que no funcione con distintos endianess.
_Array_u8
sign_and_encrypt(RSA_Keys keys_alice, RSA_Keys keys_bob, _Array_u8 data) {
	mpz_t signature, encrypted_data_mpz, tmp_d;
	mpz_inits(tmp_d, signature, encrypted_data_mpz, null);

	sign_crt(signature, data.data, data.count, keys_alice);

	_Array_u8 signature_exported = {0};
	_Array_u8 packed = {0};
	_Array_u8 encrypted_data = {0};

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
	decrypt_crt(decrypted_mpz, encrypted_mpz, keys_bob);

	_Array_u8 decrypted = {0};
	decrypted.data = mpz_export(null, &decrypted.count, 1, sizeof(u8), 0, 0, decrypted_mpz);

	mpz_import(designed_mpz, *(u64*)encrypted_data, 1, sizeof(u8), 0, 0, encrypted_data+16);
	design_data(designed_mpz, designed_mpz, keys_alice);
	_Array_u8 designed = {0};
	designed.data = mpz_export(null, &designed.count, 1, sizeof(u8), 0, 0, designed_mpz);
	return (Data_And_Signature){.data = decrypted, .signature = designed};
}

#endif
#endif

// :tests
#ifdef RSA_TESTS

static char* buffer_logs[256];
static u64 buffer_logs_count = 0;

void
_rsa_log(char* text) {
	char* new_string = malloc(strlen(text));
	buffer_logs[buffer_logs_count] = new_string;
	buffer_logs_count += 1;
}
// @TODO: Cambiar como funciona este sistema de logs
void
_print_logs(void) {
	for (int i = 0; i < buffer_logs_count; i++) {
		printf("\nLOG:[%s]\n", buffer_logs[i]);
	}
}

// #define bool_pointer void*
// #define to_bool_pointer(b) (void*)(intptr_t)b

bool
encrypt_decrypt_rsa_test(char *arg) {
	RSA_Keys keys_alice = rsa_generate_keys();
	RSA_Keys keys_bob = rsa_generate_keys();

	u8* packed_and_encrypted_data;
	u64 packed_and_encrypted_count;

	_Array_u8 try_string_u8 = {.data = arg, .count = strlen(arg)};
	_Array_u8 encrypted = sign_and_encrypt(keys_alice, keys_bob, try_string_u8);

	// sending ...

	Data_And_Signature data_and_signature = decrypt(keys_alice, keys_bob, encrypted.data, encrypted.count);
	if (data_and_signature.data.count != data_and_signature.signature.count || memcmp(data_and_signature.data.data, data_and_signature.signature.data, data_and_signature.data.count) != 0) {
		_rsa_log("signature does not coincide in encrypt_decrypt_rsa_test\n");
		return false;
	}
	return true;
}

bool
connect_chacha_with_rsa_test(char* arg) {
	// printf("====== connect_chacha_with_rsa_test ====== \n");
	RSA_Keys keys_rsa_alice = rsa_generate_keys();
	RSA_Keys keys_rsa_bob = rsa_generate_keys();


	mpz_t result;
	mpz_init(result);

	u32 chacha_key[8];
	u32 first_nonce[3];
	chacha20_generate_key(chacha_key, first_nonce);

	// packing the key and the nonce

	u32 chacha_key_and_nonce[11];
	memcpy(chacha_key_and_nonce, chacha_key, sizeof(u32) * 8);
	memcpy(chacha_key_and_nonce + 8, first_nonce, sizeof(u32) * 3);

	_Array_u8 chacha_key_and_nonce_array = {.data = (u8*)chacha_key_and_nonce, .count = sizeof(u32) * 11};

	_Array_u8 encrypted_key = sign_and_encrypt(keys_rsa_alice, keys_rsa_bob, chacha_key_and_nonce_array);

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
	return true;
}

#define ANSI_COLOR_RED          "\x1b[31m"
#define ANSI_COLOR_GREEN        "\x1b[32m"
#define ANSI_RESET_ALL          "\x1b[0m"


struct Thread {
	pthread_t thread_id;
};

struct Task {
	bool (*func)(char*);
	char* arg;
	char* test_name;
	u64 thread_index;
};


#define MAX_THREADS 12

internal Array_Thread thread_pool;
internal Array_Task task_pool;
internal Array_u64 free_threads;
internal pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_test(bool result, char* func_name) {
  pthread_mutex_lock(&pool_mutex);
	if (!result) printf(ANSI_COLOR_RED "FAILED" ANSI_RESET_ALL " %s\n", func_name);
	if (result) printf(ANSI_COLOR_GREEN "PASSED" ANSI_RESET_ALL " %s\n", func_name);
	_print_logs();
  pthread_mutex_unlock(&pool_mutex);
}

void*
task_wrapper(void* data) {
	Task* task = data;
	bool result = task->func(task->arg);
	log_test(result, task->test_name);
	fflush(stdout);

	pthread_mutex_lock(&pool_mutex);

	array_add(free_threads, task->thread_index);
	pthread_mutex_unlock(&pool_mutex);
	return null;
}

void
pool_test_run(bool (*func)(char*), char* arg, char* test_name) {
  pthread_mutex_lock(&pool_mutex);
	while(free_threads.count == 0) {
	  pthread_mutex_unlock(&pool_mutex);
		usleep(500);
	  pthread_mutex_lock(&pool_mutex);
	}

	u64 free_index = free_threads.data[free_threads.count-1];
	free_threads.count -= 1;

	Task task;
	task.func = func;
	task.arg = arg;
	task.test_name = test_name;
	task.thread_index = free_index;
	array_add(task_pool, task);

	Thread *thread = &thread_pool.data[free_index];
	pthread_create(&thread->thread_id, null, task_wrapper, &(task_pool.data[task_pool.count-1]));

  pthread_mutex_unlock(&pool_mutex);
}


void
pool_join(void) {
	for (int i = 0; i < MAX_THREADS; i++) pthread_join(thread_pool.data[i].thread_id, null);
}

int
main(void) {
	char* arg = "abracadabra";
	for(int i = 0; i < MAX_THREADS; i++) {
		array_add(free_threads, i);
		array_add(thread_pool, (Thread){0});
	}

	for (int i = 0; i < 5; i++) {
	  pool_test_run(encrypt_decrypt_rsa_test, arg, "encrypt_decrypt_rsa_test");
	  pool_test_run(connect_chacha_with_rsa_test, arg, "connect_chacha_with_rsa_test");
	}
	pool_join();
}


#endif
