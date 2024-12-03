/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
//#define USE_RAND
#ifdef USE_RAND
#include <gmssl/rand.h>
#endif
//#include <gmssl/asn1.h>
//#include <gmssl/error.h>
#include <gmssl/sm2.h>
//#include <gmssl/pkcs8.h>


// TODO: prepare POINT with different length		

static int test_sm2_ciphertext(void)
{
	struct {
		char *label;
		size_t ciphertext_size;
	} tests[] = {
		{ "null ciphertext", 0 },
		{ "min ciphertext size", SM2_MIN_PLAINTEXT_SIZE },
		{ "max ciphertext size", SM2_MAX_PLAINTEXT_SIZE },
	};

	SM2_CIPHERTEXT C;
	SM2_KEY sm2_key;
	uint8_t buf[1024];
	size_t i;

#ifdef USE_RAND
	rand_bytes(C.hash, 32);
	rand_bytes(C.ciphertext, SM2_MAX_PLAINTEXT_SIZE);
    printf("{");
    for (uint8_t* c = C.hash; *c != NULL; c++) {
        printf("0x%x,",*c);
    }
    printf("}");
    
    printf("{");
    for (uint8_t* c = C.ciphertext; *c != NULL; c++) {
        printf("0x%x,",*c);
    }
    printf("}");
#else
    uint8_t hash_tmp[] = {0xdb,0x73,0xd7,0xdd,0x49,0xaa,0x8d,0x36,0xc7,0x15,0x4d,0x1e,0xda,0x55,0x8c,0x4b,0xed,0xcf,0x2a,0xe5,0x45,0xd1,0xf7,0x90,0x43,0x25,0x63,0x77,0x57,0xd0,0x24,0x92};
    memcpy(C.hash, hash_tmp, 32);
    uint8_t ciphertext_tmp[] = {0x9d,0xb5,0x6b,0xbf,0x72,0xe3,0xa6,0xd,0xf8,0xd1,0xda,0x14,0x87,0x7e,0x77,0x2b,0x60,0x36,0x4f,0x49,0x8f,0xc1,0xa6,0x81,0x90,0x85,0x47,0xa4,0x79,0xb1,0xd8,0xad,0x43,0xea,0xcd,0xa6,0xa4,0x14,0xb2,0x40,0xe8,0x82,0x53,0xa8,0x25,0xd1,0x2e,0xad,0x5a,0x4};
    memcpy(C.ciphertext, ciphertext_tmp, SM2_MAX_PLAINTEXT_SIZE);
    
#endif
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		uint8_t *p = buf;
		const uint8_t *cp = buf;
		size_t len = 0;

		if (sm2_key_generate(&sm2_key) != 1) {
			//error_print();
			return -1;
		}

		sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&(C.point));
		C.ciphertext_size = (uint8_t)tests[i].ciphertext_size;

		if (sm2_ciphertext_to_der(&C, &p, &len) != 1) {
			//error_print();
			return -1;
		}

		printf("Plaintext size = %zu, SM2Ciphertext DER size %zu\n", tests[i].ciphertext_size, len);

		if (sm2_ciphertext_from_der(&C, &cp, &len) != 1
        ) {
			//error_print();
			return -1;
		}

	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

#define TEST_COUNT 20

static int test_sm2_do_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t plaintext[] = "Hello World!";
	SM2_CIPHERTEXT ciphertext;

	uint8_t plainbuf[SM2_MAX_PLAINTEXT_SIZE] = {0};
	size_t plainlen = 0;
	int r = 0;

	size_t i = 0;

	for (i = 0; i < TEST_COUNT; i++) {

		if (sm2_key_generate(&sm2_key) != 1) {
			//error_print();
			return -1;
		}

		if (sm2_do_encrypt(&sm2_key, plaintext, sizeof(plaintext), &ciphertext) != 1) {
			//error_print();
			return -1;
		}

		if (sm2_do_decrypt(&sm2_key, &ciphertext, plainbuf, &plainlen) != 1) {
			//error_print();
			return -1;
		}
		if (plainlen != sizeof(plaintext)
			|| memcmp(plainbuf, plaintext, sizeof(plaintext)) != 0) {
			//error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_sm2_do_encrypt_fixlen(void)
{
	struct {
		int point_size;
		size_t plaintext_len;
	} tests[] = {
		{ SM2_ciphertext_compact_point_size, 10 },
		{ SM2_ciphertext_typical_point_size, 10 },
		{ SM2_ciphertext_max_point_size, 10 },
	};

	SM2_KEY sm2_key;
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	SM2_CIPHERTEXT ciphertext;
	uint8_t decrypted[SM2_MAX_PLAINTEXT_SIZE];
	size_t decrypted_len;

	size_t i;

	if (sm2_key_generate(&sm2_key) != 1) {
		//error_print();
		return -1;
	}
#ifdef USE_RAND
	rand_bytes(plaintext, sizeof(plaintext));
    printf("{");
    for (uint8_t* c = plaintext; *c != NULL; c++) {
        printf("0x%x,",*c);
    }
    printf("}");
#else
    uint8_t plaintext_tmp[] = {0x3c,0x45,0xc6,0x5e,0x7b,0x16,0xcf,0xfc,0xfd,0x9c,0xe0,0xa,0x4c,0x27,0x52,0xea,0x68,0x88,0x6c,0x3b,0x93,0x1b,0xd2,0x2c,0x6,0xf3,0xd3,0xec,0xa4,0xc2,0x43,0xc,0x7a,0x28,0xe4,0x66,0xc5,0x5c,0x8d,0x27,0xff,0x1d,0x15,0x13,0x97,0xaa,0x9d,0x11,0x27,0x27,0x6e,0x67,0xb0,0x4e,0xd8,0xc7,0x1c,0x88,0xec,0xe9,0x1e,0xe7,0x8,0x5b,0x34,0x3b,0xd5,0x4c,0x6c,0x19,0xd3,0x79,0xa1,0x95,0x8b,0xa0,0x87,0xa9,0xb3,0xe8,0x1c,0xe2,0x21,0x3,0xdd,0x16,0x7b,0x44,0x81,0x48,0xfc,0xe1,0xda,0xcd,0x44,0x30,0xc5,0x7f,0x95,0x85,0x4a,0x78,0x7e,0x36,0xd4,0x55,0xd0,0x9b,0x7b,0xdc,0xe8,0xcb,0x2f,0x14,0x39,0xb8,0xa,0x2a,0x46,0xe4,0xf9,0xab,0x54,0x3a,0x86,0x71,0x79,0xf9,0xeb,0x29,0xb4,0x8b,0xed,0x9,0xd8,0x26,0x2,0x55,0xb3,0xdf,0x6d,0x6f,0x17,0x52,0x1e,0xc2,0x1e,0xfb,0x33,0x17,0xe,0xf0,0x7f,0x10,0xe5,0x51,0x6f,0x7d,0x52,0xa,0xce,0x36,0xb0,0x54,0xb1,0x91,0xbe,0x9c,0x91,0x2a,0xd6,0x3c,0xba,0x3d,0xa2,0x5d,0x51,0xa1,0x6c,0x1d,0x6b,0x99,0x7f,0x2d,0x46,0xa1,0xc8,0x3f,0x23,0x4a,0xbc,0xee,0xd2,0xc1,0xf6,0x29,0x57,0x1e,0xb1,0x1d,0xe5,0xb6,0x12,0xaf,0x99,0x32,0x6b,0xf5,0xbf,0xd0,0xda,0x92,0xad,0x4e,0x13,0x8,0x27,0x57,0x82,0x21,0x3b,0x4d,0xe0,0xe2,0xbd,0x72,0x71,0x35,0xc4,0xf7,0xfe,0xb8,0x9a,0x5a,0xd0,0xd4,0x7b,0x8d,0x6d,0x62,0x3e,0xf3,0xb2,0x69,0xca,0x57,0x43,0xac,0xa6,0xa0,0x16,0x8a,0xc7,0xd3,0xf};
    memcpy(plaintext, plaintext_tmp, sizeof(plaintext_tmp));
#endif
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		if (sm2_do_encrypt_fixlen(&sm2_key, plaintext, tests[i].plaintext_len, tests[i].point_size, &ciphertext) != 1) {
			//error_print();
			return -1;
		}

		if (sm2_do_decrypt(&sm2_key, &ciphertext, decrypted, &decrypted_len) != 1) {
			//error_print();
			return -1;
		}

		if (decrypted_len != tests[i].plaintext_len) {
			//error_print();
			return -1;
		}
		if (memcmp(decrypted, plaintext, decrypted_len) != 0) {
			//error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_encrypt_fixlen(void)
{
	struct {
		int point_size;
		size_t plaintext_len;
	} tests[] = {
		{ SM2_ciphertext_compact_point_size, 1 },
		{ SM2_ciphertext_typical_point_size, 64 },
		{ SM2_ciphertext_max_point_size, SM2_MAX_PLAINTEXT_SIZE },
	};

	SM2_KEY sm2_key;
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t encrypted[SM2_MAX_CIPHERTEXT_SIZE];
	uint8_t decrypted[SM2_MAX_PLAINTEXT_SIZE];
	size_t encrypted_len, encrypted_fixlen, decrypted_len;
	size_t i, j;

	if (sm2_key_generate(&sm2_key) != 1) {
		//error_print();
		return -1;
	}
#ifdef USE_RAND
	rand_bytes(plaintext, sizeof(plaintext));
    
    printf("{");
    for (uint8_t* c = plaintext; *c != NULL; c++) {
        printf("0x%x,",*c);
    }
    printf("}");
#else
    
    uint8_t plaintext_tmp[] = {0xe4,0xc8,0xeb,0x9,0x50,0xb5,0x12,0x13,0x4b,0x62,0x66,0x2f,0xa8,0xe1,0x67,0xc,0xc2,0xd3,0x33,0xb3,0x93,0x3c,0xd2,0x18,0xa6,0x72,0x3b,0x7b,0x46,0x81,0xf6,0xc1,0x28,0xc6,0x29,0xe5,0x47,0x95,0x4,0xfa,0x9f,0xd2,0x10,0xe,0x84,0xd6,0x60,0x73,0x88,0x16,0x61,0xbc,0x24,0x5d,0xae,0xee,0x6c,0xd5,0x40,0x8a,0xe,0x37,0x62,0x3e,0x2d,0x19,0x9f,0x21,0xdf,0xcd,0x21,0x70,0xd5,0x26,0x5b,0x5e,0x3c,0x2f,0x73,0x71,0xaf,0x84,0x1,0x1d,0xb3,0x6b,0xa,0xb2,0x24,0x83,0x83,0x9c,0xb9,0x3b,0xd7,0x4,0x1,0x9a,0xed,0xf,0xed,0x30,0x88,0x2f,0x1a,0xe1,0xf0,0x4e,0x72,0xb0,0xe5,0xd5,0xd,0xf4,0xfb,0x2c,0x60,0xe9,0x8e,0x51,0x56,0xf9,0xf4,0xf,0x43,0x39,0x84,0x90};
    memcpy(plaintext, plaintext_tmp, sizeof(plaintext_tmp));
    
#endif
	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {

		if (sm2_encrypt_fixlen(&sm2_key, plaintext, tests[i].plaintext_len, tests[i].point_size,
			encrypted, &encrypted_len) != 1) {
			//error_print();
			return -1;
		}

		if (sm2_decrypt(&sm2_key, encrypted, encrypted_len, decrypted, &decrypted_len) != 1) {
			//error_print();
			return -1;
		}
		if (decrypted_len != tests[i].plaintext_len) {
			//error_print();
			return -1;
		}
		if (memcmp(decrypted, plaintext, tests[i].plaintext_len) != 0) {
			//error_print();
			return -1;
		}

		// check if sm2_encrypt_fixlen always output fixed length ciphertext
		encrypted_fixlen = encrypted_len;
		for (j = 0; j < 10; j++) {
			if (sm2_encrypt_fixlen(&sm2_key, plaintext, tests[i].plaintext_len, tests[i].point_size,
				encrypted, &encrypted_len) != 1) {
				//error_print();
				return -1;
			}
			if (encrypted_len != encrypted_fixlen) {
				//error_print();
				return -1;
			}
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


static int test_sm2_encrypt(void)
{
	SM2_KEY sm2_key;
	uint8_t msg[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t cbuf[SM2_MAX_CIPHERTEXT_SIZE+100];
	uint8_t mbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t lens[] = {
//		0,
		1,
		16,
		SM2_MAX_PLAINTEXT_SIZE,
	};
	size_t clen, mlen;
	int i;

	if (sm2_key_generate(&sm2_key) != 1) {
		//error_print();
		return -1;
	}

	for (i = 0; i < sizeof(msg); i++) {
		msg[i] = (uint8_t)i;
	}

	for (i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
	//	format_print(stderr, 0, 0, "test %d\n", i + 1);
	//	format_bytes(stderr, 0, 4, "plaintext", msg, lens[i]);
		if (sm2_encrypt(&sm2_key, msg, lens[i], cbuf, &clen) != 1) {
			//error_print();
			return -1;
		}
	//	format_bytes(stderr, 0, 4, "ciphertext", cbuf, clen);
		sm2_ciphertext_print(stderr, 0, 4, "Ciphertext", cbuf, clen);
	//	format_print(stderr, 0, 0, "\n");

		if (sm2_decrypt(&sm2_key, cbuf, clen, mbuf, &mlen) != 1) {
			//error_print();
			return -1;
		}
		if (mlen != lens[i]
			|| memcmp(mbuf, msg, lens[i]) != 0) {
			//error_print();
			return -1;
		}
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int speed_sm2_encrypt_ctx(void)
{
	SM2_KEY sm2_key;
	SM2_ENC_CTX enc_ctx;
	uint8_t plaintext[32];
	uint8_t ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
	size_t ciphertext_len;
	clock_t begin, end;
	double seconds;
	int i;

	sm2_key_generate(&sm2_key);

	if (sm2_encrypt_init(&enc_ctx) != 1) {
		//error_print();
		return -1;
	}

	begin = clock();
	for (i = 0; i < 4096; i++) {
		if (sm2_encrypt_update(&enc_ctx, plaintext, sizeof(plaintext)) != 1) {
			//error_print();
			return -1;
		}
		if (sm2_encrypt_finish(&enc_ctx, &sm2_key, ciphertext, &ciphertext_len) != 1) {
			//error_print();
			return -1;
		}
		sm2_encrypt_reset(&enc_ctx);
	}
	end = clock();
	seconds = (double)(end - begin)/CLOCKS_PER_SEC;

	printf("%s: %f encryptions per second\n", __FUNCTION__, 4096/seconds);
	return 1;
}


int main(void)
{
	if (test_sm2_ciphertext() != 1) goto err;
	if (test_sm2_do_encrypt() != 1) goto err;
	if (test_sm2_do_encrypt_fixlen() != 1) goto err;
	if (test_sm2_encrypt() != 1) goto err;
	if (test_sm2_encrypt_fixlen() != 1) goto err;
#if ENABLE_TEST_SPEED
	if (speed_sm2_encrypt_ctx() != 1) goto err;
#endif
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	//error_print();
	return -1;
}

