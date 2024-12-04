/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


static const char *usage = "-key pem -pass str [-in file] [-out file]";

static const char *options =
"\n"
"Options\n"
"\n"
"    -key pem            Decryption private key file in PEM format\n"
"    -pass str           Password to open the private key\n"
"    -in file | stdin    Input ciphertext in binary DER-encoding\n"
"    -in file | stdout   Output decrypted data\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem\n"
"    $ echo 'Secret message' | gmssl sm2encrypt -pubkey sm2pub.pem -out sm2.der\n"
"    $ gmssl sm2decrypt -key sm2.pem -pass P@ssw0rd -in sm2.der\n"
"\n";

int sm2decrypt_main(int argc, char **argv)
{
	int ret = 1;
	char *prog = argv[0];
	char *keyfile = NULL;
	char *pass = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	FILE *keyfp = NULL;
	FILE *infp = stdin;
	FILE *outfp = stdout;
	SM2_KEY key;
	SM2_DEC_CTX ctx;
	//uint8_t inbuf[SM2_MAX_CIPHERTEXT_SIZE];
    const size_t inlen = 111;
    uint8_t inbuf[inlen] = {0x30,0x6d,0x2,0x20,0x5a,0xcb,0xb1,0x52,0xfa,0xa3,0x6d,0x14,0xb1,0xa7,0x5,0x52,0x34,0x72,0x42,0xbd,0x57,0xc1,0x3a,0x62,0xc0,0xcb,0xf1,0x4d,0x59,0x5a,0x74,0x16,0xa5,0xb9,0xad,0x2e,0x2,0x21,0x0,0xe6,0xcf,0x26,0x3,0x8a,0xee,0x41,0xf8,0x99,0xf7,0x9a,0x43,0xb7,0x95,0x56,0x92,0x7e,0x3c,0x62,0x45,0xb7,0x39,0x17,0x3,0x8,0xca,0x6b,0x1e,0x56,0x1,0x93,0xbd,0x4,0x20,0x23,0x41,0xed,0x13,0x32,0x71,0x50,0x26,0x62,0xde,0x23,0x3f,0x39,0xf4,0x3a,0x9a,0xb0,0xb8,0xe3,0x72,0xbf,0xa7,0x21,0x72,0x3e,0x71,0x3,0x14,0xc7,0x2a,0x1e,0xe6,0x4,0x4,0xa6,0x34,0x29,0xf9};
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t outlen;

	argc--;
	argv++;

	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
			ret = 0;
			goto end;
		} else if (!strcmp(*argv, "-key")) {
			if (--argc < 1) goto bad;
			keyfile = *(++argv);
			if (!(keyfp = fopen(keyfile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, keyfile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-pass")) {
			if (--argc < 1) goto bad;
			pass = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
			if (!(infp = fopen(infile, "rb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, infile, strerror(errno));
				goto end;
			}
		} else if (!strcmp(*argv, "-out")) {
			if (--argc < 1) goto bad;
			outfile = *(++argv);
			if (!(outfp = fopen(outfile, "wb"))) {
				fprintf(stderr, "gmssl %s: open '%s' failure : %s\n", prog, outfile, strerror(errno));
				goto end;
			}
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
			goto end;
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
			goto end;
		}

		argc--;
		argv++;
	}

	if (!keyfile) {
		fprintf(stderr, "gmssl %s: '-key' option required\n", prog);
		goto end;
	}
	if (!pass) {
		fprintf(stderr, "gmssl %s: '-pass' option required\n", prog);
		goto end;
	}

	if (sm2_private_key_info_decrypt_from_pem(&key, pass, keyfp) != 1) {
		fprintf(stderr, "gmssl %s: private key decryption failure\n", prog);
		goto end;
	}

//	if ((inlen = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0) {
//		fprintf(stderr, "gmssl %s: read input failed : %s\n", prog, strerror(errno));
//		goto end;
//	}

	if (sm2_decrypt_init(&ctx) != 1) {
		fprintf(stderr, "gmssl %s: sm2_decrypt_init failed\n", prog);
		goto end;
	}
	if (sm2_decrypt_update(&ctx, inbuf, inlen) != 1) {
		fprintf(stderr, "gmssl %s: sm2_decyrpt_update failed\n", prog);
		goto end;
	}
	if (sm2_decrypt_finish(&ctx, &key, outbuf, &outlen) != 1) {
		fprintf(stderr, "gmssl %s: decryption failure\n", prog);
		goto end;
	}
	if (outlen != fwrite(outbuf, 1, outlen, outfp)) {
		fprintf(stderr, "gmssl %s: output plaintext failed : %s\n", prog, strerror(errno));
		goto end;
	}
	ret = 0;
end:
	gmssl_secure_clear(&key, sizeof(key));
	gmssl_secure_clear(&ctx, sizeof(ctx));
	gmssl_secure_clear(outbuf, sizeof(outbuf));
	if (keyfp) fclose(keyfp);
	if (infile && infp) fclose(infp);
	if (outfile && outfp) fclose(outfp);
	return ret;
}
