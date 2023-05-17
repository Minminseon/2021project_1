#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>

const char keyA[] = \
"-----BEGIN PRIVATE KEY-----\n" \
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgk7XfOPqQiQpzyeVY\n" \
"Mk089Rfwwr7RZgLQiuZqk5jYBvqhRANCAATQlpIk16DiESm0FL4VuM3baDwstymZ\n" \
"25lwcbGgQs5SE4rISABIUZrfKrny9YweIUnP9jO8Ncf03bXJNdSp9hYc\n" \
"-----END PRIVATE KEY-----\n";

const char keyB[] = \
"-----BEGIN PRIVATE KEY-----\n" \
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgl2sACG5Kc0Y6QZFG\n" \
"docrR6upPMrRTCGjRsWWeQLZgCKhRANCAAR7u3P/lnLIcly/4WhnaZi7syvlJYKx\n" \
"MhIRo2nDoxL0dOckXkeJ8/JvGz2nT4CbqgRIEKwuGf6c/NDU2ytW2CqS\n" \
"-----END PRIVATE KEY-----\n";

void RAND_init(void) {
	char buf[32];
	FILE *fin = fopen("/dev/random","rb");
	fread(buf, sizeof(buf), 1, fin);
	fclose(fin);
	RAND_seed(fin, 32);
}

const unsigned char* generate_Rand() {
	int i;
	int retVal = 0;
	int length = 16;

	RAND_status();

	unsigned char *buffer = (unsigned char*)malloc(sizeof(unsigned char)*length);
	retVal = RAND_bytes(buffer, length);
	if(retVal <= 0) {
		printf("error\n");
		return 0;
	}

	for(i = 0; i < length; i++)
			 buffer[i];
	return buffer;
}

EC_POINT *EC_POINT_mult_BN(const EC_GROUP *group, EC_POINT *P, const EC_POINT *a, const BIGNUM *b, BN_CTX *ctx)
{
	EC_POINT *O = EC_POINT_new(group);
	if (P == NULL) P = EC_POINT_new(group);

	for(int i = BN_num_bits(b); i >= 0; i--) {
		EC_POINT_dbl(group, P, P, ctx);
		if (BN_is_bit_set(b, i))
			EC_POINT_add(group, P, P, a, ctx);
		else
			EC_POINT_add(group, P, P, O, ctx);
	}

	return P;
}

int EC_KEY_public_derive_S(const EC_KEY *key, point_conversion_form_t fmt, BIGNUM *S, BIGNUM *R)
{
	BN_CTX *ctx = BN_CTX_new();
	const EC_GROUP *group = EC_KEY_get0_group(key);
	const EC_POINT *Kb = EC_KEY_get0_public_key(key);
	BIGNUM *n = BN_new();
	BIGNUM *r = BN_new();
	EC_POINT *P = NULL;
	EC_POINT *Rp = EC_POINT_new(group);
	BIGNUM *Py = BN_new();
	const EC_POINT *G = EC_GROUP_get0_generator(group);
	int bits,ret=-1;
	EC_GROUP_get_order(group, n, ctx);
	bits = BN_num_bits(n);
	BN_rand(r, bits, -1, 0);
	
	Rp = EC_POINT_mult_BN(group, Rp, G, r, ctx);
	
	P = EC_POINT_mult_BN(group, P, Kb, r, ctx);
	if (!EC_POINT_is_at_infinity(group, P)) {
		EC_POINT_get_affine_coordinates_GFp(group, P, S, Py, ctx);
		EC_POINT_point2bn(group, Rp, fmt, R, ctx);
		ret = 0;
	}
	BN_free(r);
	BN_free(n);
	BN_free(Py);
	EC_POINT_free(P);
	EC_POINT_free(Rp);
	BN_CTX_free(ctx);
	return ret;
}

int EC_KEY_private_derive_S(const EC_KEY *key, const BIGNUM *R, BIGNUM *S)
{
	int ret = -1;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *Py = BN_new();
	const EC_GROUP *group = EC_KEY_get0_group(key);
	EC_POINT *Rp = EC_POINT_bn2point(group, R, NULL, ctx);
	const BIGNUM *kB = EC_KEY_get0_private_key(key);
	EC_GROUP_get_order(group, n, ctx);
	
	EC_POINT *P = EC_POINT_mult_BN(group, NULL, Rp, kB, ctx);
	if (!EC_POINT_is_at_infinity(group, P)) {
		EC_POINT_get_affine_coordinates_GFp(group, P, S, Py, ctx);
		ret = 0;
	}
	BN_free(n);
	BN_free(Py);
	EC_POINT_free(Rp);
	EC_POINT_free(P);
	BN_CTX_free(ctx);
	return ret;
}

const unsigned char* decipher(const EC_KEY *key,
	const unsigned char *R_in, size_t R_len, const unsigned char *c_in, size_t c_len, 
	const unsigned char *d_in, size_t d_len, const unsigned char *salt, size_t salt_len)
{
	BIGNUM *R = BN_bin2bn(R_in, R_len, BN_new());
	BIGNUM *S = BN_new();
	BIGNUM *C = BN_bin2bn(c_in, c_len, BN_new());
	BIGNUM *d = BN_bin2bn(d_in, d_len, BN_new());

	if (EC_KEY_private_derive_S(key, R, S) != 0) {
		printf("Key derivation failed\n");
		return -1;
	}
		sleep(5);
		printf("R: \t");
		BN_print_fp(stdout, R);
		printf("\n");

        size_t S_len = BN_num_bytes(S);
        unsigned char password[S_len];
        BN_bn2bin(S, password);

        const EVP_MD *md = EVP_sha1();
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
        size_t km_len = EVP_MD_block_size(md);
        unsigned char ke_km[ke_len+km_len];

        unsigned char *dc_out;
        size_t dc_len = 0;
        int outl = 0;
	
        PKCS5_PBKDF2_HMAC((const char*)password, S_len, salt, salt_len, 2000, md, ke_len+km_len, ke_km);

        unsigned char dv_out[km_len];
        unsigned int dv_len;
        HMAC(md, ke_km + ke_len, km_len, c_in, c_len, dv_out, &dv_len);

	if (d_len != dv_len || memcmp(dv_out, d_in, dv_len) != 0)
		printf("MAC verification failed\n");

        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
        EVP_DecryptUpdate(ectx, dc_out + dc_len, &outl, c_in, c_len);
        dc_len += outl;
        EVP_DecryptFinal_ex(ectx, dc_out + dc_len, &outl);
        dc_len += outl;
		dc_out[dc_len] = 0;
		
		printf("C: \t");
		BN_print_fp(stdout, C);
		printf("\n");
		printf("d: \t");
		BN_print_fp(stdout, d);
		printf("\n");

		return dc_out;
}

int encipher(const EC_KEY *key, unsigned char *msg,
	unsigned char *R_out, size_t *R_len, unsigned char *c_out, size_t *c_len,
	unsigned char *d_out, size_t *d_len, const unsigned char *salt, size_t salt_len)
{
	BIGNUM *R = BN_new();
	BIGNUM *S = BN_new();

	while(EC_KEY_public_derive_S(key, POINT_CONVERSION_COMPRESSED, S, R) != 0);

	printf("R: \t");
	BN_print_fp(stdout, R);
	printf("\n");

	size_t S_len = BN_num_bytes(S);
	unsigned char password[S_len];
	BN_bn2bin(S, password);

	const EVP_MD *md = EVP_sha1();
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
	size_t km_len = EVP_MD_block_size(md);
	unsigned char ke_km[ke_len+km_len];

	*c_len = 0;
	int outl = 0;

	PKCS5_PBKDF2_HMAC((const char*)password, S_len, salt, salt_len, 2000, md, ke_len+km_len, ke_km);

	EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
	EVP_EncryptUpdate(ectx, c_out + *c_len, &outl, (const unsigned char *)msg, 30);
	*c_len += outl;
	EVP_EncryptFinal_ex(ectx, c_out + *c_len, &outl);
	*c_len += outl;

	unsigned int len;

	HMAC(md, ke_km + ke_len, km_len, c_out, *c_len, d_out, &len);

	*d_len = len;

	BIGNUM *C = BN_bin2bn(c_out, outl+outl, BN_new());
	printf("C: \t");
	BN_print_fp(stdout, C);	
	printf("\n");

	BIGNUM *d = BN_bin2bn(d_out, len, BN_new());
	printf("d: \t");
	BN_print_fp(stdout, d);
	printf("\n");

	*R_len = BN_num_bytes(R);
	BN_bn2bin(R, R_out);
	
	return 0;
}

int main(void) {
	unsigned char R[512], D[512], c[512], salt[16];
	unsigned char *re1, *re2;
	unsigned char *msg1 = generate_Rand();
	unsigned char *msg2 = generate_Rand();
	size_t R_len, D_len, c_len;

	RAND_init();

	BIO *b1 = BIO_new_mem_buf((void*)keyB, sizeof(keyB));
	BIO *b2 = BIO_new_mem_buf((void*)keyA, sizeof(keyA));

	EVP_PKEY *pkey1 = NULL;
	EC_KEY *eckey1 = NULL;

	EVP_PKEY *pkey2 = NULL;
	EC_KEY *eckey2 = NULL;

	PEM_read_bio_PrivateKey(b1, &pkey1, NULL, NULL);
	PEM_read_bio_PrivateKey(b2, &pkey2, NULL, NULL);

	eckey1 = EVP_PKEY_get1_EC_KEY(pkey1);
	eckey2 = EVP_PKEY_get1_EC_KEY(pkey2);

	RAND_bytes(salt, sizeof(salt));

	printf("==================================================================================\n");
	printf("\t\t** clientA --> clientB **\n");
	printf("clientA encrypt randA and generate R,C,d\n\n");
	encipher(eckey1, msg1, R, &R_len, c, &c_len, D, &D_len, salt, sizeof(salt));
	printf("\n-------->clientA send encrypted randA and R,C,d\n");
	printf("==================================================================================\n");
	printf("clientB received encrypted randA and R,C,d\n\n");
	re1 = decipher(eckey1, R, R_len, c, c_len, D, D_len, salt, sizeof(salt));
	printf("\n-------->clientB decrypt randA\n\n");
	printf("randA : ");
	for(int i=0; i<16; i++) {
		printf("%d", re1[i]);
		}
	printf("\n");
	printf("====================================================================================\n");
	sleep(5);
	printf("\t\t** clientB --> clientA **\n");
	printf("clientB encrypt randB and generate R,C,d\n\n");
	encipher(eckey2, msg2, R, &R_len, c, &c_len, D, &D_len, salt, sizeof(salt));
	printf("\n-------->clientB send randA encrypted randB and R,C,d\n\n");
	printf("====================================================================================\n");
	printf("clientA recieve randA and encrypted randB and R,C,d\n\n");
	re2 = decipher(eckey2, R, R_len, c, c_len, D, D_len, salt, sizeof(salt));
	printf("====================================================================================\n");	
	sleep(8);
	printf("First, clientA check if randA is correct\n");
	sleep(1);
	printf("-------->clientA verify randA\n");
	sleep(1);
	printf("checking\n");
	sleep(1);
	printf(".\n");
	sleep(1);
	printf(".\n");
	sleep(1);
	printf(".\n");
	if(strcmp((const char*)re1,(const char*) msg1) == 0) {
		printf("verifying success!\n");
	}
	else
		printf("verifying fail.\n");
	printf("======================================================================================\n");
	sleep(1);
	printf("Then, clientA decrypt randB\n\n");
	sleep(1);
	printf("randB : ");
	for(int i=0; i<16; i++) {
		printf("%d", re2[i]);
		}
	printf("\n");
	printf("\n-------->clientA send randB\n");
	printf("======================================================================================\n");
	sleep(2);
	printf("\t\t** clientA --> clientB **\n");
	printf("clientB recieve randB\n");
	printf("clientB check if randB is correct\n");
	printf("-------->clientB verify randB\n");
	sleep(1);
	printf("checking\n");
	sleep(1);
	printf(".\n");
	sleep(1);
	printf(".\n");
	sleep(1);
	printf(".\n");
	if(strcmp((const char*)re2,(const char*) msg2) == 0) {
		printf("verifying success!\n");
	}
	else
		printf("verifying fail.\n");
	printf("======================================================================================\n");
	sleep(2);
	printf("\n** mutual authentication complete! **\n\n");
	printf("======================================================================================\n");
}
	
