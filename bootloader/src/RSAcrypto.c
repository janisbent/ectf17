#include "crypto.h"

unsigned char priv_key[] EEMEM = PRIVATE_KEY;

unsigned char publ_key[] EEMEM = PUBLIC_KEY;

int padding = RSA_PKCS1_OAEP_PADDING;
int enc_data_len = 256;

int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start) {

	RSA *private = createRSA(priv_key, false);
	RSA *public  = createRSA(publ_key, true);
	unsigned char *msg;

	int msg_size = RSA_private_decrypt(enc_data_len, frame + enc_data_len, msg, private, padding);

	if (verify(msg, msg_size, frame, enc_data_len, public) == 1) {
		buffer[buffer_start] = msg;
		return msg_size;
	} else {
		return -1;
	}
	
}

int encrypt_frame(unsigned char *frame, unsigned char *buffer,
                   unsigned int size) {

	RSA *public = createRSA(publ_key, true);
    encrypt_size = RSA_public_encrypt(size, frame, buffer, public, padding);
    return encrypt_size;
}

// http://etutorials.org/Programming/secure+programming/Chapter+7.+Public+Key+Cryptography/7.13+Verifying+Signed+Data+Using+an+RSA+Public+Key/
int verify(unsigned char *msg, unsigned int mlen, unsigned char *sig,
               unsigned int siglen, RSA *r) {
	unsigned char hash[20];
	BN_CTX        *c;
	int           ret;

	if (!(c = BN_CTX_new())) {
		return 0;
	} 
	if (!SHA1(msg, mlen, hash) || !RSA_blinding_on(r, c)) {
		BN_CTX_free(c);
		return 0;
	}

	ret = RSA_verify(NID_sha1, hash, 20, sig, siglen, r);
	RSA_blinding_off(r);
	BN_CTX_free(c);
	return ret;
}

// http://hayageek.com/rsa-encryption-decryption-openssl-c/
RSA *createRSA(unsigned char *key, bool public) {
    RSA *rsa;
    BIO *keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL) {
        printf( "Failed to create key BIO");
        return 0;
    }

    if (public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    if (rsa == NULL) {
        printf("Failed to create RSA");
        return 0;
    }
 
    return rsa;
}
