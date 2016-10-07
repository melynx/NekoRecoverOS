/*
 * The implementation is modified from the original verify_file() function found in Android Eclair
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include <dirent.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

#include "verifier.h"

// Look for an RSA signature embedded in the .ZIP file comment given
// the path to the zip.  Verify it matches one of the given public
// keys.
//
// Return VERIFY_SUCCESS, VERIFY_FAILURE (if any error is encountered
// or no key matches the signature).

int verify_file(const char* path) 
{
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        printf("failed to open %s\n", path);
        return VERIFY_FAILURE;
    }

    // An archive with a whole-file signature will end in six bytes:
    //
    //   (2-byte signature start) $ff $ff (2-byte comment size)
    //
    // (As far as the ZIP format is concerned, these are part of the
    // archive comment.)  We start by reading this footer, this tells
    // us how far back from the end we have to start reading to find
    // the whole comment.

#define FOOTER_SIZE 6

    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        printf("failed to seek in %s\n", path);
        fclose(f);
        return VERIFY_FAILURE;
    }

    unsigned char footer[FOOTER_SIZE];
    if (fread(footer, 1, FOOTER_SIZE, f) != FOOTER_SIZE) {
        printf("failed to read footer from %s\n", path);
        fclose(f);
        return VERIFY_FAILURE;
    }

    if (footer[2] != 0xff || footer[3] != 0xff) {
        fclose(f);
        return VERIFY_FAILURE;
    }

    int comment_size = footer[4] + (footer[5] << 8);
    int signature_start = footer[0] + (footer[1] << 8);
    printf("comment is %d bytes; signature %d bytes from end\n",
         comment_size, signature_start);

#define EOCD_HEADER_SIZE 22

    // The end-of-central-directory record is 22 bytes plus any
    // comment length.
    size_t eocd_size = comment_size + EOCD_HEADER_SIZE;

    if (fseek(f, -eocd_size, SEEK_END) != 0) {
        printf("failed to seek in %s\n", path);
        fclose(f);
        return VERIFY_FAILURE;
    }

    // Determine how much of the file is covered by the signature.
    // This is everything except the signature data and length, which
    // includes all of the EOCD except for the comment length field (2
    // bytes) and the comment data.
    size_t signed_len = ftell(f) + EOCD_HEADER_SIZE - 2;

    unsigned char* eocd = malloc(eocd_size);
    if (eocd == NULL) {
        printf("malloc for EOCD record failed\n");
        fclose(f);
        return VERIFY_FAILURE;
    }
    if (fread(eocd, 1, eocd_size, f) != eocd_size) {
        printf("failed to read eocd from %s\n", path);
        fclose(f);
        return VERIFY_FAILURE;
    }

    // If this is really is the EOCD record, it will begin with the
    // magic number $50 $4b $05 $06.
    if (eocd[0] != 0x50 || eocd[1] != 0x4b ||
        eocd[2] != 0x05 || eocd[3] != 0x06) {
        printf("signature length doesn't match EOCD marker\n");
        fclose(f);
        return VERIFY_FAILURE;
    }

    int i;
    for (i = 4; i < eocd_size-3; ++i) {
        if (eocd[i  ] == 0x50 && eocd[i+1] == 0x4b &&
            eocd[i+2] == 0x05 && eocd[i+3] == 0x06) {
            // if the sequence $50 $4b $05 $06 appears anywhere after
            // the real one, minzip will find the later (wrong) one,
            // which could be exploitable.  Fail verification if
            // this sequence occurs anywhere after the real one.
            printf("EOCD marker occurs after start of EOCD\n");
            fclose(f);
            return VERIFY_FAILURE;
        }
    }

    unsigned char *content = malloc(signed_len);

    fseek(f, 0, SEEK_SET);
    fread(content, 1, signed_len, f);

    uint8_t* signature = eocd + eocd_size - signature_start;
    size_t signature_size = signature_start - FOOTER_SIZE;

    int ret = openssl_verify_signature(signature, signature_size, content, signed_len); 

    free(eocd);
    free(content);

    return ret;
}

int openssl_verify_signature(unsigned char *signature, size_t signature_len, unsigned char *content, size_t content_len)
{
    // zl: use openssl instead of mincrypt to do the certificate verification
    int ret = 1;

    BIO *in = NULL, *tbio = NULL, *p7bio = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    PKCS7 *p7 = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();

    /* Read in signer certificates */
    DIR *dir;
    struct dirent *dp;
    char buf[1024];
    char *cert_dir = "/root/ota/certs/";

    dir = opendir(cert_dir);
    if (dir != NULL)
    {
    	while (dp = readdir(dir))
	{
		if (strncmp(dp->d_name, ".", 1) == 0)
			continue;

		strncpy(buf, cert_dir, 1024);
		strncat(buf, dp->d_name, 1024);

		tbio = BIO_new_file(buf, "r");

		if (!tbio)
			goto err;

		cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

		if (!cacert)
			goto err;
		if (!X509_STORE_add_cert(st, cacert))
			goto err;
	}
	(void)closedir(dir);
    }

    in = BIO_new_mem_buf(content, content_len);
    p7bio = BIO_new_mem_buf(signature, signature_len);

    /* Sign content */
    p7 = d2i_PKCS7_bio(p7bio, NULL);
    if (!p7) {
        printf("Could not find signature DER block");
	goto err;
    }

    if (!PKCS7_verify(p7, NULL, st, in, NULL, PKCS7_DETACHED)) 
    {
        goto err;
    }

    //fprintf(stderr, "Verification Successful\n"); 
    ret = 0;

err:
    if (ret) {
        //fprintf(stderr, "Error Verifying Data\n");
        //ERR_print_errors_fp(stderr);
    }

    PKCS7_free(p7);
    X509_free(cacert);
    BIO_free(in);
    BIO_free(p7bio);
    BIO_free(tbio);
    return ret;
}
