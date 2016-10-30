#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

// cheating, .. ignoring deprecation warnings
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

unsigned char *base64_decode(const char* base64data, int* len) {
   BIO *b64, *bmem;
   size_t length = strlen(base64data);
   unsigned char *buffer = (unsigned char *)malloc(length);
   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   bmem = BIO_new_mem_buf((void*)base64data, length);
   bmem = BIO_push(b64, bmem);
   *len = BIO_read(bmem, buffer, length);
   BIO_free_all(bmem);
   return buffer;
}

BIGNUM* bignum_base64_decode(const char* base64bignum) {
   BIGNUM* bn = NULL;
   int len;
   unsigned char* data = base64_decode(base64bignum, &len);
   if (len) {
       bn = BN_bin2bn(data, len, NULL);
   }
   free(data);
   return bn;
}

EVP_PKEY* RSA_fromBase64(const char* modulus_b64, const char* exp_b64) {
   BIGNUM *n = bignum_base64_decode(modulus_b64);
   BIGNUM *e = bignum_base64_decode(exp_b64);

   if (!n) printf("Invalid encoding for modulus\n");
   if (!e) printf("Invalid encoding for public exponent\n");

   if (e && n) {
       EVP_PKEY* pRsaKey = EVP_PKEY_new();
       RSA* rsa = RSA_new();
       rsa->e = e;
       rsa->n = n;
       EVP_PKEY_assign_RSA(pRsaKey, rsa);
       return pRsaKey;
   } else {
       if (n) BN_free(n);
       if (e) BN_free(e);
       return NULL;
   }
}

void assert_syntax(int argc, char** argv) {
   if (argc != 4) {
      fprintf(stderr, "Description: %s takes a RSA public key modulus and exponent in base64 encoding and produces a public key file in PEM format.\n", argv[0]);
      fprintf(stderr, "syntax: %s <modulus_base64> <exp_base64> <output_file>\n", argv[0]);
      exit(1);
   }
}

int main(int argc, char** argv) {
   assert_syntax(argc, argv);

   const char* modulus = argv[1];
   const char* exp = argv[2];
   const char* filename = argv[3];

   EVP_PKEY* pkey = RSA_fromBase64(modulus, exp);

   if (pkey == NULL) {
      fprintf(stderr, "an error occurred :(\n");
      return 2;
    } else {
       printf("success decoded into RSA public key\n");
       FILE* file = fopen(filename, "w");
       PEM_write_PUBKEY(file, pkey);
       fflush(file);
       fclose(file);
       printf("written to file: %s\n", filename);
    }

    return 0;
}
