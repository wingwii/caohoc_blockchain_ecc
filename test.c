#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>

EC_KEY* GenerateKey()
{
	EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_generate_key(key);
	return key;
}

EC_KEY* LoadKey(const unsigned char* key, int keyLen)
{
	BIO* bio = BIO_new_mem_buf((void*)key, keyLen);
	EC_KEY* k = PEM_read_bio_ECPrivateKey(bio, 0, 0, 0);
	BIO_free(bio);
	return k;
}

int SignMessage(
	const unsigned char* key, int keyLen, 
	const unsigned char* msg, int msgLen, 
	unsigned char** signature, int* signatureLen
)
{
	int result = 0;
	EC_KEY* k = LoadKey(key, keyLen);
	ECDSA_SIG *s = ECDSA_do_sign(msg, msgLen, k);
	if (s != 0)
	{
		int len = ECDSA_size(s);
		(*signature) = (unsigned char *)malloc(len);
		(*signatureLen) = i2d_ECDSA_SIG(s, signature);
		result = 1;
	}
	EC_KEY_free(k);
	return result;
}

void VerifyMessage(
	const unsigned char* key, int keyLen, 
	const unsigned char* msg, int msgLen, 
	const unsigned char* signature, int signatureLen
)
{
	EC_KEY* k = LoadKey(key, keyLen);
	ECDSA_SIG* s = ECDSA_SIG_new();
	d2i_ECDSA_SIG(&s, signature, signatureLen);
	int ret = ECDSA_do_verify(msg, msgLen, s, k);
	EC_KEY_free(key);
	ECDSA_SIG_free(s);
}


int main(int argc, const char* argv[])
{
	SignMessage(0, 0, 0, 0, 0, 0);
	VerifyMessage(0, 0, 0, 0, 0, 0);
	
	return 0;
}
