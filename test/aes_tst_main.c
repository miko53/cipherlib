#define CTEST_MAIN

#include "ctest.h"
#include "aes.h"

CTEST(aes_test, test_aes_simple)
{
  unsigned char sTextACrypter[] = "ClaudiusCaligula";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[17];;
  unsigned char sResultatApresDecryptage[17];
  int result;
  AES obj;

  obj = aes_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS);
  ASSERT_NOT_NULL(obj);

  result = aes_generateKey(obj, sClef);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(obj, sTextACrypter, sTextCrypter);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(obj, sTextCrypter, sResultatApresDecryptage);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 16, sResultatApresDecryptage, 16);

  aes_destroy(obj);
}

CTEST(aes_test, test_aes_simple_192_txt_len)
{
  unsigned char sTextACrypter[] = "ClaudiusCaligulaAUGUSTUS";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[25];
  unsigned char sResultatApresDecryptage[25];
  int result;
  AES obj;

  obj = aes_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_192BITS);
  ASSERT_NOT_NULL(obj);

  result = aes_generateKey(obj, sClef);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(obj, sTextACrypter, sTextCrypter);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(obj, sTextCrypter, sResultatApresDecryptage);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 24, sResultatApresDecryptage, 24);

  aes_destroy(obj);
}

CTEST(aes_test, test_aes_simple_256_txt_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;
  AES obj;

  obj = aes_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_256BITS);
  ASSERT_NOT_NULL(obj);

  result = aes_generateKey(obj, sClef);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(obj, sTextACrypter, sTextCrypter);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(obj, sTextCrypter, sResultatApresDecryptage);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 32, sResultatApresDecryptage, 32);

  aes_destroy(obj);
}

CTEST(aes_test, test_aes_simple_192_key_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF012345678";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;
  AES obj;

  obj = aes_init(AES_KEY_LEN_192BITS, AES_BLOCK_LEN_256BITS);
  ASSERT_NOT_NULL(obj);

  result = aes_generateKey(obj, sClef);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(obj, sTextACrypter, sTextCrypter);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(obj, sTextCrypter, sResultatApresDecryptage);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 32, sResultatApresDecryptage, 32);

  aes_destroy(obj);
}



CTEST(aes_test, test_aes_simple_256_key_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF0123456789AbCdEf0";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;
  AES obj;

  obj = aes_init(AES_KEY_LEN_256BITS, AES_BLOCK_LEN_256BITS);
  ASSERT_NOT_NULL(obj);

  result = aes_generateKey(obj, sClef);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(obj, sTextACrypter, sTextCrypter);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(obj, sTextCrypter, sResultatApresDecryptage);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 32, sResultatApresDecryptage, 32);

  aes_destroy(obj);
}


int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);
  return result;
}

