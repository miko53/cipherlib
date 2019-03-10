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
  aes_obj obj;

  result = aes_init(&obj);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_generateKey(&obj, sClef, 128, 128);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(&obj, sTextACrypter, sTextCrypter, 128);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(&obj, sTextCrypter, sResultatApresDecryptage, 128);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 16, sResultatApresDecryptage, 16);
}

CTEST(aes_test, test_aes_simple_192_txt_len)
{
  unsigned char sTextACrypter[] = "ClaudiusCaligulaAUGUSTUS";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[25];
  unsigned char sResultatApresDecryptage[25];
  int result;
  aes_obj obj;

  result = aes_init(&obj);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_generateKey(&obj, sClef, 128, 192);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(&obj, sTextACrypter, sTextCrypter, 192);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(&obj, sTextCrypter, sResultatApresDecryptage, 192);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 24, sResultatApresDecryptage, 24);
}

CTEST(aes_test, test_aes_simple_256_txt_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;
  aes_obj obj;

  result = aes_init(&obj);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_generateKey(&obj, sClef, 128, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(&obj, sTextACrypter, sTextCrypter, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(&obj, sTextCrypter, sResultatApresDecryptage, 256);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 32, sResultatApresDecryptage, 32);

}

CTEST(aes_test, test_aes_simple_192_key_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF012345678";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;
  aes_obj obj;

  result = aes_init(&obj);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_generateKey(&obj, sClef, 192, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(&obj, sTextACrypter, sTextCrypter, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(&obj, sTextCrypter, sResultatApresDecryptage, 256);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 32, sResultatApresDecryptage, 32);
}



CTEST(aes_test, test_aes_simple_256_key_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF0123456789AbCdEf0";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;
  aes_obj obj;

  result = aes_init(&obj);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_generateKey(&obj, sClef, 256, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_cipher(&obj, sTextACrypter, sTextCrypter, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(&obj, sTextCrypter, sResultatApresDecryptage, 256);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sTextACrypter, 32, sResultatApresDecryptage, 32);
}



int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);

  return result;
}

