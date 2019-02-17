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

  result = aes_cipher(sTextACrypter, sTextCrypter, sClef, 128, 128);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(sTextCrypter, sResultatApresDecryptage, sClef, 128, 128);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sResultatApresDecryptage, 16, sTextACrypter, 16);
}

CTEST(aes_test, test_aes_simple_192_txt_len)
{
  unsigned char sTextACrypter[] = "ClaudiusCaligulaAUGUSTUS";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[25];
  unsigned char sResultatApresDecryptage[25];
  int result;

  result = aes_cipher(sTextACrypter, sTextCrypter, sClef, 192, 128);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(sTextCrypter, sResultatApresDecryptage, sClef, 192, 128);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sResultatApresDecryptage, 24, sTextACrypter, 24);
}

CTEST(aes_test, test_aes_simple_256_txt_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF0";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;

  result = aes_cipher(sTextACrypter, sTextCrypter, sClef, 256, 128);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(sTextCrypter, sResultatApresDecryptage, sClef, 256, 128);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sResultatApresDecryptage, 32, sTextACrypter, 32);
}

CTEST(aes_test, test_aes_simple_192_key_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF012345678";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;

  result = aes_cipher(sTextACrypter, sTextCrypter, sClef, 256, 192);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(sTextCrypter, sResultatApresDecryptage, sClef, 256, 192);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sResultatApresDecryptage, 32, sTextACrypter, 32);
}



CTEST(aes_test, test_aes_simple_256_key_len)
{
  unsigned char sTextACrypter[] = "Sed ut perspiciatis unde omnis i";
  unsigned char sClef[]         = "123456789ABCDEF0123456789AbCdEf0";
  unsigned char sTextCrypter[33];
  unsigned char sResultatApresDecryptage[33];
  int result;

  result = aes_cipher(sTextACrypter, sTextCrypter, sClef, 256, 256);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(sTextCrypter, sResultatApresDecryptage, sClef, 256, 256);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sResultatApresDecryptage, 32, sTextACrypter, 32);
}



int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);

  return result;
}

