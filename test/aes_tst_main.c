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
  unsigned char sTextCrypter[17];;
  unsigned char sResultatApresDecryptage[17];
  int result;

  result = aes_cipher(sTextACrypter, sTextCrypter, sClef, 192, 128);
  ASSERT_EQUAL(result, AES_OK);

  result = aes_uncipher(sTextCrypter, sResultatApresDecryptage, sClef, 192, 128);
  ASSERT_EQUAL(result, AES_OK);

  ASSERT_DATA(sResultatApresDecryptage, 24, sTextACrypter, 24);
}


int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);

  return result;
}

