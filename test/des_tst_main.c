#define CTEST_MAIN

#include "ctest.h"
#include "des.h"

CTEST(des_test, test_des_simple)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key[] = "Claudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  int result;
  result = des_cipher(toCrypt, cryptResult, key, o_DES_CRYPTAGE);
  ASSERT_EQUAL(result, DES_OK);

  result = des_cipher(cryptResult, uncryptResult, key, o_DES_DECRYPTAGE);
  ASSERT_EQUAL(result, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}

CTEST(des_test, test_triple_des_simple)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  int result;
  result = des_tripleCipher(toCrypt, cryptResult, key3, o_DES_CRYPTAGE);
  ASSERT_EQUAL(result, DES_OK);

  result = des_tripleCipher(cryptResult, uncryptResult, key3, o_DES_DECRYPTAGE);
  ASSERT_EQUAL(result, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}


int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);

  return result;
}
