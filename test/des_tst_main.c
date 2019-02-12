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
  result = des_cipher(toCrypt, cryptResult, key, 64, 64);
  ASSERT_EQUAL(result, DES_OK);

  result = des_uncipher(cryptResult, uncryptResult, key, 64, 64);
  ASSERT_EQUAL(result, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}

CTEST(des_test, test_des_wrong_text_len)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key[] = "Claudius";
  unsigned char cryptResult[8];
  int result;
  result = des_cipher(toCrypt, cryptResult, key, 8, 64);
  ASSERT_EQUAL(result, DES_WRONG_TEXT_LEN);
  result = des_uncipher(toCrypt, cryptResult, key, 8, 64);
  ASSERT_EQUAL(result, DES_WRONG_TEXT_LEN);
}

CTEST(des_test, test_des_wrong_key_len)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key[] = "Claudius";
  unsigned char cryptResult[8];
  int result;
  result = des_cipher(toCrypt, cryptResult, key, 64, 2);
  ASSERT_EQUAL(result, DES_WRONG_KEY_LEN);
  result = des_uncipher(toCrypt, cryptResult, key, 64, 2);
  ASSERT_EQUAL(result, DES_WRONG_KEY_LEN);
}

CTEST(des_test, test_triple_des_simple)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  int result;
  result = des_tripleCipher(toCrypt, cryptResult, key3, 192, 192);
  ASSERT_EQUAL(result, DES_OK);

  result = des_tripleUncipher(cryptResult, uncryptResult, key3, 192, 192);
  ASSERT_EQUAL(result, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}

CTEST(des_test, test_triple_des_simple_wrong_text_len)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  int result;
  result = des_tripleCipher(toCrypt, cryptResult, key3, 182, 192);
  ASSERT_EQUAL(result, DES_WRONG_TEXT_LEN);

  result = des_tripleUncipher(cryptResult, uncryptResult, key3, 60, 192);
  ASSERT_EQUAL(result, DES_WRONG_TEXT_LEN);
}

CTEST(des_test, test_triple_des_simple_wrong_key_len)
{
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  int result;
  result = des_tripleCipher(toCrypt, cryptResult, key3, 192, 5);
  ASSERT_EQUAL(result, DES_WRONG_KEY_LEN);

  result = des_tripleUncipher(cryptResult, uncryptResult, key3, 192, 65);
  ASSERT_EQUAL(result, DES_WRONG_KEY_LEN);
}


CTEST(des_obj, initialization)
{
  des_obj obj;
  DES_STATUS status;
  unsigned char key[] = "12345678";


  status = des_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des_generateKey(&obj, key, 8 * 8);
  ASSERT_EQUAL(status, DES_OK);
}

CTEST(des_obj, cyphering_with_obj)
{
  des_obj obj;
  DES_STATUS status;
  unsigned char toCrypt[] = "Caligula";
  unsigned char key[] = "12345678";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];


  status = des_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des_generateKey(&obj, key, 8 * 8);
  ASSERT_EQUAL(status, DES_OK);

  status = des_cipher2(&obj, toCrypt, cryptResult, 64, 64);
  ASSERT_EQUAL(status, DES_OK);

  status = des_uncipher2(&obj, cryptResult, uncryptResult, 64, 64);
  ASSERT_EQUAL(status, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}



int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);

  return result;
}
