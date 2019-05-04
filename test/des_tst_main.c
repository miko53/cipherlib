#define CTEST_MAIN

#include "ctest.h"
#include "des.h"

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

CTEST(des_test, cyphering_with_obj)
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

  status = des_cipher(&obj, toCrypt, cryptResult, 64);
  ASSERT_EQUAL(status, DES_OK);

  status = des_uncipher(&obj, cryptResult, uncryptResult, 64);
  ASSERT_EQUAL(status, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}

CTEST(des_test, test_des_wrong_text_len)
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

  status = des_cipher(&obj, toCrypt, cryptResult, 8);
  ASSERT_EQUAL(status, DES_WRONG_TEXT_LEN);

  status = des_uncipher(&obj, cryptResult, uncryptResult, 8);
  ASSERT_EQUAL(status, DES_WRONG_TEXT_LEN);
}

CTEST(des_test, test_des_wrong_key_len)
{
  des_obj obj;
  DES_STATUS status;
  unsigned char toCrypt[] = "Caligula";
  unsigned char key[] = "12345678";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];


  status = des_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des_generateKey(&obj, key, 2);
  ASSERT_EQUAL(status, DES_WRONG_KEY_LEN);

  status = des_cipher(&obj, toCrypt, cryptResult, 64);
  ASSERT_EQUAL(status, DES_INIT_FAILED);

  status = des_uncipher(&obj, cryptResult, uncryptResult, 64);
  ASSERT_EQUAL(status, DES_INIT_FAILED);
}


CTEST(des3_test, initialization)
{
  des3_obj obj;
  DES_STATUS status;
  unsigned char key3[] = "ClaudiusClaudiusClaudius";


  status = des3_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_generateKey(&obj, key3, 3 * 8 * 8);
  ASSERT_EQUAL(status, DES_OK);
}

CTEST(des3_test, test_triple_des_simple)
{
  des3_obj obj;
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  DES_STATUS status;

  status = des3_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_generateKey(&obj, key3, 3 * 8 * 8);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_cipher(&obj, toCrypt, cryptResult, 64);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_uncipher(&obj, cryptResult, uncryptResult, 64);
  ASSERT_EQUAL(status, DES_OK);

  //data shall be the same after deciphering
  ASSERT_DATA(uncryptResult, 8, toCrypt, 8);
}

CTEST(des3_test, test_triple_des_simple_wrong_text_len)
{
  des3_obj obj;
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  DES_STATUS status;

  status = des3_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_generateKey(&obj, key3, 3 * 8 * 8);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_cipher(&obj, toCrypt, cryptResult, 182);
  ASSERT_EQUAL(status, DES_WRONG_TEXT_LEN);

  status = des3_uncipher(&obj, cryptResult, uncryptResult, 60);
  ASSERT_EQUAL(status, DES_WRONG_TEXT_LEN);
}

CTEST(des3_test, test_triple_des_simple_wrong_key_len)
{
  des3_obj obj;
  unsigned char toCrypt[] = "Caligula";
  unsigned char key3[] = "ClaudiusClaudiusClaudius";
  unsigned char cryptResult[8];
  unsigned char uncryptResult[8];
  DES_STATUS status;

  status = des3_init(&obj);
  ASSERT_EQUAL(status, DES_OK);

  status = des3_generateKey(&obj, key3, 5);
  ASSERT_EQUAL(status, DES_WRONG_KEY_LEN);

  status = des3_generateKey(&obj, key3, 65);
  ASSERT_EQUAL(status, DES_WRONG_KEY_LEN);

  status = des3_cipher(&obj, toCrypt, cryptResult, 64);
  ASSERT_EQUAL(status, DES_INIT_FAILED);

  status = des3_uncipher(&obj, cryptResult, uncryptResult, 64);
  ASSERT_EQUAL(status, DES_INIT_FAILED);
}


int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);
  return result;
}
