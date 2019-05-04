#define CTEST_MAIN

#include "ctest.h"
#include "aes.h"

CTEST(aes_block_cbc, check_iv)
{
  AES_STATUS status;

  AES aes;
  aes = aes_block_init(AES_KEY_LEN_192BITS, AES_BLOCK_LEN_192BITS, CIPHER_MODE_CBC);
  ASSERT_NOT_NULL(aes);

  status = aes_block_generateInitializationVector(aes);
  ASSERT_EQUAL(AES_OK, status);

  unsigned char IV[32];

  status = aes_block_getInitializationVector(aes, IV);
  ASSERT_EQUAL(AES_OK, status);

  //   for(int i = 0; i <32; i++)
  //     fprintf(stdout, "%.2x-", IV[i]);
  //   fprintf(stdout, "\n");

  memset(IV, 0, 32);

  unsigned char resultData[32];
  memset(resultData, 0, 32);

  status = aes_block_setInitializationVector(aes, IV);
  ASSERT_EQUAL(AES_OK, status);

  status = aes_block_getInitializationVector(aes, IV);
  ASSERT_EQUAL(AES_OK, status);

  ASSERT_DATA(resultData, 32, IV, 32);
}

CTEST(aes_block_cbc, cbc_ciphering_one_block)
{
  AES_STATUS status;
  unsigned char sTextACrypter[] = "ClaudiusCaligula";
  unsigned char sKey[]         = "123456789ABCDEF0";
  unsigned char* pCipherText;
  unsigned int lenCipherText;
  unsigned char* pPlainText;
  unsigned int lenPlainText;
  AES aes = NULL;
  AES aesUnCipher = NULL;

  aes = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_CBC);
  ASSERT_NOT_NULL(aes);

  status = aes_block_cipher(aes, sTextACrypter, 16, sKey, &pCipherText, &lenCipherText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pCipherText);
  ASSERT_EQUAL(32, lenCipherText);

  aesUnCipher = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_CBC);
  ASSERT_NOT_NULL(aesUnCipher);

  status = aes_block_uncipher(aesUnCipher, pCipherText, lenCipherText, sKey, &pPlainText, &lenPlainText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pPlainText);
  ASSERT_EQUAL(16, lenPlainText);
  ASSERT_DATA(sTextACrypter, 16, pPlainText, 16);

  free(pPlainText);
  free(pCipherText);

  aes_destroy(aes);
  aes_destroy(aesUnCipher);
}

CTEST(aes_block_cbc, aes_more_block)
{
  AES_STATUS status;
  unsigned char sTextACrypter[] = "ClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaClaudiusCaligula";
  unsigned char sKey[]         = "123456789ABCDEF0";
  unsigned char* pCipherText;
  unsigned int lenCipherText;
  unsigned char* pPlainText;
  unsigned int lenPlainText;

  AES aes = NULL;

  aes = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_CBC);
  ASSERT_NOT_NULL(aes);

  status = aes_block_cipher(aes, sTextACrypter, strlen((char*) sTextACrypter), sKey, &pCipherText, &lenCipherText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pCipherText);
  ASSERT_EQUAL(lenCipherText, strlen((char*) sTextACrypter) + 16); //plus one block the dummy block

  AES aesUnCipher = NULL;
  aesUnCipher = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_CBC);
  ASSERT_NOT_NULL(aes);

  status = aes_block_uncipher(aesUnCipher, pCipherText, lenCipherText, sKey, &pPlainText, &lenPlainText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pPlainText);
  ASSERT_EQUAL(lenPlainText, 5 * 16);
  ASSERT_DATA(sTextACrypter,  strlen((char*) sTextACrypter), pPlainText, lenPlainText);

  free(pPlainText);
  free(pCipherText);

  aes_destroy(aes);
  aes_destroy(aesUnCipher);
}


int main(int argc, const char* argv[])
{
  int result = ctest_main(argc, argv);
  return result;
}


