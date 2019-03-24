#define CTEST_MAIN

#include "ctest.h"
#include "aes.h"

CTEST(aes_block_ecb, aes_one_block)
{
  AES_STATUS status;
  unsigned char sTextACrypter[] = "ClaudiusCaligula";
  unsigned char sKey[]         = "123456789ABCDEF0";
  unsigned char* pCipherText;
  unsigned int lenCipherText;
  unsigned char* pPlainText;
  unsigned int lenPlainText;

  AES aes = NULL;

  aes = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_cipher(aes, sTextACrypter, 16, sKey, &pCipherText, &lenCipherText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pCipherText);
  ASSERT_EQUAL(16, lenCipherText);



  AES aesUnCipher = NULL;
  aesUnCipher = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_uncipher(aesUnCipher, pCipherText, 16, sKey, &pPlainText, &lenPlainText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pPlainText);
  ASSERT_EQUAL(16, lenPlainText);

  ASSERT_DATA(sTextACrypter, 16, pPlainText, 16);

  free(pPlainText);
  free(pCipherText);

  aes_destroy(aes);
  aes_destroy(aesUnCipher);
}

CTEST(aes_block_ecb, aes_more_block)
{
  AES_STATUS status;
  unsigned char sTextACrypter[] = "ClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaClaudiusCaligula";
  unsigned char sKey[]         = "123456789ABCDEF0";
  unsigned char* pCipherText;
  unsigned int lenCipherText;
  unsigned char* pPlainText;
  unsigned int lenPlainText;

  AES aes = NULL;

  aes = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_cipher(aes, sTextACrypter, strlen((char*) sTextACrypter), sKey, &pCipherText, &lenCipherText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pCipherText);
  ASSERT_EQUAL(strlen((char*) sTextACrypter), lenCipherText);

  AES aesUnCipher = NULL;
  aesUnCipher = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_uncipher(aesUnCipher, pCipherText, lenCipherText, sKey, &pPlainText, &lenPlainText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pPlainText);
  ASSERT_EQUAL(lenCipherText, lenPlainText);
  ASSERT_EQUAL(lenCipherText, 5 * 16);

  ASSERT_DATA(sTextACrypter, lenCipherText, pPlainText, lenPlainText);

  free(pPlainText);
  free(pCipherText);

  aes_destroy(aes);
  aes_destroy(aesUnCipher);
}


CTEST(aes_block_ecb, aes_more_block_uncomplete)
{
  AES_STATUS status;
  unsigned char sTextACrypter[] = "ClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaClaudiusCaligulaABF";
  unsigned char sKey[]         = "123456789ABCDEF0";
  unsigned char* pCipherText;
  unsigned int lenCipherText;
  unsigned char* pPlainText;
  unsigned int lenPlainText;

  AES aes = NULL;

  aes = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_cipher(aes, sTextACrypter, strlen((char*) sTextACrypter), sKey, &pCipherText, &lenCipherText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pCipherText);
  ASSERT_EQUAL(6 * 16, lenCipherText);

  AES aesUnCipher = NULL;
  aesUnCipher = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_uncipher(aesUnCipher, pCipherText, lenCipherText, sKey, &pPlainText, &lenPlainText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pPlainText);
  ASSERT_EQUAL(lenCipherText, lenPlainText);
  ASSERT_EQUAL(lenCipherText, 6 * 16);

  //result is 0-padded
  char result[6 * 16];
  memset(result, '\0', 6 * 16);
  memcpy(result, sTextACrypter, strlen(sTextACrypter));

  ASSERT_DATA(result, lenCipherText, pPlainText, lenPlainText);

  free(pPlainText);
  free(pCipherText);

  aes_destroy(aes);
  aes_destroy(aesUnCipher);
}

CTEST(aes_block_ecb, aes_one_block_uncomplete)
{
  AES_STATUS status;
  unsigned char sTextACrypter[] = "Claudius";
  unsigned char sKey[]         = "123456789ABCDEF0";
  unsigned char* pCipherText;
  unsigned int lenCipherText;
  unsigned char* pPlainText;
  unsigned int lenPlainText;

  AES aes = NULL;

  aes = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_cipher(aes, sTextACrypter, strlen((char*) sTextACrypter), sKey, &pCipherText, &lenCipherText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pCipherText);
  ASSERT_EQUAL(1 * 16, lenCipherText);

  AES aesUnCipher = NULL;
  aesUnCipher = aes_block_init(AES_KEY_LEN_128BITS, AES_BLOCK_LEN_128BITS, CIPHER_MODE_ECB);
  ASSERT_NOT_NULL(aes);

  status = aes_block_uncipher(aesUnCipher, pCipherText, lenCipherText, sKey, &pPlainText, &lenPlainText);
  ASSERT_EQUAL(status, AES_OK);
  ASSERT_NOT_NULL(pPlainText);
  ASSERT_EQUAL(lenCipherText, lenPlainText);
  ASSERT_EQUAL(lenCipherText, 1 * 16);

  //result is 0-padded
  char result[1 * 16];
  memset(result, '\0', 1 * 16);
  memcpy(result, sTextACrypter, strlen(sTextACrypter));

  ASSERT_DATA(result, lenCipherText, pPlainText, lenPlainText);

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

