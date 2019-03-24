#include "aes.h"
#include "aes_loc.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

AES aes_block_init(AES_KEY_LEN keylen, AES_BLOCK_LEN blocklen, cipher_mode mode)
{
  AES aes = aes_init(keylen, blocklen);

  if (aes != NULL)
  {
    aes->mode = mode;
  }

  return aes;
}

AES_STATUS aes_block_setInitializationVector(AES aes, unsigned char IV[])
{
  if (aes == NULL)
  {
    return AES_FAILED;
  }
  return AES_FAILED;
}

static AES_STATUS aes_block_doCipherInECBMode(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
    unsigned char** pCipherText, unsigned int* lenCipherText);

AES_STATUS aes_block_cipher(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
                            unsigned char** pCipherText, unsigned int* lenCipherText)
{
  AES_STATUS status = AES_OK;

  if (aes == NULL)
  {
    status = AES_FAILED;
  }

  if (status == AES_OK)

    switch (aes->mode)
    {
      case CIPHER_MODE_ECB:
        status = aes_block_doCipherInECBMode(aes, plaintext, len, key, pCipherText, lenCipherText);
        break;

      case CIPHER_MODE_CBC:

        break;

      default:
        status = AES_FAILED;
        break;
    }




  return status;
}

static AES_STATUS aes_block_doCipherInECBMode(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
    unsigned char** pCipherText, unsigned int* lenCipherText)
{
  AES_STATUS status = AES_OK;

  //split plaintext in chunk of size of data.
  assert((aes->Nb == 4) || (aes->Nb == 6) || (aes->Nb == 8));

  int blockSizeInBytes = aes->Nb * 4;

  int nbMaxBlock = len / blockSizeInBytes;
  int padding = len % blockSizeInBytes;
  if (padding != 0)
  {
    nbMaxBlock++;
  }

  //allocate area
  *pCipherText = malloc(nbMaxBlock * blockSizeInBytes);
  if (*pCipherText == NULL)
  {
    status = AES_FAILED;
    *lenCipherText = 0;
  }
  else
  {
    *lenCipherText = nbMaxBlock * blockSizeInBytes;
  }

  if (status == AES_OK)
  {
    status = aes_generateKey(aes, key);
  }

  if (status == AES_OK)
  {
    int nbBock;
    nbBock = 0;


    while ((nbBock < (nbMaxBlock - 1)) && (status == AES_OK))
    {
      status = aes_cipher(aes, plaintext + nbBock * blockSizeInBytes, *pCipherText + nbBock * blockSizeInBytes);
      nbBock++;
    }

    //last block
    //nbBock++;
    if (padding != 0)
    {
      unsigned char lastBlock[blockSizeInBytes];
      memcpy(lastBlock, plaintext + nbBock * blockSizeInBytes, padding);
      memset(lastBlock + padding, 0, blockSizeInBytes - padding);
      status = aes_cipher(aes, lastBlock, *pCipherText + nbBock * blockSizeInBytes);
    }
    else
    {
      status = aes_cipher(aes, plaintext + nbBock * blockSizeInBytes, *pCipherText + nbBock * blockSizeInBytes);
    }

  }

  if ((status != AES_OK) && (*pCipherText != NULL))
  {
    free(*pCipherText);
    *lenCipherText = 0;
  }

  return status;
}


static AES_STATUS aes_block_doUnCipherInECBMode(AES aes, unsigned char ciphertext[], unsigned int len,
    unsigned char key[], unsigned char** pPlainText, unsigned int* lenPlainText);


AES_STATUS aes_block_uncipher(AES aes, unsigned char ciphertext[], unsigned int len, unsigned char key[],
                              unsigned char** pPlainText, unsigned int* lenPlainText)
{
  AES_STATUS status = AES_OK;

  if (aes == NULL)
  {
    status = AES_FAILED;
  }

  if (status == AES_OK)

    switch (aes->mode)
    {
      case CIPHER_MODE_ECB:
        status = aes_block_doUnCipherInECBMode(aes, ciphertext, len, key, pPlainText, lenPlainText);
        break;

      case CIPHER_MODE_CBC:

        break;

      default:
        status = AES_FAILED;
        break;
    }

  return status;
}


static AES_STATUS aes_block_doUnCipherInECBMode(AES aes, unsigned char ciphertext[], unsigned int len,
    unsigned char key[], unsigned char** pPlainText, unsigned int* lenPlainText)
{
  AES_STATUS status = AES_OK;

  //split plaintext in chunk of size of data.
  assert((aes->Nb == 4) || (aes->Nb == 6) || (aes->Nb == 8));

  int blockSizeInBytes = aes->Nb * 4;

  int nbMaxBlock = len / blockSizeInBytes;
  int padding = len % blockSizeInBytes;
  if (padding != 0)
  {
    nbMaxBlock++;
  }

  //allocate area
  *pPlainText = malloc(nbMaxBlock * blockSizeInBytes);
  if (*pPlainText == NULL)
  {
    status = AES_FAILED;
    *lenPlainText = 0;
  }
  else
  {
    *lenPlainText = nbMaxBlock * blockSizeInBytes;
  }

  if (status == AES_OK)
  {
    status = aes_generateKey(aes, key);
  }

  if (status == AES_OK)
  {
    int nbBock;
    nbBock = 0;


    while ((nbBock < (nbMaxBlock - 1)) && (status == AES_OK))
    {
      status = aes_uncipher(aes, ciphertext + nbBock * blockSizeInBytes, *pPlainText + nbBock * blockSizeInBytes);
      nbBock++;
    }

    //last block
    //nbBock++;
    if (padding != 0)
    {
      unsigned char lastBlock[blockSizeInBytes];
      memcpy(lastBlock, ciphertext + nbBock * blockSizeInBytes, padding);
      memset(lastBlock + padding, 0, blockSizeInBytes - padding);
      status = aes_uncipher(aes, lastBlock, *pPlainText + nbBock * blockSizeInBytes);
    }
    else
    {
      status = aes_uncipher(aes, ciphertext + nbBock * blockSizeInBytes, *pPlainText + nbBock * blockSizeInBytes);
    }

  }

  if ((status != AES_OK) && (*pPlainText != NULL))
  {
    free(*pPlainText);
    *lenPlainText = 0;
  }

  return status;
}
