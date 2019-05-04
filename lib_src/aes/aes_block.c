#include "aes.h"
#include "aes_loc.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static BOOL aes_block_getRandomData(unsigned char* buffer, unsigned int len);
static AES_STATUS aes_block_doCipherInECBMode(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
    unsigned char** pCipherText, unsigned int* lenCipherText);
static AES_STATUS aes_block_doCipherInCBCMode(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
    unsigned char** pCipherText, unsigned int* lenCipherText);
static AES_STATUS aes_block_doUnCipherInECBMode(AES aes, unsigned char ciphertext[], unsigned int len,
    unsigned char key[], unsigned char** pPlainText, unsigned int* lenPlainText);
static AES_STATUS aes_block_doUnCipherInCBCMode(AES aes, unsigned char ciphertext[], unsigned int len,
    unsigned char key[], unsigned char** pPlainText, unsigned int* lenPlainText);


AES aes_block_init(AES_KEY_LEN keylen, AES_BLOCK_LEN blocklen, cipher_mode mode)
{
  AES aes = aes_init(keylen, blocklen);

  if (aes != NULL)
  {
    aes->mode = mode;
  }

  return aes;
}

AES_STATUS aes_block_setInitializationVector(AES aes, char IV[32])
{
  AES_STATUS status;

  if (aes == NULL)
  {
    status = AES_FAILED;
  }
  else
  {
    memcpy(aes->IV, IV, 32);
    status = AES_OK;
  }

  return status;
}

AES_STATUS aes_block_getInitializationVector(AES aes, char IV[32])
{
  AES_STATUS status;

  if (aes == NULL)
  {
    status = AES_FAILED;
  }
  else
  {
    memcpy(IV, aes->IV, 32);
    status = AES_OK;
  }

  return status;
}

static BOOL aes_block_getRandomData(unsigned char* buffer, unsigned int len)
{
  BOOL bOk;
  bOk = TRUE;

  int someRandomData = open("/dev/urandom", O_RDONLY);
  if (someRandomData < 0)
  {
    bOk = FALSE;
  }
  else
  {
    ssize_t result;
    result = read(someRandomData, buffer, len);
    if (result < 0)
    {
      bOk = FALSE;
    }
    else
    {
      bOk = TRUE;
    }
    close(someRandomData);
  }

  return bOk;
}

AES_STATUS aes_block_generateInitializationVector(AES aes)
{
  AES_STATUS status;
  status = AES_OK;

  if (aes == NULL)
  {
    status = AES_FAILED;
  }

  if (status == AES_OK)
  {
    BOOL bOk;
    bOk = aes_block_getRandomData(aes->IV, sizeof(aes->IV));
    if (bOk)
    {
      status = AES_OK;
    }
    else
    {
      status = AES_FAILED;
    }
  }

  return status;
}

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
        status = aes_block_doCipherInCBCMode(aes, plaintext, len, key, pCipherText, lenCipherText);

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


static AES_STATUS aes_block_doCipherInCBCMode(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
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

  //add a dummy block in first place
  nbMaxBlock++;

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
    unsigned char dummyBlock[blockSizeInBytes];
    unsigned char xoredBlock[blockSizeInBytes];
    BOOL bOk;

    bOk = aes_block_getRandomData(dummyBlock, blockSizeInBytes);
    if (bOk)
    {

      for (int i = 0; i < blockSizeInBytes; i++)
      {
        xoredBlock[i] = dummyBlock[i] ^ aes->IV[i];
      }

      status = aes_cipher(aes, xoredBlock, *pCipherText);

      int nbBlock;
      nbBlock = 1;

      while (nbBlock < (nbMaxBlock))
      {
        for (int i = 0; i < blockSizeInBytes; i++)
        {
          xoredBlock[i] = plaintext[blockSizeInBytes * (nbBlock - 1) + i] ^ (*pCipherText)[blockSizeInBytes * (nbBlock - 1) + i];
        }

        status = aes_cipher(aes, xoredBlock, *pCipherText + blockSizeInBytes * (nbBlock));

        nbBlock++;
      }

      //last block
      if (padding != 0)
      {
        nbBlock--;
        unsigned char lastBlock[blockSizeInBytes];
        memcpy(lastBlock, &plaintext [ (nbBlock - 1) * blockSizeInBytes], padding);
        memset(lastBlock + padding, 0, blockSizeInBytes - padding);

        for (int i = 0; i < blockSizeInBytes; i++)
        {
          xoredBlock[i] = lastBlock[i] ^ (*pCipherText)[blockSizeInBytes * (nbBlock - 1) + i];
        }

        status = aes_cipher(aes, xoredBlock, *pCipherText + nbBlock * blockSizeInBytes);
      }
      else
      {
        /*
         for (int i = 0; i < blockSizeInBytes; i++)
         {
           xoredBlock[i] = plaintext[blockSizeInBytes * (nbBlock - 1) + i] ^ (*pCipherText)[blockSizeInBytes * (nbBlock - 1) + i];
         }
         status = aes_cipher(aes, xoredBlock, *pCipherText + blockSizeInBytes * (nbBlock));*/
      }
    }
    else
    {
      status = AES_FAILED;
    }
  }

  if ((status != AES_OK) && (*pCipherText != NULL))
  {
    free(*pCipherText);
    *lenCipherText = 0;
  }

  return status;
}



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
        status = aes_block_doUnCipherInCBCMode(aes, ciphertext, len, key, pPlainText, lenPlainText);
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
    assert(FALSE); //normally not possible always of blockSizeInBytes len
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


static AES_STATUS aes_block_doUnCipherInCBCMode(AES aes, unsigned char ciphertext[], unsigned int len,
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
    assert(FALSE); // not possible
  }

  //remove the dummy block
  if (nbMaxBlock > 1)
  {
    nbMaxBlock--;
  }
  else
  {
    return AES_FAILED;
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
    unsigned char xoredBlock[blockSizeInBytes];
    int nbBlock;
    nbBlock = 1;

    while (nbBlock < (nbMaxBlock + 1))
    {
      status = aes_uncipher(aes, ciphertext + blockSizeInBytes * (nbBlock), xoredBlock);

      for (int i = 0; i < blockSizeInBytes; i++)
      {
        (*pPlainText)[blockSizeInBytes * (nbBlock - 1) + i] = xoredBlock[i] ^ ciphertext[blockSizeInBytes * (nbBlock - 1) + i];
      }
      nbBlock++;
    }

    //last block
    if (padding != 0)
    {
      //       unsigned char lastBlock[blockSizeInBytes];
      //       memcpy(lastBlock, plaintext + nbBlock * blockSizeInBytes, padding);
      //       memset(lastBlock + padding, 0, blockSizeInBytes - padding);
      //
      //       for (int i = 0; i < blockSizeInBytes; i++)
      //       {
      //         xoredBlock[i] = lastBlock[i] ^ (*pCipherText)[blockSizeInBytes * (nbBlock - 1) + i];
      //       }
      //
      //       status = aes_cipher(aes, lastBlock, *pCipherText + nbBlock * blockSizeInBytes);
    }
    else
    {
      ;
    }
  }
  else
  {
    status = AES_FAILED;
  }


  if ((status != AES_OK) && (*pPlainText != NULL))
  {
    free(*pPlainText);
    *lenPlainText = 0;
  }

  return status;
}
