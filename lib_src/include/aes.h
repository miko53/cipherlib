#ifndef AES_H
#define AES_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define  aes_nMaxRound (14)
#define  aes_nMaxNb    (8)

typedef enum
{
  AES_OK = 0,
  AES_FAILED = -1
} AES_STATUS;

typedef struct
{
  cipher_context context;
  int nSizeBlockInBits;
  int Nk;
  int Nb;
  int Nr;
  unsigned char byTabKey[4][aes_nMaxNb][aes_nMaxRound + 1];
} aes_obj;

extern AES_STATUS aes_init(aes_obj* aes);
extern AES_STATUS aes_generateKey(aes_obj* aes, unsigned char pKey[], int nLenKeyInBits, int nLenBlockInBits);
extern AES_STATUS aes_cipher(aes_obj* aes, unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                             int nLongueurBlockInBits);
extern AES_STATUS aes_uncipher(aes_obj* aes, unsigned char pTexteCrypter[], unsigned char pTexteDeCrypter[],
                               int nLongueurBlockInBits);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */

