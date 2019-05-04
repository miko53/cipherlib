#ifndef __AES_LOC_H
#define __AES_LOC_H

#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define  AES_N_MAX_ROUND (14)
#define  AES_N_MAX_NB    (8)

struct aes_obj
{
  cipher_context context;
  cipher_mode mode;
  unsigned char IV[32]; //max block size if 256bits
  int Nk;
  int Nb;
  int Nr;
  unsigned char byTabKey[4][AES_N_MAX_NB][AES_N_MAX_ROUND + 1];
} ;

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __AES_LOC_H */
