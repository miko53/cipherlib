#ifndef AES_H
#define AES_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum
{
  AES_OK = 0,
  AES_FAILED = -1
} AES_STATUS;

typedef enum
{
  AES_KEY_LEN_128BITS,
  AES_KEY_LEN_192BITS,
  AES_KEY_LEN_256BITS
} AES_KEY_LEN;

typedef enum
{
  AES_BLOCK_LEN_128BITS,
  AES_BLOCK_LEN_192BITS,
  AES_BLOCK_LEN_256BITS,
} AES_BLOCK_LEN;

struct aes_obj;
typedef struct aes_obj* AES;

extern AES aes_init(AES_KEY_LEN keylen, AES_BLOCK_LEN blocklen);
extern AES_STATUS aes_generateKey(AES aes, unsigned char pKey[]);
extern AES_STATUS aes_cipher(AES aes, unsigned char plaintext[], unsigned char ciphertext[]);
extern AES_STATUS aes_uncipher(AES aes, unsigned char ciphertext[], unsigned char plaintext[]);
extern void aes_destroy(AES aes);

extern AES aes_block_init(AES_KEY_LEN keylen, AES_BLOCK_LEN blocklen, cipher_mode mode);
extern AES_STATUS aes_block_cipher(AES aes, unsigned char plaintext[], unsigned int len, unsigned char key[],
                                   unsigned char** pCipherText, unsigned int* lenCipherText);
extern AES_STATUS aes_block_uncipher(AES aes, unsigned char ciphertext[], unsigned int len, unsigned char key[],
                                     unsigned char** pPlainText, unsigned int* lenPlainText);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */

