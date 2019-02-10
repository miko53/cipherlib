#ifndef DES_H
#define DES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum
{
  DES_OK = 0,
  DES_FAILED = -1
} AES_STATUS;

#define  o_DES_CRYPTAGE     1
#define  o_DES_DECRYPTAGE   2


extern AES_STATUS des_cipher ( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                               unsigned char pClefCryptage[],
                               int typeAction);
extern AES_STATUS des_tripleCipher( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                    unsigned char pClefCryptage[], int typeAction);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DES_H */
