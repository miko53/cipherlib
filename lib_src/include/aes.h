#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum
{
  AES_OK = 0,
  AES_FAILED = -1
} AES_STATUS;

extern AES_STATUS aes_cipher(unsigned char pTexteACrypter[], unsigned char pTexteCrypter[], unsigned char pClef[],
                             int nLongueurBlockInBits, int nLongueurClefInBits);

extern AES_STATUS aes_uncipher(unsigned char pTexteCrypter[], unsigned char pTexteDeCrypter[], unsigned char pClef[],
                               int nLongueurBlockInBits, int nLongueurClefInBits);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* AES_H */

