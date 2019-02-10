#ifndef DES_H
#define DES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum
{
  DES_OK = 0,
  DES_FAILED = -1
} DES_STATUS;

extern DES_STATUS des_cipher ( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                               unsigned char pClefCryptage[],
                               int nLenTextToCrypt, int nLenKey);

extern DES_STATUS des_uncipher ( unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                                 unsigned char pClefCryptage[],
                                 int nLenTextToCrypt, int nLenKey);

extern DES_STATUS des_tripleCipher( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                    unsigned char pClefCryptage[],
                                    int nLenTextToCrypt, int nLenKey);

extern DES_STATUS des_tripleUncipher( unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                                      unsigned char pClefCryptage[],
                                      int nLenTextToCrypt, int nLenKey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DES_H */
