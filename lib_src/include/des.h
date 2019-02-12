#ifndef DES_H
#define DES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum
{
  DES_OK = 0,
  DES_FAILED = -1,
  DES_WRONG_TEXT_LEN = -2,
  DES_WRONG_KEY_LEN = -3
} DES_STATUS;

typedef struct
{
  int context;
  unsigned char cleGeneree[16][6];
} des_obj;

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

extern DES_STATUS des_init(des_obj* des);
extern DES_STATUS des_generateKey(des_obj* des, unsigned char cypherKey[], int nKeyLen);
extern DES_STATUS des_cipher2(des_obj* des, unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                              int nLenTextToCrypt, int nLenKey);
extern DES_STATUS des_uncipher2(des_obj* des, unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                                int nLenTextToCrypt, int nLenKey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DES_H */
