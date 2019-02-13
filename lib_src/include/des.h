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

typedef struct
{
  des_obj clefs[3];
} des3_obj;

extern DES_STATUS des_init(des_obj* des);
extern DES_STATUS des_generateKey(des_obj* des, unsigned char cypherKey[], int nKeyLen);
extern DES_STATUS des_cipher(des_obj* des, unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                             int nLenTextToCrypt, int nLenKey);
extern DES_STATUS des_uncipher(des_obj* des, unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                               int nLenTextToCrypt, int nLenKey);

extern DES_STATUS des3_init(des3_obj* des);
extern DES_STATUS des3_generateKey(des3_obj* des, unsigned char cypherKey[], int nKeyLen);
extern DES_STATUS des3_cipher(des3_obj* des, unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                              int nLenTextToCrypt, int nLenKey);
extern DES_STATUS des3_uncipher(des3_obj* des, unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                                int nLenTextToCrypt, int nLenKey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* DES_H */
