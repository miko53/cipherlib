


#ifndef __DES_CRYPTAGE_H
#define __DES_CRYPTAGE_H


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define  o_DES_CRYPTAGE		1
#define  o_DES_DECRYPTAGE	2


extern int cryptageDES ( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[], unsigned char pClefCryptage[], int typeAction);
extern int cryptageTripleDES( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[], unsigned char pClefCryptage[], int typeAction);



#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __DES_CRYPTAGE_H */