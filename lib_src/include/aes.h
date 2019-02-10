

#ifndef AES_H
#define AES_H

extern int AEScryptage(unsigned char pTexteACrypter[], unsigned char pTexteCrypter[], unsigned char pClef[],
                       int nLongueurBlock, int nLongueurClef);

extern int AESDecryptage(unsigned char pTexteCrypter[], unsigned char pTexteDeCrypter[], unsigned char pClef[],
                         int nLongueurBlock, int nLongueurClef);



#endif /* AES_H */

