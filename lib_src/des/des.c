/* DES.c implementation file  */
/* M. Sergent 02-2001;04-2001 */

/* realisation d'algo data encryption standard */
#include "des.h"
#include <assert.h>

/* constantes */
typedef enum
{
  DES_CRYPTAGE,
  DES_DECRYPTAGE
} des_cipheringAction;

const int des_nbBouclesDES = 16;

const int des_tablePermutation[] =
{
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
};

const int des_tablePermutation32a48bits[] =
{
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1
};

const int des_tablePermutation64a56bits[] =
{
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,

  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4
};

const int des_tablePermutation56a48bits[] =
{
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32
};

const int des_tableDecalage[] =
{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

const unsigned char des_tableauSelectionBlocs[8][4][16] =
{
  {   /* 1 */
    { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
    {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12,  1,  9,  5,  3,  8 },
    {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
    { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
  },
  {   /* 2 */
    { 15,  1,  8, 14, 11,  6,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
    {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
    {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
    { 13,  8, 10,  1,  3,  4, 15,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
  },
  {   /* 3 */
    { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
    { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
    { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
    {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
  },
  {   /* 4 */
    {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
    { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
    { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
    {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
  },
  {   /* 5 */
    {  2, 14,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
    { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
    {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
    { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
  },
  {   /* 6 */
    { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  3,  4, 14,  7,  5 },
    { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
    {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13,  1,  6 },
    {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
  },
  {   /* 7 */
    {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
    { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
    {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
    {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
  },
  {   /* 8 */
    { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
    {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
    {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
    {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
  }
};

const int des_tablePermutationFinaleDroit[] =
{
  16,  7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2,  8, 24, 14,
  32, 27,  3,  9,
  19, 13, 30,  6,
  22, 11,  4, 25
};


const int des_tablePermutationDerniere[] =
{
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25
};


/* static function declaration */
static void des_bitPermutation2(int noBit1, int noBit2, unsigned char* element, unsigned char* sortie);
static void des_generateurCleCodage(unsigned char* pcCle, unsigned char tabSortieCle[][6]);
static unsigned char des_pariteBit(unsigned char octetTest);
static unsigned char des_selection4bits(unsigned char paquet6bits, int noBloc);

static DES_STATUS des_ciphering ( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                  unsigned char pClefCryptage[],
                                  des_cipheringAction typeAction);
static DES_STATUS des_tripleCiphering( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                       unsigned char pClefCryptage[],
                                       des_cipheringAction typeAction);

DES_STATUS des_cipher ( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                        unsigned char pClefCryptage[],
                        int nLenTextToCrypt, int nLenKey)
{
  if (nLenTextToCrypt != 64)
  {
    return DES_WRONG_TEXT_LEN;
  }

  if (nLenKey != 64)
  {
    return DES_WRONG_KEY_LEN;
  }

  return des_ciphering (pTexteACrypter, pTexteCrypter, pClefCryptage, DES_CRYPTAGE);
}


DES_STATUS des_uncipher ( unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                          unsigned char pClefCryptage[],
                          int nLenTextToCrypt, int nLenKey)
{
  if (nLenTextToCrypt != 64)
  {
    return DES_WRONG_TEXT_LEN;
  }

  if (nLenKey != 64)
  {
    return DES_WRONG_KEY_LEN;
  }

  return des_ciphering (pTexteCrypter, pTexteDeCrypte, pClefCryptage, DES_DECRYPTAGE);
}

extern DES_STATUS des_tripleCipher( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                    unsigned char pClefCryptage[],
                                    int nLenTextToCrypt, int nLenKey)
{
  if (nLenTextToCrypt != 192)
  {
    return DES_WRONG_TEXT_LEN;
  }

  if (nLenKey != 192)
  {
    return DES_WRONG_KEY_LEN;
  }

  return des_tripleCiphering(pTexteACrypter, pTexteCrypter, pClefCryptage, DES_CRYPTAGE);
}

extern DES_STATUS des_tripleUncipher( unsigned char pTexteCrypter[], unsigned char pTexteDeCrypte[],
                                      unsigned char pClefCryptage[],
                                      int nLenTextToCrypt, int nLenKey)
{
  if (nLenTextToCrypt != 192)
  {
    return DES_WRONG_TEXT_LEN;
  }

  if (nLenKey != 192)
  {
    return DES_WRONG_KEY_LEN;
  }

  return des_tripleCiphering(pTexteCrypter, pTexteDeCrypte, pClefCryptage, DES_DECRYPTAGE);
}


static DES_STATUS des_ciphering ( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                  unsigned char pClefCryptage[],
                                  des_cipheringAction typeAction)
{
  register int i, j;

  unsigned char sortiePermutationInitiale[8];
  unsigned char finCryptage[8];
  unsigned char bloc6Bits[8];

  unsigned char Gauche[4];
  unsigned char Droit[4];
  unsigned char DroitAvantPermutation[4];
  unsigned char DroitApresPermutation[4];

  unsigned char valeur48bits[6];
  unsigned char valeurApresCle[6];

  unsigned char cleGeneree[16][6];

  unsigned char tempo;

  assert((typeAction == DES_CRYPTAGE) || (typeAction == DES_DECRYPTAGE));

  des_generateurCleCodage(pClefCryptage, cleGeneree);

  /* permutation d'entree */
  for (i = 1; i < 65; i++)
  {
    des_bitPermutation2(des_tablePermutation[i - 1], i, pTexteACrypter, sortiePermutationInitiale);
  }

  for (i = 0; i < 4; i++)
  {
    Gauche[i] = sortiePermutationInitiale[i];
  }

  for (i = 0; i < 4; i++)
  {
    Droit[i] = sortiePermutationInitiale[4 + i];
  }

  for (j = 0; j < des_nbBouclesDES; j++)
  {
    /* mise a zero des variables critiques */
    for (i = 0; i < 4; i++)
    {
      valeur48bits[i] = 0;
      DroitAvantPermutation[i] = 0;
      DroitApresPermutation[i] = 0;
    }

    valeur48bits[4] = 0;
    valeur48bits[5] = 0;


    /* partie droite de 32bits a 48bits par une permutation */
    for (i = 1; i < 49; i++)
    {
      des_bitPermutation2(des_tablePermutation32a48bits[i - 1], i, Droit, valeur48bits);
    }

    if (typeAction == DES_CRYPTAGE)
    {
      for (i = 0; i < 6; i++)
      {
        valeurApresCle[i] = valeur48bits[i] ^ cleGeneree[j][i];
      }
    }
    else
    {
      for (i = 0; i < 6; i++)
      {
        valeurApresCle[i] = valeur48bits[i] ^ cleGeneree[15 - j][i];
      }
    }

    bloc6Bits[0] = ( valeurApresCle[0] >> 2);
    bloc6Bits[1] = ((valeurApresCle[0] & 0x03) << 4) + ((valeurApresCle[1] & 0xF0) >> 4);
    bloc6Bits[2] = ((valeurApresCle[1] & 0x0F) << 2) + ((valeurApresCle[2] & 0xC0) >> 6);
    bloc6Bits[3] = ( valeurApresCle[2] & 0x3F);
    bloc6Bits[4] = ( valeurApresCle[3] >> 2);
    bloc6Bits[5] = ((valeurApresCle[3] & 0x03) << 4) + ((valeurApresCle[4] & 0xF0) >> 4);
    bloc6Bits[6] = ((valeurApresCle[4] & 0x0F) << 2) + ((valeurApresCle[5] & 0xC0) >> 6);
    bloc6Bits[7] = ( valeurApresCle[5] & 0x3F);

    /* Reconstitution des 32 bits droits */
    for (i = 0; i < 8; i++)
    {
      tempo = des_selection4bits(bloc6Bits[i], i);
      if ((i % 2) == 0)
      {
        tempo = tempo << 4;
      }

      DroitAvantPermutation[(i >> 1)] += tempo;
    }

    /* derniere permutation  sur les bits droits */
    for (i = 1; i < 33; i++)
    {
      des_bitPermutation2(des_tablePermutationFinaleDroit[i - 1], i, DroitAvantPermutation, DroitApresPermutation);
    }

    if (j == (des_nbBouclesDES - 1))
    {
      for (i = 0; i < 4; i++)
      {
        finCryptage[4 + i] = Droit[i];
      }

      for (i = 0; i < 4; i++)
      {
        finCryptage[i] = DroitApresPermutation[i] ^ Gauche[i];
      }
    }
    else
    {
      for (i = 0; i < 4; i++)
      {
        finCryptage[i] = Droit[i];
      }

      for (i = 0; i < 4; i++)
      {
        finCryptage[4 + i] = DroitApresPermutation[i] ^ Gauche[i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      Gauche[i] = finCryptage[i];
      Droit[i] = finCryptage[i + 4];
    }
  }

  for (i = 1; i < 65; i++)
  {
    des_bitPermutation2(des_tablePermutationDerniere[i - 1], i, finCryptage, pTexteCrypter);
  }

  return DES_OK;
}


static DES_STATUS des_tripleCiphering( unsigned char pTexteACrypter[], unsigned char pTexteCrypter[],
                                       unsigned char pClefCryptage[],
                                       des_cipheringAction typeAction)
{
  register int i;
  unsigned char pClefCryptage1[9];
  unsigned char pClefCryptage2[9];
  unsigned char pClefCryptage3[9];

  pClefCryptage1[8] = 0;
  pClefCryptage2[8] = 0;
  pClefCryptage3[8] = 0;

  for (i = 0; i < 8; i++)
  {
    pClefCryptage1[i] = pClefCryptage[i];
    pClefCryptage2[i] = pClefCryptage[8 + i];
    pClefCryptage3[i] = pClefCryptage[16 + i];
  }

  assert((typeAction == DES_CRYPTAGE) || (typeAction == DES_DECRYPTAGE));

  if (typeAction == DES_CRYPTAGE)
  {
    des_ciphering(pTexteACrypter, pTexteCrypter, pClefCryptage1, DES_CRYPTAGE);
    des_ciphering(pTexteCrypter, pTexteCrypter, pClefCryptage2, DES_CRYPTAGE);
    des_ciphering(pTexteCrypter, pTexteCrypter, pClefCryptage3, DES_CRYPTAGE);
  }
  else
  {
    des_ciphering(pTexteACrypter, pTexteCrypter, pClefCryptage3, DES_DECRYPTAGE);
    des_ciphering(pTexteCrypter, pTexteCrypter, pClefCryptage2, DES_DECRYPTAGE);
    des_ciphering(pTexteCrypter, pTexteCrypter, pClefCryptage1, DES_DECRYPTAGE);
  }

  return DES_OK;
}



/* static function implementation */

/* generation de la cle, la cle est rentre comme une chaine de char
   la fonction crer les 16 cles pour les cycles et les place dans
   tabSortieCle */

static void des_generateurCleCodage(unsigned char* pcCle, unsigned char tabSortieCle[][6])
{
  register int i, j;
  unsigned char pcCle2[8] = {0};
  unsigned char valeur56bits[7] = {0};
  unsigned char dernierBit0;

  for (i = 0; i < 8; i++)
  {
    pcCle2[i] = (pcCle[i] << 1) + des_pariteBit(pcCle[i]);
  }

  for (i = 1; i < 57; i++)
  {
    des_bitPermutation2(des_tablePermutation64a56bits[i - 1], i, pcCle2, valeur56bits);
  }

  /* decalage a gauche selon table des decalages */
  for (i = 0; i < 16; i++)
  {
    for (j = 0; j < des_tableDecalage[i]; j++)
    {
      int k;
      /* effectue une rotation a gauche sur 56 bits */
      dernierBit0 = (unsigned char) ((valeur56bits[0] & 0x80) >> 7);
      for (k = 0; k < 6; k++)
      {
        valeur56bits[k] = (valeur56bits[k] << 1) + ((valeur56bits[k + 1] & 0x80) >> 7);
      }
      valeur56bits[6] = (valeur56bits[6] << 1) + dernierBit0;
    }

    /* une fois le bon nombre de rotation effectuer, effectuer la permutation inverse */
    for (j = 1; j < 49; j++)
    {
      des_bitPermutation2(des_tablePermutation56a48bits[j - 1], j, valeur56bits,  &(tabSortieCle[i][0]));
    }
  }
}


static unsigned char des_pariteBit(unsigned char octetTest)
{
  register int i;
  unsigned char nombreUn = 0;
  unsigned char decalage;

  for (i = 0; i < 8; i++)
  {
    decalage = (1 << i);

    if ((octetTest & decalage) == decalage)
    {
      /* c'est un 1 */
      nombreUn++;
    }
  }

  if ((nombreUn % 2) == 0)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

static unsigned char des_selection4bits(unsigned char paquet6bits, int noBloc)
{
  unsigned char ligne;
  unsigned char colonne;

  ligne = ((paquet6bits & 0x20) >> 4) + (paquet6bits & 0x01);
  colonne = ((paquet6bits & 0x1E) >> 1);

  return (des_tableauSelectionBlocs[noBloc][ligne][colonne]);
}

static void des_bitPermutation2(int noBit1, int noBit2, unsigned char element[], unsigned char sortie[])
{
  int offset1;
  int offset2;
  int decalage1;
  int decalage2;
  unsigned char bit1;

  offset1 = ((noBit1 - 1) / 8);
  decalage1 =	((noBit1) % 8);

  offset2 = ((noBit2 - 1) / 8);
  decalage2 =	((noBit2) % 8);

  if (decalage1 != 0)
  {
    decalage1--;
  }
  else
  {
    decalage1 = 7;
  }

  if (decalage2 != 0)
  {
    decalage2--;
  }
  else
  {
    decalage2 = 7;
  }


  bit1 = (unsigned char) ((element[offset1] & (0x80 >> decalage1)) >> (7 - decalage1));

  if (bit1 >= 1)
  {
    sortie[offset2] |= (0x80 >> decalage2);
  }
  else
  {
    sortie[offset2] &= ~(0x80 >> decalage2);
  }

}
