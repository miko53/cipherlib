#include "aes.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include "aes_loc.h"

static const unsigned char aes_byByteSubTransformation[256] =
{
  99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118,
  202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
  183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21,
  4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117,
  9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
  83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207,
  208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,
  81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210,
  205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115,
  96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
  224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121,
  231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8,
  186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138,
  112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158,
  225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
  140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22
};

static const unsigned char aes_byInvByteSubTransformation[256] =
{
  82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
  124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
  84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
  8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
  114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
  108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
  144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
  208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
  58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
  150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
  71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
  252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
  31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
  96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
  160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
  23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125
};


static const unsigned char aes_byLogtable[256] =
{
  0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3,
  100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193,
  125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120,
  101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142,
  150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56,
  102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16,
  126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186,
  43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87,
  175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,
  44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160,
  127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183,
  204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157,
  151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,
  83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171,
  68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165,
  103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7,
};


static const unsigned char aes_byAlogtable[256] =
{
  1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
  95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
  229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
  83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
  76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
  131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
  181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
  254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
  251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
  195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
  159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
  155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
  252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
  69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
  18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
  57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1,
};


static const unsigned long aes_dwRoundCnst[30] =
{
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};


static void aes_mixColumn(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);
static void aes_invMixColumn(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);

static unsigned char aes_multiplicationGF2Poly(unsigned char a, unsigned char b);
static void aes_shiftRow(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);
static void aes_invShiftRow(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);

static void aes_rotationLignes(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb, int nNoLigne, int NbRotation);
static void aes_rotationLignesDroite(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb, int nNoLigne,
                                     int NbRotation);

static void aes_invByteSub(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);
static void aes_byteSub(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);

static void aes_formatteBlock(unsigned char byBlock[], unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb);
static void aes_formatteKey(unsigned long dwTabKey[], unsigned char byTabKey[4][AES_N_MAX_NB][AES_N_MAX_ROUND + 1],
                            int nNb,
                            int nNr);

static void aes_addRoundKey(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb,
                            unsigned char byBlockKey[4][AES_N_MAX_NB][AES_N_MAX_ROUND + 1],
                            int nRound);

static void aes_calculExpansionKeyInf6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr);
static void aes_calculExpansionKeySup6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr);

static unsigned long aes_rotByte(unsigned long dwValue);
static unsigned long aes_subByte(unsigned long dwValue);

static void aes_doCiphering(AES aes, unsigned char plaintext[], unsigned char ciphertext[]);
static void aes_doUnCiphering(AES aes, unsigned char ciphertext[], unsigned char plaintext[]);


AES aes_init(AES_KEY_LEN keylen, AES_BLOCK_LEN blocklen)
{
  AES aes;

  aes = malloc(sizeof(struct aes_obj));
  if (aes != NULL)
  {
    aes->context = CIPHER_INITIALIZED;
    switch (keylen)
    {
      case AES_KEY_LEN_128BITS:
        aes->Nk = 4;
        break;

      case AES_KEY_LEN_192BITS:
        aes->Nk = 6;
        break;

      case AES_KEY_LEN_256BITS:
        aes->Nk = 8;
        break;

      default:
        free(aes);
        aes = NULL;
    }
  }

  if (aes != NULL)
  {
    switch (blocklen)
    {
      case AES_BLOCK_LEN_128BITS:
        aes->Nb = 4;
        break;

      case AES_BLOCK_LEN_192BITS:
        aes->Nb = 6;
        break;

      case AES_BLOCK_LEN_256BITS:
        aes->Nb = 8;
        break;

      default:
        free(aes);
        aes = NULL;
    }
  }

  if (aes != NULL)
  {
    //calculate nb of necc. round according to data len
    if (aes->Nk > aes->Nb)
    {
      aes->Nr = aes->Nk;
    }
    else
    {
      aes->Nr = aes->Nb;
    }

    switch (aes->Nr)
    {
      case 4:
        aes->Nr = 10;
        break;

      case 6:
        aes->Nr = 12;
        break;

      case 8:
        aes->Nr = 14;
        break;

      default:
        assert(FALSE); //not possible to reach here...
    }

  }

  return aes;
}


void aes_destroy(AES aes)
{
  if (aes != NULL)
  {
    free(aes);
  }
}


AES_STATUS aes_generateKey(AES aes, unsigned char pKey[])
{
  unsigned long dwTabKey[AES_N_MAX_NB * (AES_N_MAX_ROUND + 1)];

  if (aes == NULL)
  {
    return AES_FAILED;
  }

  //Calcul de l'expansion de la clef
  if (aes->Nk <= 6)
  {
    aes_calculExpansionKeyInf6(pKey, dwTabKey, aes->Nk, aes->Nb, aes->Nr);
  }
  else
  {
    aes_calculExpansionKeySup6(pKey, dwTabKey, aes->Nk, aes->Nb, aes->Nr);
  }

  aes_formatteKey(dwTabKey, aes->byTabKey, aes->Nb, aes->Nr);

  aes->context = CIPHER_KEY_GENERATED;

  return AES_OK;
}



AES_STATUS aes_cipher(AES aes, unsigned char plaintext[], unsigned char ciphertext[])
{
  AES_STATUS status;
  status = AES_FAILED;

  if (aes != NULL)
  {
    if (aes->context == CIPHER_KEY_GENERATED)
    {
      //we can continue now...
      aes_doCiphering(aes, plaintext, ciphertext);
      status = AES_OK;
    }
    else
    {
      status = AES_FAILED;
    }
  }

  return status;
}

static void aes_doCiphering(AES aes, unsigned char plaintext[], unsigned char ciphertext[])
{
  unsigned char byTabBlock[4][AES_N_MAX_NB];
  int nCurrentRound = 0;

  assert(aes != NULL);

  aes_formatteBlock(plaintext, byTabBlock, aes->Nb);

  //nCurrentRound = 0;
  aes_addRoundKey(byTabBlock, aes->Nb, aes->byTabKey, nCurrentRound);

  for (nCurrentRound = 1; nCurrentRound < aes->Nr; nCurrentRound++)
  {
    aes_byteSub(byTabBlock, aes->Nb);
    aes_shiftRow(byTabBlock, aes->Nb);
    aes_mixColumn(byTabBlock, aes->Nb);
    aes_addRoundKey(byTabBlock, aes->Nb, aes->byTabKey, nCurrentRound);
  }

  aes_byteSub(byTabBlock, aes->Nb);
  aes_shiftRow(byTabBlock, aes->Nb);
  aes_addRoundKey(byTabBlock, aes->Nb, aes->byTabKey, nCurrentRound);


  //Reconstitution du tableau final
  int i;
  int j;

  for (i = 0; i < aes->Nb; i++)
  {
    for (j = 0; j < 4; j++)
    {
      ciphertext[4 * i + j ] = byTabBlock[j][i];
    }
  }
}

AES_STATUS aes_uncipher(AES aes, unsigned char ciphertext[], unsigned char plaintext[])
{
  AES_STATUS status;
  status = AES_FAILED;

  if (aes != NULL)
  {
    if (aes->context == CIPHER_KEY_GENERATED)
    {
      //we can continue now...
      aes_doUnCiphering(aes, ciphertext, plaintext);
      status = AES_OK;
    }
    else
    {
      status = AES_FAILED;
    }
  }

  return status;
}

static void aes_doUnCiphering(AES aes, unsigned char ciphertext[], unsigned char plaintext[])
{
  assert(aes != NULL);
  unsigned char byTabBlock[4][AES_N_MAX_NB];
  int nCurrentRound = 0;

  aes_formatteBlock(ciphertext, byTabBlock, aes->Nb);

  nCurrentRound = aes->Nr;
  aes_addRoundKey(byTabBlock, aes->Nb, aes->byTabKey, nCurrentRound);
  aes_invShiftRow(byTabBlock, aes->Nb);
  aes_invByteSub(byTabBlock, aes->Nb);


  for (nCurrentRound = aes->Nr - 1; nCurrentRound > 0; nCurrentRound--)
  {
    aes_addRoundKey(byTabBlock, aes->Nb, aes->byTabKey, nCurrentRound);
    aes_invMixColumn(byTabBlock, aes->Nb);
    aes_invShiftRow(byTabBlock, aes->Nb);
    aes_invByteSub(byTabBlock, aes->Nb);
  }

  aes_addRoundKey(byTabBlock, aes->Nb, aes->byTabKey, 0);

  //Reconstitution du tableau final
  int i;
  int j;

  for (i = 0; i < aes->Nb; i++)
  {
    for (j = 0; j < 4; j++)
    {
      plaintext[4 * i + j ] = byTabBlock[j][i];
    }
  }
}

static void aes_invShiftRow(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  if ((nNb == 4) || (nNb == 6))
  {
    aes_rotationLignesDroite(byArrayBlock, nNb, 1, 1);
    aes_rotationLignesDroite(byArrayBlock, nNb, 2, 2);
    aes_rotationLignesDroite(byArrayBlock, nNb, 3, 3);
  }
  else
  {
    aes_rotationLignesDroite(byArrayBlock, nNb, 1, 1);
    aes_rotationLignesDroite(byArrayBlock, nNb, 2, 3);
    aes_rotationLignesDroite(byArrayBlock, nNb, 3, 4);
  }
}

static void aes_rotationLignesDroite(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb, int nNoLigne, int NbRotation)
{
  int i;
  int j;
  unsigned char byTemp;

  for (j = 0; j < NbRotation; j++)
  {
    byTemp = byArrayBlock[nNoLigne][nNb - 1];

    for (i = (nNb - 1); i >= 1; i--)
    {
      byArrayBlock[nNoLigne][i] = byArrayBlock[nNoLigne][i - 1];
    }

    byArrayBlock[nNoLigne][0] = byTemp;
  }
}

static void aes_invMixColumn(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  unsigned char byTempArray[4][AES_N_MAX_NB];
  int i;
  int j;

  for (i = 0; i < nNb; i++)
  {
    byTempArray[0][i] = aes_multiplicationGF2Poly(0x0E, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x0B, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x0D, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x09, byArrayBlock[3][i]);

    byTempArray[1][i] = aes_multiplicationGF2Poly(0x09, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x0E, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x0B, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x0D, byArrayBlock[3][i]);

    byTempArray[2][i] = aes_multiplicationGF2Poly(0x0D, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x09, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x0E, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x0B, byArrayBlock[3][i]);

    byTempArray[3][i] = aes_multiplicationGF2Poly(0x0B, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x0D, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x09, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x0E, byArrayBlock[3][i]);
  }

  for (i = 0; i < nNb; i++)
  {
    for (j = 0; j < 4; j++)
    {
      byArrayBlock[j][i] = byTempArray[j][i];
    }
  }
}

static void aes_mixColumn(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  unsigned char byTempArray[4][AES_N_MAX_NB];
  int i;
  int j;

  for (i = 0; i < nNb; i++)
  {
    byTempArray[0][i] = aes_multiplicationGF2Poly(0x02, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x03, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x01, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x01, byArrayBlock[3][i]);

    byTempArray[1][i] = aes_multiplicationGF2Poly(0x01, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x02, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x03, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x01, byArrayBlock[3][i]);

    byTempArray[2][i] = aes_multiplicationGF2Poly(0x01, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x01, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x02, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x03, byArrayBlock[3][i]);

    byTempArray[3][i] = aes_multiplicationGF2Poly(0x03, byArrayBlock[0][i]) ^
                        aes_multiplicationGF2Poly(0x01, byArrayBlock[1][i]) ^
                        aes_multiplicationGF2Poly(0x01, byArrayBlock[2][i]) ^
                        aes_multiplicationGF2Poly(0x02, byArrayBlock[3][i]);
  }

  for (i = 0; i < nNb; i++)
  {
    for (j = 0; j < 4; j++)
    {
      byArrayBlock[j][i] = byTempArray[j][i];
    }
  }
}

unsigned char aes_multiplicationGF2Poly(unsigned char a, unsigned char b)
{
  if (a && b)
  {
    return aes_byAlogtable[(aes_byLogtable[a] + aes_byLogtable[b]) % 255];
  }
  else
  {
    return 0;
  }
}

static void aes_shiftRow(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  if ((nNb == 4) || (nNb == 6))
  {
    aes_rotationLignes(byArrayBlock, nNb, 1, 1);
    aes_rotationLignes(byArrayBlock, nNb, 2, 2);
    aes_rotationLignes(byArrayBlock, nNb, 3, 3);
  }
  else
  {
    aes_rotationLignes(byArrayBlock, nNb, 1, 1);
    aes_rotationLignes(byArrayBlock, nNb, 2, 3);
    aes_rotationLignes(byArrayBlock, nNb, 3, 4);
  }
}

static void aes_rotationLignes(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb, int nNoLigne, int NbRotation)
{
  int i;
  int j;
  unsigned char byTemp;

  for (j = 0; j < NbRotation; j++)
  {
    byTemp = byArrayBlock[nNoLigne][0];

    for (i = 0; i < (nNb - 1); i++)
    {
      byArrayBlock[nNoLigne][i] = byArrayBlock[nNoLigne][i + 1];
    }

    byArrayBlock[nNoLigne][nNb - 1] = byTemp;
  }
}

static void aes_invByteSub(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  int i;
  int j;

  for (i = 0; i < 4; i++)
  {
    for ( j = 0; j < nNb; j++)
    {
      byArrayBlock[i][j] = aes_byInvByteSubTransformation[byArrayBlock[i][j]];
    }
  }
}


static void aes_byteSub(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  int i;
  int j;

  for (i = 0; i < 4; i++)
  {
    for ( j = 0; j < nNb; j++)
    {
      byArrayBlock[i][j] = aes_byByteSubTransformation[byArrayBlock[i][j]];
    }
  }
}


static void aes_addRoundKey(unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb,
                            unsigned char byBlockKey[4][AES_N_MAX_NB][AES_N_MAX_ROUND + 1],
                            int nRound)
{
  int i;
  int j;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < nNb; j++)
    {
      byArrayBlock[i][j] = byArrayBlock[i][j] ^ byBlockKey[i][j][nRound];
    }
  }
}


static void aes_formatteBlock(unsigned char byBlock[], unsigned char byArrayBlock[4][AES_N_MAX_NB], int nNb)
{
  int j;

  for (j = 0; j < nNb; j++)
  {
    byArrayBlock[0][j] = byBlock[4 * j];
    byArrayBlock[1][j] = byBlock[4 * j + 1];
    byArrayBlock[2][j] = byBlock[4 * j + 2];
    byArrayBlock[3][j] = byBlock[4 * j + 3];
  }
}


static void aes_formatteKey(unsigned long dwTabKey[], unsigned char byTabKey[4][AES_N_MAX_NB][AES_N_MAX_ROUND + 1],
                            int nNb,
                            int nNr)
{
  int i;
  int j;

  for (i = 0; i < nNr + 1; i++)
  {
    for (j = 0; j < nNb; j++)
    {
      byTabKey[0][j][i] = (unsigned char) (dwTabKey[i + j] >> 24);
      byTabKey[1][j][i] = (unsigned char) (dwTabKey[i + j] >> 16);
      byTabKey[2][j][i] = (unsigned char) (dwTabKey[i + j] >> 8);
      byTabKey[3][j][i] = (unsigned char) (dwTabKey[i + j]);
    }
  }

}

static void aes_calculExpansionKeyInf6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr)
{
  int i;
  unsigned long dwTemp;


  for (i = 0; i < nNk; i++)
  {
    dwTabKey[i] = ((unsigned long) pClef[4 * i]) << 24 |
                  ((unsigned long) pClef[(4 * i) + 1]) << 16 |
                  ((unsigned long) pClef[(4 * i) + 2]) << 8 | pClef[(4 * i) + 3];
  }

  for (i = nNk; i < (nNb * (nNr + 1)); i++)
  {
    dwTemp = dwTabKey[i - 1];
    if ((i % nNk) == 0)
    {
      dwTemp = aes_subByte(aes_rotByte(dwTemp)) ^ aes_dwRoundCnst[i / nNk];
    }

    dwTabKey[i] = dwTabKey[i - nNk] ^ dwTemp;
  }
}


/* Ici Nk = 8 */
static void aes_calculExpansionKeySup6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr)
{
  int i;
  unsigned long dwTemp;

  for (i = 0; i < nNk; i++)
  {
    dwTabKey[i] = ((unsigned long) pClef[4 * i]) << 24 |
                  ((unsigned long) pClef[(4 * i) + 1]) << 16 |
                  ((unsigned long) pClef[(4 * i) + 2]) << 8 | pClef[(4 * i) + 3];
  }


  for (i = nNk; i < (nNb * (nNr + 1)); i++)
  {
    dwTemp = dwTabKey[i - 1];
    if ((i % nNk) == 0)
    {
      dwTemp = aes_subByte(aes_rotByte(dwTemp)) ^ aes_dwRoundCnst[i / nNk];
    }
    else
    {
      if ((i % nNk) == 4)
      {
        dwTemp = aes_subByte(dwTemp);
      }
    }

    dwTabKey[i] = dwTabKey[i - nNk] ^ dwTemp;
  }

}

static unsigned long aes_rotByte(unsigned long dwValue)
{
  return ((dwValue << 8) | (unsigned char) (dwValue >> 24));
}

static unsigned long aes_subByte(unsigned long dwValue)
{
  unsigned char byTemp0;
  unsigned char byTemp1;
  unsigned char byTemp2;
  unsigned char byTemp3;

  byTemp0 = (unsigned char) (dwValue >> 24);
  byTemp1 = (unsigned char) (dwValue >> 16);
  byTemp2 = (unsigned char) (dwValue >> 8);
  byTemp3 = (unsigned char) (dwValue);

  byTemp0 = aes_byByteSubTransformation[byTemp0];
  byTemp1 = aes_byByteSubTransformation[byTemp1];
  byTemp2 = aes_byByteSubTransformation[byTemp2];
  byTemp3 = aes_byByteSubTransformation[byTemp3];

  return (((unsigned long) byTemp0) << 24 |
          ((unsigned long) byTemp1) << 16 |
          ((unsigned long) byTemp2) << 8 |
          byTemp3);
}

