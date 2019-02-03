

#include "aes.h"

#include <stdio.h>

const int nMaxRound = 14;
const int nMaxNb = 8;

const unsigned char byByteSubTransformation[256] = 
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

const unsigned char byInvByteSubTransformation[256] =
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


const unsigned char byLogtable[256] = 
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


const unsigned char byAlogtable[256] = 
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


const unsigned long dwRoundCnst[30] =
{ 
  0x01,0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};


void MixColumn(unsigned char byArrayBlock[4][nMaxNb], int nNb);
void InvMixColumn(unsigned char byArrayBlock[4][nMaxNb], int nNb);

unsigned char MultiplicationGF2Poly(unsigned char a, unsigned char b);
void ShiftRow(unsigned char byArrayBlock[4][nMaxNb], int nNb);
void InvShiftRow(unsigned char byArrayBlock[4][nMaxNb], int nNb);

void RotationLignes(unsigned char byArrayBlock[4][nMaxNb], int nNb, int nNoLigne, int NbRotation);
void RotationLignesDroite(unsigned char byArrayBlock[4][nMaxNb], int nNb, int nNoLigne, int NbRotation);

void InvByteSub(unsigned char byArrayBlock[4][nMaxNb], int nNb);
void ByteSub(unsigned char byArrayBlock[4][nMaxNb], int nNb);

void FormatteBlock(unsigned char byBlock[], unsigned char byArrayBlock[4][nMaxNb], int nNb);
void FormatteKey(unsigned long dwTabKey[], unsigned char byTabKey[4][nMaxNb][nMaxRound+1], int nNb, int nNr);

void AddRoundKey(unsigned char byArrayBlock[4][nMaxNb], int nNb, unsigned char byBlockKey[4][nMaxNb][nMaxRound+1], int nRound);

void CalculExpansionKeyInf6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr);
void CalculExpansionKeySup6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr);

unsigned long RotByte(unsigned long dwValue);
unsigned long SubByte(unsigned long dwValue);

int main(int argc, char *argv[], char *envp[]);
int AEScryptage(unsigned char pTexteACrypter[], unsigned char pTexteCrypter[], unsigned char pClef[], int nLongueurBlock, int nLongueurClef);
int AESDecryptage(unsigned char pTexteCrypter[], unsigned char pTexteDeCrypter[], unsigned char pClef[], int nLongueurBlock, int nLongueurClef);



int main(int argc, char *argv[], char *envp[])
{

  unsigned char sTextACrypter[] = "Mickael Sergent ";
  unsigned char sClef[]         = "1234567890987654";
  unsigned char sTextCrypter[17] = {0};
  unsigned char sResultatApresDecryptage[17] = {0};
  int i;

  AEScryptage(sTextACrypter, sTextCrypter, sClef, 128, 128);

  printf("%s\n", sTextACrypter);

  for(i = 0; i< 17; i++)
    printf(" %i --> %.2x\n", i, sTextCrypter[i]);


  AESDecryptage(sTextCrypter, sResultatApresDecryptage, sClef, 128, 128);

  for(i = 0; i< 17; i++)
    printf(" %i --> %.2x\n", i, sResultatApresDecryptage[i]);
 
  printf("%s\n", sResultatApresDecryptage);

  return 0;
}



int AEScryptage(unsigned char pTexteACrypter[], unsigned char pTexteCrypter[], unsigned char pClef[], int nLongueurBlock, int nLongueurClef)
{
  int Nb;
  int Nk;
  int Nr;
  int nCurrentRound = 0; 
  unsigned long dwTabKey[nMaxNb * (nMaxRound+1)] = {0};
  unsigned char byTabKey[4][nMaxNb][nMaxRound+1] = {0};
  unsigned char byTabBlock[4][nMaxNb] = {0};

  // Verification Longueur de block et longueur de la clef
  if ((nLongueurBlock == 128) || (nLongueurBlock == 192) || (nLongueurBlock == 256))
  {
    Nb = nLongueurBlock / 32;
  }
  else
    return (-1);


  if ((nLongueurClef == 128) || (nLongueurClef == 192) || (nLongueurClef == 256))
  {
    Nk = nLongueurClef / 32;
  }
  else
    return (-1);

  //Calcul du nombre de rounds necc. pour les longeurs données
  if (Nk > Nb)
    Nr = Nk;
  else
    Nr = Nb;

  switch (Nr)
  {
  case 4:
    Nr = 10;
    break;

  case 6:
    Nr = 12;
    break;

  case 8:
    Nr = 14;
    break;

  default:
    return (-1);
  }

  //Calcul de l'expansion de la clef
  if (Nk <= 6)
    CalculExpansionKeyInf6(pClef, dwTabKey, Nk, Nb, Nr);
  else
    CalculExpansionKeySup6(pClef, dwTabKey, Nk, Nb, Nr);

  FormatteKey(dwTabKey, byTabKey, Nb, Nr);
  FormatteBlock(pTexteACrypter, byTabBlock, Nb);

  //nCurrentRound = 0;
  AddRoundKey(byTabBlock, Nb, byTabKey, nCurrentRound);

  for(nCurrentRound = 1; nCurrentRound < Nr; nCurrentRound++)
  {
    ByteSub(byTabBlock, Nb);
    ShiftRow(byTabBlock, Nb);
    MixColumn(byTabBlock, Nb);
    AddRoundKey(byTabBlock, Nb, byTabKey, nCurrentRound);
  }

  ByteSub(byTabBlock, Nb);
  ShiftRow(byTabBlock, Nb);
  AddRoundKey(byTabBlock, Nb, byTabKey, nCurrentRound);


  //Reconstitution du tableau final
  int i;
  int j;

  for(i = 0; i<Nb; i++)
  {
    for(j = 0; j< 4; j++)
    {
      pTexteCrypter[4*i + j ] = byTabBlock[j][i];
    }
  }

  return 0;
}



int AESDecryptage(unsigned char pTexteCrypter[], unsigned char pTexteDeCrypter[], unsigned char pClef[], int nLongueurBlock, int nLongueurClef)
{
  int Nb;
  int Nk;
  int Nr;
  int nCurrentRound = 0; 
  unsigned long dwTabKey[nMaxNb * (nMaxRound+1)] = {0};
  unsigned char byTabKey[4][nMaxNb][nMaxRound+1];
  unsigned char byTabBlock[4][nMaxNb];

  // Verification Longueur de block et longueur de la clef
  if ((nLongueurBlock == 128) || (nLongueurBlock == 192) || (nLongueurBlock == 256))
  {
    Nb = nLongueurBlock / 32;
  }
  else
    return (-1);


  if ((nLongueurClef == 128) || (nLongueurClef == 192) || (nLongueurClef == 256))
  {
    Nk = nLongueurClef / 32;
  }
  else
    return (-1);

  //Calcul du nombre de rounds necc. pour les longeurs données
  if (Nk > Nb)
    Nr = Nk;
  else
    Nr = Nb;

  switch (Nr)
  {
  case 4:
    Nr = 10;
    break;

  case 6:
    Nr = 12;
    break;

  case 8:
    Nr = 14;
    break;

  default:
    return (-1);
  }

  //Calcul de l'expansion de la clef
  if (Nk <= 6)
    CalculExpansionKeyInf6(pClef, dwTabKey, Nk, Nb, Nr);
  else
    CalculExpansionKeySup6(pClef, dwTabKey, Nk, Nb, Nr);

  FormatteKey(dwTabKey, byTabKey, Nb, Nr);
  FormatteBlock(pTexteCrypter, byTabBlock, Nb);

  
  nCurrentRound = Nr;
  AddRoundKey(byTabBlock, Nb, byTabKey, nCurrentRound);
  InvShiftRow(byTabBlock, Nb);
  InvByteSub(byTabBlock, Nb);


  for(nCurrentRound = Nr-1; nCurrentRound > 0; nCurrentRound--)
  {
    AddRoundKey(byTabBlock, Nb, byTabKey, nCurrentRound);
    InvMixColumn(byTabBlock, Nb);
    InvShiftRow(byTabBlock, Nb);
    InvByteSub(byTabBlock, Nb);
  }

  AddRoundKey(byTabBlock, Nb, byTabKey, 0);

  //Reconstitution du tableau final
  int i;
  int j;

  for(i = 0; i<Nb; i++)
  {
    for(j = 0; j< 4; j++)
    {
      pTexteDeCrypter[4*i + j ] = byTabBlock[j][i];
    }
  }

  return 0;
}


void InvShiftRow(unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  if ((nNb == 4) || (nNb == 6))
  {
    RotationLignesDroite(byArrayBlock, nNb, 1, 1);
    RotationLignesDroite(byArrayBlock, nNb, 2, 2);
    RotationLignesDroite(byArrayBlock, nNb, 3, 3);
  }
  else
  {
    RotationLignesDroite(byArrayBlock, nNb, 1, 1);
    RotationLignesDroite(byArrayBlock, nNb, 2, 3);
    RotationLignesDroite(byArrayBlock, nNb, 3, 4);
  }
}


void RotationLignesDroite(unsigned char byArrayBlock[4][nMaxNb], int nNb, int nNoLigne, int NbRotation)
{
  int i;
  int j;
  unsigned char byTemp;

  for(j = 0; j < NbRotation; j++)
  {
    byTemp = byArrayBlock[nNoLigne][nNb-1];

    for(i = (nNb-1); i >= 1; i--)
    {
      byArrayBlock[nNoLigne][i] = byArrayBlock[nNoLigne][i-1];
    }

    byArrayBlock[nNoLigne][0] = byTemp;
  }
}


void InvMixColumn(unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  unsigned char byTempArray[4][nMaxNb];
  int i;
  int j;

  for(i = 0; i<nNb; i++)
  {
    byTempArray[0][i] = MultiplicationGF2Poly(0x0E, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x0B, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x0D, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x09, byArrayBlock[3][i]);

    byTempArray[1][i] = MultiplicationGF2Poly(0x09, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x0E, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x0B, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x0D, byArrayBlock[3][i]);

    byTempArray[2][i] = MultiplicationGF2Poly(0x0D, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x09, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x0E, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x0B, byArrayBlock[3][i]);

    byTempArray[3][i] = MultiplicationGF2Poly(0x0B, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x0D, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x09, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x0E, byArrayBlock[3][i]);
  }

  for(i = 0; i < nNb; i++)
  {
    for(j = 0; j < 4; j++)
    {
      byArrayBlock[j][i] = byTempArray[j][i];
    }
  }
}


void MixColumn(unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  unsigned char byTempArray[4][nMaxNb];
  int i;
  int j;

  for(i = 0; i<nNb; i++)
  {
    byTempArray[0][i] = MultiplicationGF2Poly(0x02, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x03, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x01, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x01, byArrayBlock[3][i]);

    byTempArray[1][i] = MultiplicationGF2Poly(0x01, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x02, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x03, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x01, byArrayBlock[3][i]);

    byTempArray[2][i] = MultiplicationGF2Poly(0x01, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x01, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x02, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x03, byArrayBlock[3][i]);

    byTempArray[3][i] = MultiplicationGF2Poly(0x03, byArrayBlock[0][i]) ^
                        MultiplicationGF2Poly(0x01, byArrayBlock[1][i]) ^
                        MultiplicationGF2Poly(0x01, byArrayBlock[2][i]) ^
                        MultiplicationGF2Poly(0x02, byArrayBlock[3][i]);
  }

  for(i = 0; i < nNb; i++)
  {
    for(j = 0; j < 4; j++)
    {
      byArrayBlock[j][i] = byTempArray[j][i];
    }
  }
}


unsigned char MultiplicationGF2Poly(unsigned char a, unsigned char b)
{
  if (a&&b)
    return byAlogtable[(byLogtable[a] + byLogtable[b])%255];
	else
    return 0;
}


void ShiftRow(unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  if ((nNb == 4) || (nNb == 6))
  {
    RotationLignes(byArrayBlock, nNb, 1, 1);
    RotationLignes(byArrayBlock, nNb, 2, 2);
    RotationLignes(byArrayBlock, nNb, 3, 3);
  }
  else
  {
    RotationLignes(byArrayBlock, nNb, 1, 1);
    RotationLignes(byArrayBlock, nNb, 2, 3);
    RotationLignes(byArrayBlock, nNb, 3, 4);
  }
}

void RotationLignes(unsigned char byArrayBlock[4][nMaxNb], int nNb, int nNoLigne, int NbRotation)
{
  int i;
  int j;
  unsigned char byTemp;

  for(j = 0; j < NbRotation; j++)
  {
    byTemp = byArrayBlock[nNoLigne][0];

    for(i = 0; i < (nNb-1); i++)
    {
      byArrayBlock[nNoLigne][i] = byArrayBlock[nNoLigne][i+1];
    }

    byArrayBlock[nNoLigne][nNb-1] = byTemp;
  }
}

void InvByteSub(unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  int i;
  int j;

  for(i = 0; i< 4; i++)
  {
    for( j =0; j<nNb; j++)
    {
      byArrayBlock[i][j] = byInvByteSubTransformation[byArrayBlock[i][j]];
    }
  }
}


void ByteSub(unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  int i;
  int j;

  for(i = 0; i< 4; i++)
  {
    for( j =0; j<nNb; j++)
    {
      byArrayBlock[i][j] = byByteSubTransformation[byArrayBlock[i][j]];
    }
  }
}


void AddRoundKey(unsigned char byArrayBlock[4][nMaxNb], int nNb, unsigned char byBlockKey[4][nMaxNb][nMaxRound+1], int nRound)
{
  int i;
  int j;

  for(i= 0; i<4; i++)
  {
    for(j = 0; j< nNb; j++)
    {
      byArrayBlock[i][j] = byArrayBlock[i][j] ^ byBlockKey[i][j][nRound];
    }
  }
}


void FormatteBlock(unsigned char byBlock[], unsigned char byArrayBlock[4][nMaxNb], int nNb)
{
  int j;

  for(j = 0; j < nNb; j++)
  {
    byArrayBlock[0][j] = byBlock[4*j];
    byArrayBlock[1][j] = byBlock[4*j+1];
    byArrayBlock[2][j] = byBlock[4*j+2];
    byArrayBlock[3][j] = byBlock[4*j+3];
  }
}


void FormatteKey(unsigned long dwTabKey[], unsigned char byTabKey[4][nMaxNb][nMaxRound+1], int nNb, int nNr)
{
  int i;
  int j;

  for(i = 0; i<nNr+1; i++)
  {
    for(j = 0; j<nNb; j++)
    {
      byTabKey[0][j][i] = (unsigned char) (dwTabKey[i + j] >> 24);
      byTabKey[1][j][i] = (unsigned char) (dwTabKey[i + j] >> 16);
      byTabKey[2][j][i] = (unsigned char) (dwTabKey[i + j] >> 8);
      byTabKey[3][j][i] = (unsigned char) (dwTabKey[i + j]);
    }
  }

}


void CalculExpansionKeyInf6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr)
{
  int i;
  unsigned long dwTemp;


  for(i = 0; i<nNk; i++)
  {
    dwTabKey[i] = ((unsigned long) pClef[4*i])<<24 |
                  ((unsigned long) pClef[(4*i)+1])<<16 |
                  ((unsigned long) pClef[(4*i)+2])<<8 | pClef[(4*i)+3];
  }

  for(i = nNk; i<(nNb * (nNr+1)); i++)
  {
    dwTemp = dwTabKey[i - 1];
    if ((i % nNk) == 0)
      dwTemp = SubByte(RotByte(dwTemp)) ^ dwRoundCnst[i/nNk];

    dwTabKey[i] = dwTabKey[i - nNk] ^ dwTemp;
  }
}


/* Ici Nk = 8 */
void CalculExpansionKeySup6(unsigned char pClef[], unsigned long dwTabKey[], int nNk, int nNb, int nNr)
{
  int i;
  unsigned long dwTemp;

  for(i = 0; i<nNk; i++)
  {
    dwTabKey[i] = ((unsigned long) pClef[4*i])<<24 | 
                  ((unsigned long) pClef[(4*i)+1])<<16 |
                  ((unsigned long) pClef[(4*i)+2])<<8 | pClef[(4*i)+3];
  }


  for(i = nNk; i<(nNb * (nNr+1)); i++)
  {
    dwTemp = dwTabKey[i - 1];
    if ((i % nNk) == 0)
      dwTemp = SubByte(RotByte(dwTemp)) ^ dwRoundCnst[i/nNk];
    else
    {
      if ((i % nNk) == 4)
        dwTemp = SubByte(dwTemp);
    }

    dwTabKey[i] = dwTabKey[i - nNk] ^ dwTemp;
  }

}


unsigned long RotByte(unsigned long dwValue)
{
  return ((dwValue << 8) | (unsigned char) (dwValue>>24));
}



unsigned long SubByte(unsigned long dwValue)
{
  unsigned char byTemp0;
  unsigned char byTemp1;
  unsigned char byTemp2;
  unsigned char byTemp3;

  byTemp0 = (unsigned char) (dwValue>>24);
  byTemp1 = (unsigned char) (dwValue>>16);
  byTemp2 = (unsigned char) (dwValue>>8);
  byTemp3 = (unsigned char) (dwValue);

  byTemp0 = byByteSubTransformation[byTemp0];
  byTemp1 = byByteSubTransformation[byTemp1];
  byTemp2 = byByteSubTransformation[byTemp2];
  byTemp3 = byByteSubTransformation[byTemp3];

  return (((unsigned long) byTemp0)<<24 | 
          ((unsigned long) byTemp1)<<16 |
          ((unsigned long) byTemp2)<<8 | 
          byTemp3);
}



