

#include <stdio.h>
#include <string.h>
#include "common.h"

int AnalyseFrequence(FILE* pFile, unsigned int* iTabOccurence);


/*
int main(int argc, char *argv[], char *envp[])
{
   FILE* pFile;
  unsigned int iTabFrequence[256] = {0};
  unsigned int iIndex[256] = {0};

  if (argc != 2)
  {
    printf("Nb d'argument incorrecte \n");
    return 0;
  }


  pFile = fopen(argv[1],"r");
  if (pFile == NULL)
  {
    printf("Fichier impossible à ouvrir");
    return 0;
  }

  AnalyseFrequence(pFile, iTabFrequence);


  int i;
  int j;

  printf("\n--Analyse de fréquence--\n");

  for(i = 0 ;i<256;i++)
    iIndex[i] = i;

  // afficher dans l'ordre, ranger
  for(i = 0;i<256;i++)
  {
    for(j = i+1;j<256;j++)
    {
      if (iTabFrequence[j] > iTabFrequence[i])
      {
        //swap
        unsigned int tempo;
        tempo = iTabFrequence[j];
        iTabFrequence[j] = iTabFrequence[i];
        iTabFrequence[i] = tempo;

        tempo = iIndex[j];
        iIndex[j] = iIndex[i];
        iIndex[i] = tempo;
      }
    }
  }

  for(i = 0;i<256;i++)
  {
    if ((iIndex[i] >= 32) && (iIndex[i] <= 127))
     printf(" caractere :%c, nb occurence :%i\n", iIndex[i], iTabFrequence[i]);
  }



  return 0;
}
*/


int AnalyseFrequence(FILE* pFile, unsigned int* iTabOccurence)
{
  unsigned int nValeurCourante;
  unsigned char cCharCourante;
  unsigned long toto = 0;

  while (!feof(pFile))
  {
    nValeurCourante = fgetc(pFile);
    if (nValeurCourante == EOF)
    {
      break;
    }

    cCharCourante = (unsigned char) nValeurCourante;

    iTabOccurence[cCharCourante] = iTabOccurence[cCharCourante] + 1;
    toto++;
  }

  printf("toto %i", toto);
  return 0;
}

char ppszTableauCesar[26][27] =
{
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "BCDEFGHIJKLMNOPQRSTUVWXYZA",
  "CDEFGHIJKLMNOPQRSTUVWXYZAB",
  "DEFGHIJKLMNOPQRSTUVWXYZABC",
  "EFGHIJKLMNOPQRSTUVWXYZABCD",
  "FGHIJKLMNOPQRSTUVWXYZABCDE",
  "GHIJKLMNOPQRSTUVWXYZABCDEF",
  "HIJKLMNOPQRSTUVWXYZABCDEFG",
  "IJKLMNOPQRSTUVWXYZABCDEFGH",
  "JKLMNOPQRSTUVWXYZABCDEFGHI",
  "KLMNOPQRSTUVWXYZABCDEFGHIJ",
  "LMNOPQRSTUVWXYZABCDEFGHIJK",
  "MNOPQRSTUVWXYZABCDEFGHIJKL",
  "NOPQRSTUVWXYZABCDEFGHIJKLM",
  "OPQRSTUVWXYZABCDEFGHIJKLMN",
  "PQRSTUVWXYZABCDEFGHIJKLMNO",
  "QRSTUVWXYZABCDEFGHIJKLMNOP",
  "RSTUVWXYZABCDEFGHIJKLMNOPQ",
  "STUVWXYZABCDEFGHIJKLMNOPQR",
  "TUVWXYZABCDEFGHIJKLMNOPQRS",
  "UVWXYZABCDEFGHIJKLMNOPQRST",
  "VWXYZABCDEFGHIJKLMNOPQRSTU",
  "WXYZABCDEFGHIJKLMNOPQRSTUV",
  "XYZABCDEFGHIJKLMNOPQRSTUVW",
  "YZABCDEFGHIJKLMNOPQRSTUVWX",
  "ZABCDEFGHIJKLMNOPQRSTUVWXY",
};

char szTextCrypte[] =
  "MHILY LZA ZBHL XBPZXBL MVYABUHL HWWPBZ JSHBKPBZ JHLJBZ KPJABT HYJHUBT LZA ULBAYVU";


int main(int argc, char* argv[], char* envp[])
{
  // Decodage chiffre de cesar
  for (int i = 0; i < 26; i++)
  {
    int j;
    char cCourant;
    BOOL bTrouve;
    for (j = 0; j < (int)strlen(szTextCrypte); j++)
    {
      cCourant = szTextCrypte[j];
      bTrouve = FALSE;
      for (int k = 0; k < 26; k++)
      {
        if (cCourant == ppszTableauCesar[0][k])
        {
          printf("%c", ppszTableauCesar[i][k]);
          bTrouve = TRUE;
          break;
        }
      }

      if (bTrouve == FALSE)
      {
        printf("%c", cCourant);
      }

    }
    printf("\n");
  }

  return 0;
}

/*
int main(int argc, char *argv[], char *envp[])
{
  char c, d;

  c = 'A';

//  while (c<='Z')
//  {
    d = 'A';
    while (d<='Z')
    {
      printf("%cET\n", d);
      d++;
    }
//    c++;
//  }


  return 0;
}
*/
