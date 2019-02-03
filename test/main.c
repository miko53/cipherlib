
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "des.h"
#include "listeSimple.h"
#include "common.h"

const char o_VERSION_LOGICIEL = 1;
const char o_CHAR_COMMENT = ';';

const int o_NB_CHAMPS = 5;

const char o_CHAMPS_SCRIPT[][100] =
{
	"[CryptageType]",	/* Marqueur no 0 */
	"[Action]",			/* 1 */
	"[Key]",			/* 2 */
	"[InputFiles]",		/* 3 */
	"[OutputFiles]"		/* 4 */
};

const char o_VALEUR_CHAMPS[4][11] = 
{
	"DES3",
	"DES1",
	"Cryptage",
	"Decryptage",
};


const int o_TAILLE_MAX_LIGNE = 255;


void essai_liste (void);


typedef union
{
	unsigned long typeLong;
	unsigned char typeChar[sizeof(unsigned long)];
} longToChar;


typedef struct
{
	unsigned char typeCryptage;
	unsigned char typeAction;
	unsigned char* clefCryptage;
	listeSimple fichierEntres;
	listeSimple fichierSortie;
} stDecodageCommande;


int crypterFichier(char fichierSource[], char fichierDestination[], char* clefCryptage, unsigned char typeCryptage);
int decrypterFichier(char fichierSource[], char fichierDestination[], char* clefCryptage, unsigned char typeCryptage);



int main(int argc, char *argv[], char *envp[])
{
	register int i;
	FILE *pScriptFile;
	char pBuffer[o_TAILLE_MAX_LIGNE];// = {0};
	char* pFileName = NULL;
	BOOL presenceMarqueur = FALSE;
	BOOL champRemplie = FALSE;
	BOOL ligneOk;
	BOOL modificationMarqueur = FALSE;
	int champActuel = -1;
	stDecodageCommande commandeScript;

	/* ouverture du fichier script */
	if (argc != 2)
	{
		printf("You must specify a valid scrypt file\n -> Crypt scryptFile\n");
		return 0;
	}


	pScriptFile = fopen(argv[1], "r");
	if (pScriptFile == NULL)
	{
		printf("Unable to open %s file \n", argv[1]);
		return 0;
	}

	/* décodage script */
	listeSimple_CreerListe(&(commandeScript.fichierEntres));
	listeSimple_CreerListe(&(commandeScript.fichierSortie));
	commandeScript.clefCryptage = NULL;
	commandeScript.typeCryptage = (unsigned char) -1;
	commandeScript.typeAction = (unsigned char) -1;

	while(!feof(pScriptFile))
	{
		if (fgets(pBuffer, o_TAILLE_MAX_LIGNE, pScriptFile) == NULL)
			continue;

		pBuffer[strlen(pBuffer)-1] = '\0';

		if (pBuffer[0] == o_CHAR_COMMENT)
			continue;

		ligneOk = FALSE;

		for(i = 0; i< (signed int) strlen(pBuffer); i++)
		{
			if ((pBuffer[i] != (char)0x20) && (pBuffer[i] != (char)0x0D))
				ligneOk = TRUE;
		}

		if (ligneOk == FALSE)
			continue;

		if (presenceMarqueur == TRUE)
		{
			for(i=0;i<o_NB_CHAMPS;i++)
			{
				if (strstr(pBuffer, o_CHAMPS_SCRIPT[i]) != NULL)
				{
					if ((i == 3) || (i == 4))
					{
						champActuel = i;
						modificationMarqueur = TRUE;
						break;
					}
					else
					{
						printf(" Script file error mark %s has no parameters !\n", o_CHAMPS_SCRIPT[champActuel]);
						if (commandeScript.clefCryptage != NULL)
							free(commandeScript.clefCryptage);
						listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
						listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
						return 0;
					}
				}
			}


			if (modificationMarqueur == TRUE)
			{
				modificationMarqueur = FALSE;
				continue;
			}
		
			/* recherche valeur pour le champs trouve */
			switch (champActuel)
			{
			case 0:  /* [CryptageType] */
				if (strstr(pBuffer, o_VALEUR_CHAMPS[0]) != NULL)
				{
					if (champRemplie == TRUE)
					{
						printf(" Many parameters for mark %s \n", o_CHAMPS_SCRIPT[champActuel]);
						if (commandeScript.clefCryptage != NULL)
							free(commandeScript.clefCryptage);
						listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
						listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
						return 0;
					}
					else
					{
						champRemplie = TRUE;
						presenceMarqueur = FALSE;
						commandeScript.typeCryptage = 0;
					}
				}

				if (strstr(pBuffer, o_VALEUR_CHAMPS[1]) != NULL)
				{
					if (champRemplie == TRUE)
					{
						printf(" Many parameters for mark %s \n", o_CHAMPS_SCRIPT[champActuel]);
						if (commandeScript.clefCryptage != NULL)
							free(commandeScript.clefCryptage);
						listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
						listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
						return 0;
					}
					else
					{
						champRemplie = TRUE;
						presenceMarqueur = FALSE;
						commandeScript.typeCryptage = 1;
					}
				}
				break;

			case 1:  /* [Action] */
				if (strstr(pBuffer, o_VALEUR_CHAMPS[2]) != NULL)
				{
					if (champRemplie == TRUE)
					{
						printf(" Many parameters for mark %s \n", o_CHAMPS_SCRIPT[champActuel]);
						if (commandeScript.clefCryptage != NULL)
							free(commandeScript.clefCryptage);
						listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
						listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
						return 0;
					}
					else
					{
						champRemplie = TRUE;
						presenceMarqueur = FALSE;
						commandeScript.typeAction = 0;
					}
				}

				if (strstr(pBuffer, o_VALEUR_CHAMPS[3]) != NULL)
				{
					if (champRemplie == TRUE)
					{
						printf(" Many parameters for mark %s \n", o_CHAMPS_SCRIPT[champActuel]);
						if (commandeScript.clefCryptage != NULL)
							free(commandeScript.clefCryptage);
						listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
						listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
						return 0;
					}
					else
					{
						champRemplie = TRUE;
						presenceMarqueur = FALSE;
						commandeScript.typeAction = 1;
					}
				}
				break;

			case 2:  /* [Key] */
				if ((pBuffer[0] == '-') && (pBuffer[1] == '>'))
				{
					/* le champs est valide */
					if (champRemplie == TRUE)
					{
						printf(" Many parameters for mark %s \n", o_CHAMPS_SCRIPT[champActuel]);
						if (commandeScript.clefCryptage != NULL)
							free(commandeScript.clefCryptage);
						listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
						listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
						return 0;
					}
					else
					{
						champRemplie = TRUE;
						presenceMarqueur = FALSE;
						commandeScript.clefCryptage = (unsigned char*) malloc (strlen(pBuffer) - 1);
						if (commandeScript.clefCryptage == NULL)
						{
							printf(" enough memory (02)! \n");
							if (commandeScript.clefCryptage != NULL)
								free(commandeScript.clefCryptage);
							listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
							listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
							return 1;
						}
						strcpy((char*)commandeScript.clefCryptage, &(pBuffer[2]));
					}
				}
				break;

			case 3:  /* [InputFiles] */
				pFileName = (char*) malloc(strlen(pBuffer) + 1);
				if (pFileName == NULL)
				{
					printf(" enough memory (03)! \n");
					if (commandeScript.clefCryptage != NULL)
						free(commandeScript.clefCryptage);
					listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
					listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
					return 1;
				}
				else
				{
					strcpy(pFileName, pBuffer);
					listeSimple_AjouterEnQueue(&(commandeScript.fichierEntres), (void*) pFileName);
					pFileName = NULL;
				}
				break;

			case 4:  /* [OutputFiles] */
				pFileName = (char*) malloc(strlen(pBuffer) + 1);
				if (pFileName == NULL)
				{
					printf(" enough memory (04)! \n");
					if (commandeScript.clefCryptage != NULL)
						free(commandeScript.clefCryptage);
					listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
					listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
					return 1;
				}
				else
				{
					strcpy(pFileName, pBuffer);
					listeSimple_AjouterEnQueue(&(commandeScript.fichierSortie), (void*) pFileName);
					pFileName = NULL;
				}
				break;

			default:
				printf(" Internal error ! (01), modify your script file or contact the author \n");
				/* effacer les listes  et la key */
				if (commandeScript.clefCryptage != NULL)
					free(commandeScript.clefCryptage);
				listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
				listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
				exit(1);
				break;
			}
		}
		else
		{
			/* lecture des champs */
			for(i=0;i<o_NB_CHAMPS;i++)
			{
				if (strstr(pBuffer, o_CHAMPS_SCRIPT[i]) != NULL)
				{
					presenceMarqueur = TRUE;
					champRemplie = FALSE;
					champActuel = i;
					break;
				}
			}
		}
	}



	if (commandeScript.typeCryptage == (unsigned char) -1)
	{
		printf(" No cryptage type is specified in script file \n");
		if (commandeScript.clefCryptage != NULL)
			free(commandeScript.clefCryptage);
		listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
		listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
		return 0;
	}


	if (commandeScript.typeAction == (unsigned char) -1)
	{
		printf(" No action is specified in script file \n");
		if (commandeScript.clefCryptage != NULL)
			free(commandeScript.clefCryptage);
		listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
		listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
		return 0;
	}

	if (commandeScript.clefCryptage == NULL)
	{
		printf("Error key has no value or key has wrong format (-> forgotten? ) \n");
		listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
		listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
		return 0;
	}



	if (listeSimple_EstVide(&(commandeScript.fichierEntres)) == TRUE)
	{
		printf("Error script file do not specify input files\n");
		if (commandeScript.clefCryptage != NULL)
			free(commandeScript.clefCryptage);
		listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
		return 0;
	}



	if (listeSimple_EstVide(&(commandeScript.fichierSortie)) == TRUE)
	{
		printf("Error script file do not specify output files\n");
		if (commandeScript.clefCryptage != NULL)
			free(commandeScript.clefCryptage);
		listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
		return 0;
	}


	i = strlen((char*)commandeScript.clefCryptage);

	if (((commandeScript.typeCryptage == 0) && (i != 24)) || ((commandeScript.typeCryptage == 1) && (i != 8)))
	{
		printf("key has not a correct size\n");
		if (commandeScript.clefCryptage != NULL)
			free(commandeScript.clefCryptage);
		listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
		listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
		return 0;
	}


	if (listeSimple_NombreElement(&(commandeScript.fichierSortie)) != listeSimple_NombreElement(&(commandeScript.fichierEntres)))
	{
		printf("There are no the same number of input and output file\n");
		if (commandeScript.clefCryptage != NULL)
			free(commandeScript.clefCryptage);
		listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
		listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
		return 0;
	}

	



	for(i = 0; i< listeSimple_NombreElement(&(commandeScript.fichierSortie)); i++)
	{
		int result;
		char *sourceFile = (char*) listeSimple_IemeElement(&(commandeScript.fichierEntres), (i+1));
		char *destinationFile = (char*) listeSimple_IemeElement(&(commandeScript.fichierSortie), (i+1));

		printf(" file : %s \n", sourceFile);

		if (commandeScript.typeAction == 0)
		{
			result = crypterFichier(sourceFile,
									destinationFile,
									(char*) commandeScript.clefCryptage,
									commandeScript.typeCryptage);
			if (result == -1)
			{
				if (commandeScript.clefCryptage != NULL)
					free(commandeScript.clefCryptage);
				listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
				listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
				return 0;
			}

			printf("\n crypt to file : %s \n", destinationFile);
		}
		else
		{
			result = decrypterFichier(	sourceFile,
										destinationFile,
										(char*) commandeScript.clefCryptage,
										commandeScript.typeCryptage);
			if (result == -1)
			{
				if (commandeScript.clefCryptage != NULL)
					free(commandeScript.clefCryptage);
				listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
				listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));
				return 0;
			}

			printf("\n decrypt to file : %s \n", destinationFile);
		}
	}



	if (commandeScript.clefCryptage != NULL)
		free(commandeScript.clefCryptage);
	listeSimple_SupprimerTousElements(&(commandeScript.fichierSortie));
	listeSimple_SupprimerTousElements(&(commandeScript.fichierEntres));

	return 0;
}


int decrypterFichier(char fichierSource[], char fichierDestination[], char* clefCryptage, unsigned char typeCryptage)
{
	register int i;

	FILE *pSource = NULL;
	FILE *pDestination = NULL;

	longToChar fileSize;
	unsigned long fileSizeDecrypter;
	int resteFileSize;

	unsigned char aCrypter[8];
	unsigned char finCryptage[8] = {0};

	pSource = fopen(fichierSource, "rb");
	if (pSource == NULL)
	{
		printf(" unable to open source file %s \n", fichierSource);
		return -1;
	}

	pDestination = fopen(fichierDestination, "wb");
	if (pDestination == NULL)
	{
		printf(" unable to open destination file %s \n", fichierDestination);
		fclose(pSource);
		return -1;
	}

    /* lecture de la taille du fichier final */
	for(i=0;i<sizeof(unsigned long);i++)
	{
		fileSize.typeChar[i] = fgetc(pSource);
	}

	/* lecture version */
	if (fgetc(pSource) != o_VERSION_LOGICIEL)
	{
		printf("Sorry, this software do not support this crypt file %s \n", fichierSource);
		fclose(pSource);
		fclose(pDestination);
		return -1;
	}

	fileSizeDecrypter = 0;

	while (1)
	{
		printf("\t Conversion on doing : %3.2d %% \r", (fileSizeDecrypter * 100)/fileSize.typeLong);
		if ((signed long)(fileSize.typeLong - fileSizeDecrypter) > 8)
		{
			/* decrypter 8  et mettre dans destination */
			for(i=0;i<8; i++)
				aCrypter[i] = fgetc(pSource);
			
			switch(typeCryptage)
			{
			case 0:
				cryptageTripleDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_DECRYPTAGE);
				break;
			case 1:
				cryptageDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_DECRYPTAGE);
				break;
			default:
				printf("Internal Error (02) \n");
				return -1;
				break;
			}

			for(i=0;i<8;i++)
				fputc(finCryptage[i], pDestination);

			fileSizeDecrypter = fileSizeDecrypter + 8;
		}
		else
		{
			/* le dernier */
			resteFileSize = fileSize.typeLong - fileSizeDecrypter;
			for(i=0;i<8; i++)
				aCrypter[i] = fgetc(pSource);
			
			switch(typeCryptage)
			{
			case 0:
				cryptageTripleDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_DECRYPTAGE);
				break;
			case 1:
				cryptageDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_DECRYPTAGE);
				break;
			default:
				printf("Internal Error (03) \n");
				return -1;
				break;
			}

			for(i=0;i<resteFileSize;i++)
				fputc(finCryptage[i], pDestination);

			break;
		}
	}

	fclose(pSource);
	fclose(pDestination);

	return 0;
}


int crypterFichier(char fichierSource[], char fichierDestination[], char* clefCryptage, unsigned char typeCryptage)
{
	/* essai cryptage d'un fichier */
	register int i;
	longToChar fileSize;
	long fileSizeCrypter;

	FILE *pSource = NULL;
	FILE *pDestination = NULL;

	unsigned char finCryptage[8] = {0};
	unsigned char aCrypter[8];
	int resteFileSize;


	/* Ouverture du fichier source */

	pSource = fopen(fichierSource, "rb");
	if (pSource == NULL)
	{
		printf(" unable to open source file %s \n", fichierSource);
		return -1;
	}

    pDestination = fopen(fichierDestination, "wb");
	if (pDestination == NULL)
	{
		printf(" unable to open destination file %s \n", fichierDestination);
		fclose(pSource);
		return -1;
	}

	
	/* action de cryptage */
	fileSize.typeLong = -1;
	while (!feof(pSource))
	{
		aCrypter[0] = fgetc(pSource);
		fileSize.typeLong = fileSize.typeLong + 1;
	}

	/* inscription dans le fichier resultat */
	for(i=0; i<sizeof(unsigned long); i++)
	{
		fputc(fileSize.typeChar[i], pDestination);
	}

	fputc(o_VERSION_LOGICIEL, pDestination);


	/* operation  de cryptage */
	fclose(pSource);
	pSource = fopen(fichierSource, "rb");
	if (pSource == NULL)
	{
		printf(" unable to open source file %s\n", fichierSource);
		return -1;
	}


	fileSizeCrypter = 0;
	while(1)
	{
		printf("\t conversion on doing %3.2d %% \r", (fileSizeCrypter*100) / fileSize.typeLong);

		if ((signed long) (fileSize.typeLong - fileSizeCrypter) >= 8)
		{
			for(i=0;i<8; i++)
				aCrypter[i] = fgetc(pSource);
			
			switch (typeCryptage)
			{
			case 0:
				cryptageTripleDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_CRYPTAGE);
				break;

			case 1:
				cryptageDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_CRYPTAGE);
				break;

			default:
				printf("Internal error (04) \n");
				return -1;
				break;
			}

			for(i=0;i<8;i++)
				fputc(finCryptage[i], pDestination);

			fileSizeCrypter = fileSizeCrypter + 8;
		}
		else
		{
			/* phase finale */
			resteFileSize = fileSize.typeLong - fileSizeCrypter;
			srand((unsigned)time(NULL));

			for(i = 0;i < 8; i++)
				aCrypter[i] = (unsigned char) rand();

			for(i = 0; i< resteFileSize;i++)
				aCrypter[i] = fgetc(pSource);

			switch (typeCryptage)
			{
			case 0:
				cryptageTripleDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_CRYPTAGE);
				break;

			case 1:
				cryptageDES(aCrypter, finCryptage, (unsigned char*)clefCryptage, o_DES_CRYPTAGE);
				break;

			default:
				printf("Internal error (05)!\n");
				return -1;
				break;
			}

			for(i=0;i<8;i++)
				fputc(finCryptage[i], pDestination);
			
			break;
		}
	}

	fclose(pSource);
	fclose(pDestination);

	return 0;
}

/*
int main01(int argc, char *argv[], char *envp[])
{
	register int i;

//	unsigned char aCrypter[] = { 0x88, 0xD7, 0xCC, 0x77, 0x1F, 0xB5, 0xF6, 0x50 };
//	unsigned char aCrypter[] = { 0x48, 0xD3, 0x11, 0x7E, 0x6D, 0xB0, 0x4E, 0x5F }; 

 	unsigned char aCrypter[] = "Caligula";
//	unsigned char clefCryptage[] = "Claudius";
	unsigned char clefCryptage[3][9] = { "Claudius", "dFç#fVQ-", "abcdefgh"};

	unsigned char finCryptage[8];

	printf("avant action : \n");
	printf("\t\t %s \n", aCrypter);

    for(i=0; i<8; i++)
		printf("%.2x -\n", aCrypter[i]);


//	cryptageDES(aCrypter, finCryptage, clefCryptage, o_DES_CRYPTAGE);
//	cryptageTripleDES(aCrypter, finCryptage, clefCryptage, o_DES_CRYPTAGE);


	printf("apres action : \n");
	printf("\t\t %s \n", finCryptage);

	for(i=0; i<8; i++)
		printf("%.2x -\n", finCryptage[i]);

	return 0;
}
*/

/*
void essai_liste (void)
{
	char* pValeur; 
	char Tempo[10] = {0};
	listeSimple liste;
	int i;

	printf(" liste 1 --%x\n", liste);
	listeSimple_CreerListe(&liste);
	printf(" liste 2 -- %x\n", liste);

	printf(" est vide - %x\n", listeSimple_EstVide(&liste));

	for(i=0;i<5;i++)
	{
		pValeur = (char*) malloc(15);
		strcpy(pValeur, "Valeur n°");
		strcat(pValeur, itoa(i, Tempo, 10));
		listeSimple_AjouterEnQueue(&liste, (void*) pValeur);
	}


	for(i = 0; i< 7; i++)
	{
		printf(" %i ieme element %s\n", i, listeSimple_IemeElement(&liste, i));
	}

	for(i=0; i<5; i++)
	{
		printf(" Element en tete %s\n", (char*) listeSimple_ElementEnQueue(&liste));
		printf(" Nombre d'element %i\n", listeSimple_NombreElement(&liste));
		printf(" status suprr %x\n", listeSimple_SupprimerElementEnQueue(&liste, EFFACEMENT_COMPLET));
	}

	printf(" liste 2 -- %x\n", liste);

	printf(" status suprr %x\n", listeSimple_SupprimerElementEnQueue(&liste, EFFACEMENT_COMPLET))
}*/
