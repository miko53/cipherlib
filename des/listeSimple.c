
/* listeSimple.c implementation file  */
/* M. Sergent 04-2001                 */

/* realisation d'une liste chainee simple */

//#include "stdio.h"
#include "listeSimple.h"



STATUS listeSimple_CreerListe(listeSimple* liste)
{
	/* Mise a Jour du pointeur */
	*liste = NULL;
	return OK;
}


STATUS listeSimple_AjouterEnQueue(listeSimple* liste, void* pObjet)
{
	listeSimple pListe = *liste;

	if (*liste == NULL)
		return (listeSimple_AjouterEnTete(liste, pObjet));
	else
	{
		/* rechercher le dernier element */
		while ((pListe)->pSuivant != NULL)
		{
			(pListe) = (pListe)->pSuivant;
		}

		/* ajouter l'element a la suite de pListe */
		(pListe)->pSuivant = (listeSimple) malloc(sizeof(stMaillon));
		if ((pListe)->pSuivant == NULL)
			return ERROR;
		else
		{
			pListe = (pListe)->pSuivant;
			(pListe)->pObjet = pObjet;
			(pListe)->pSuivant = NULL;
			return OK;
		}
	}
}


STATUS listeSimple_AjouterEnTete(listeSimple* liste, void* pObjet)
{
	listeSimple pListe;

	pListe = (listeSimple) malloc(sizeof(stMaillon));

	if (pListe == NULL)
		return ERROR;
	else
	{
		(pListe)->pObjet = pObjet;
		(pListe)->pSuivant = *liste;
		*liste = pListe;
		return OK;
	}
}


STATUS listeSimple_SupprimerElementEnQueue(listeSimple* liste, unsigned int typeEffacement)
{
	listeSimple pListe;
	listeSimple pListe2;

	if ((typeEffacement != EFFACEMENT_PARTIEL) && (typeEffacement != EFFACEMENT_COMPLET))
		return ERROR;

	if (*liste == NULL)
		return ERROR;
	else
	{
		pListe = (*liste)->pSuivant;
		pListe2 = *liste;

		if (pListe == NULL)
		{
			if (typeEffacement == EFFACEMENT_COMPLET)
				free(pListe2->pObjet);

			free(pListe2);
			*liste = NULL;
		}
		else
		{
			while (pListe->pSuivant != NULL)
			{
				pListe = pListe->pSuivant;
				pListe2 = pListe2->pSuivant;
			}

			if (typeEffacement == EFFACEMENT_COMPLET)
				free(pListe->pObjet);

			free(pListe);
			pListe2->pSuivant = NULL;
		}
		return OK;
	}
}


STATUS listeSimple_SupprimerElementEnTete(listeSimple* liste, unsigned int typeEffacement)
{
	listeSimple pListe;

	if ((typeEffacement != EFFACEMENT_PARTIEL) && (typeEffacement != EFFACEMENT_COMPLET))
		return ERROR;


	pListe = *liste;
	if (pListe == NULL)
		return ERROR;
	else
	{
		*liste = (*liste)->pSuivant;

		if (typeEffacement == EFFACEMENT_COMPLET)
			free(pListe->pObjet);

		free(pListe);
		return OK;
	}
}


void* listeSimple_ElementEnTete(listeSimple* liste)
{
	return ((*liste)->pObjet);
}


void* listeSimple_ElementEnQueue(listeSimple* liste)
{
	listeSimple pListe;

	pListe = *liste;

	if (*liste == NULL)
		return NULL;

	while (pListe->pSuivant != NULL)
	{
		pListe = pListe->pSuivant;
	}

	return pListe->pObjet;
}


BOOL listeSimple_EstVide(listeSimple* liste)
{
	if (*liste == NULL)
		return TRUE;
	else
		return FALSE;
}


int listeSimple_NombreElement(listeSimple* liste)
{
	listeSimple pListe = *liste;
	int nbElements = 0;

	if (*liste == NULL)
		return 0;
	else
	{
		while (pListe != NULL)
		{
			pListe = pListe->pSuivant;
			nbElements++;
		}
		return nbElements;
	}
}


void* listeSimple_IemeElement(listeSimple *liste, int ieme)
{
	int longueur;
	listeSimple pListe;

	pListe = *liste;

	longueur = listeSimple_NombreElement(liste);

	if ((ieme<1) || (ieme>longueur))
		return NULL;
	else
	{
		longueur = 1;
		while (longueur < ieme)
		{
			pListe = pListe->pSuivant;
			longueur++;
		}
		return (pListe->pObjet);
	}
}

STATUS listeSimple_SupprimerTousElements(listeSimple *liste)
{
	register int i, j;

	if (*liste == NULL)
		return OK;

	i = listeSimple_NombreElement(liste);

	for(j = 0; j < i; j++)
		listeSimple_SupprimerElementEnTete(liste, EFFACEMENT_COMPLET);

	return OK;
}



