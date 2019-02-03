

#ifndef __LISTE_SIMPLE_H
#define __LISTE_SIMPLE_H

//#include "stdio.h"
#include "stdlib.h"
#include "common.h"

#define         OK           (0)
#define         ERROR        (-1)


typedef unsigned int STATUS;


#define	EFFACEMENT_PARTIEL	   1
#define	EFFACEMENT_COMPLET     2


struct StMaillon
{
	void* pObjet;
	struct StMaillon *pSuivant;
};

typedef struct StMaillon stMaillon;

typedef stMaillon* listeSimple;



#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* Fonctions publique */
extern STATUS listeSimple_CreerListe(listeSimple* liste);

extern STATUS listeSimple_AjouterEnQueue(listeSimple* liste, void* pObjet);
extern STATUS listeSimple_AjouterEnTete(listeSimple* liste, void* pObjet);

extern STATUS listeSimple_SupprimerElementEnQueue(listeSimple* liste, unsigned int typeEffacement);
extern STATUS listeSimple_SupprimerElementEnTete(listeSimple* liste, unsigned int typeEffacement);

extern void* listeSimple_ElementEnTete(listeSimple* liste);
extern void* listeSimple_ElementEnQueue(listeSimple* liste);

extern BOOL listeSimple_EstVide(listeSimple* liste);
extern int listeSimple_NombreElement(listeSimple* liste);

extern void* listeSimple_IemeElement(listeSimple *liste, int ieme);

extern STATUS listeSimple_SupprimerTousElements(listeSimple *liste);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __LISTE_SIMPLE_H */



