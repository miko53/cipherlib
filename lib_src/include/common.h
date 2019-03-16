
#ifndef COMMON_H
#define COMMON_H

typedef enum { FALSE, TRUE} BOOL;

/*
typedef enum
{
  CIPHER_MODE_ECB,
  CIPHER_MODE_CBC
} cipher_mode;
*/

typedef enum
{
  CIPHER_INITIALIZED,
  CIPHER_KEY_GENERATED
} cipher_context;

#endif /* COMMON_H */
