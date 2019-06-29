#include <gcrypt.h>
#ifndef DEBUGTOOLS_H
#define DEBUGTOOLS_H

void sprintSEXP_Ed25519(gcry_sexp_t in, char *rt, size_t strSize);
void addCToStr(char c, char *in, size_t maxStrLn);

#endif
