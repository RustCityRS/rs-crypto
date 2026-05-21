#ifndef XTEA_H
#define XTEA_H

#include <stdint.h>

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);

#endif /* XTEA_H */
