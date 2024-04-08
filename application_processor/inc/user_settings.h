#ifdef WOLFSSL_USER_SETTINGS
#include <stdint.h>
// This initializes wolfssl's random generator to allow us to generate secure randomness
// wolfssl.com/forums/topic879-solved-using-rsa-undefined-reference-to-wcgenerateseed-error.html
int rand_gen_seed(uint8_t* output, int sz);
#define CUSTOM_RAND_GENERATE_SEED rand_gen_seed
#endif
