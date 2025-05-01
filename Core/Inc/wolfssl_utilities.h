#ifndef WOLFSSL_UTILITIES_H
#define WOLFSSL_UTILITIES_H

#include <wolfssl/ssl.h>

void print_cert_subject_from_pem(const char* pem, const char* label);
void print_ciphers(void);

#endif // WOLFSSL_UTILITIES_H
