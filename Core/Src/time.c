/*
 * time.c
 *
 *  Created on: Apr 14, 2025
 *      Author: Keyfactor
 */

#include "time.h"

// Stub the time function to allow OPENSSL_EXTRA functions
// You have to make sure there are safeguards in place like
// #define WOLFSSL_NO_ASN_TIME
time_t time(time_t *t) {
    if (t) *t = 0;
    return 0;
} /* time */
