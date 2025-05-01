#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h"
#include <tx_api.h>

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    for (word32 i = 0; i < sz; i++) {
        output[i] = (byte)(tx_time_get() >> (i & 3));
    }
    return 0;
}
