#include "main.h"
#include <stdio.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include "wolfssl_utilities.h"

void print_cert_subject_from_pem(const char* pem, const char* label)
{
    if (pem == NULL) {
        printf("%s: PEM buffer is NULL\r\n", label);
        return;
    }

    WOLFSSL_X509* cert = wolfSSL_X509_load_certificate_buffer(
        (const unsigned char*)pem,
        strlen(pem),
        WOLFSSL_FILETYPE_PEM
    );

    if (cert != NULL) {
        WOLFSSL_X509_NAME* subject_name = wolfSSL_X509_get_subject_name(cert);
        char subject_str[256] = {0};

        if (wolfSSL_X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str)) != NULL) {
            printf("%s: Subject = %s\r\n", label, subject_str);
        } else {
            printf("%s: Failed to convert subject name to string\r\n", label);
        }

        wolfSSL_X509_free(cert);
    } else {
        printf("%s: Failed to parse certificate buffer\r\n", label);
    }
}

void print_ciphers(void)
{
	char cipherList[2048];
	int len = wolfSSL_get_ciphers(cipherList, sizeof(cipherList));
	if (len > 0) {
	    printf("Supported cipher list:\r\n%s\r\n", cipherList);
	} else {
	    printf("Failed to get cipher list\r\n");
	}
}
