#ifndef CERT_VALIDATION_H
#define CERT_VALIDATION_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FALSE 0
#define TRUE 1
#define WILDCARD '*'
#define CERT_AUTHORITY "CA:FALSE"
#define DATE_SIZE 8
#define EXTENDED_KEY_VALIDATION "TLS Web Server Authentication"
#define COMMON_NAME_NOT_FOUND "Subject CN NOT FOUND"
#define MIN_KEY_LENGTH 256
#define NUM_COLS 2

int check_extended_key_usage(X509 *cert);
int check_basic_constraints(X509 *cert);
int check_key_length(X509 *cert);
int check_dates(X509 *cert);
int check_domain(char* url, X509 *cert);
int check_common_name(char* url, X509 *cert);
int check_subject_alternative_name(char* url, X509 *cert);
X509* initialise_certificate(BIO *certificate_bio, char* cert_path);

#endif
