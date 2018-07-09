/*
    * Comp 30023 Computer Systems
    * Assignment 2
    * Author: Sayyaf Waseem
    * Student ID: 841546
    * Last updated: 22/05/2019
    *
    * Program takes in path to a set of TLS certificates and tests them
    * for validation, outputting a csv file to show which of the certificate
    * were valid
    * Adapted from sample code provided by Professor Chris Culnane
*/

#include "certificate_validation_operations.h"


X509* initialise_certificate(BIO *certificate_bio, char* cert_path);

int main(int argc, char* argv[]) {
    char test_cert[500], url[100], cert_path[100];
    strcpy(test_cert, argv[1]);
    FILE* fp = fopen(test_cert,"r");
    FILE* write = fopen("output.csv", "w");
    //Reads from input file in requisite csv format
    while(fscanf(fp, " %[^,],%[^\n]", cert_path, url) == NUM_COLS) {
        BIO *certificate_bio = NULL;
        X509 *cert = NULL;
        //initialise openSSL
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();
        //create BIO object to read certificate
        certificate_bio = BIO_new(BIO_s_file());
        //Ensures that all necessary certificate characteristics are valid
        if((cert = initialise_certificate(certificate_bio, cert_path)) &&
            check_basic_constraints(cert) == TRUE &&
            check_key_length(cert)== TRUE &&
            check_dates(cert)== TRUE &&
            check_domain(url, cert)== TRUE &&
            check_extended_key_usage(cert)) {
            //writes to output file in csv format, showing certificate is valid
            fprintf(write, "%s,%s,%d\n", cert_path, url, 1);
        }
        else {
            //writes to output file showing certificate is invalid
            fprintf(write, "%s,%s,%d\n", cert_path, url, 0);
        }
        //Free memory used for certificate specific validation
        X509_free(cert);
        BIO_free_all(certificate_bio);
    }
    //Close output file
    fclose(fp);
    return 0;
}
