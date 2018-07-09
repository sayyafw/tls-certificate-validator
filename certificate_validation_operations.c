#include "certificate_validation_operations.h"


/* Checks basic constraints to ensure certificate is not a certification
    authority. Adapted from sample code provided by Professor Chris Culnane*/
int check_basic_constraints(X509 *cert) {
    ASN1_OBJECT *obj = NULL;
    //Gets basic constraints extension
    X509_EXTENSION *basic_constraints = X509_get_ext(cert,
         X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
    //Gets the associated object
    if(basic_constraints!= NULL) {
        obj = X509_EXTENSION_get_object(basic_constraints);
    }
    if(obj == NULL) {
        return FALSE;
    }
    //Converts object content to string
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, basic_constraints, 0, 0)) {
        fprintf(stderr, "Error in reading extensions");
        BIO_free_all(bio);
        return FALSE;
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    //bptr->data is not NULL terminated - add null character
    buf[bptr->length] = '\0';
    char* basic_constraints_check = CERT_AUTHORITY;
    //Compares basic constraints with CA:FALSE to validate
    if (strcmp(basic_constraints_check, buf) == 0) {
        BIO_free_all(bio);
        free(buf);
        return TRUE;
    }
    //Free the memory
    free(buf);
    BIO_free_all(bio);
    return FALSE;
}

/* Checks RSA key length to ensure it is more than or equal to 2048 bits
*/
int check_key_length(X509 *cert) {
    //Gets public key
    EVP_PKEY *pkey = X509_get_pubkey(cert);
	RSA *rsa_key;
    //Extracts RSA key from public key
	rsa_key = pkey->pkey.rsa;
    if(rsa_key == NULL) {
        EVP_PKEY_free(pkey);
        return FALSE;
    }
    //Gets length of key
    int key_length = RSA_size(rsa_key);
    //Ensure key length is mandatory minimum
    if(key_length >= MIN_KEY_LENGTH) {
        EVP_PKEY_free(pkey);
        return TRUE;
    }
    EVP_PKEY_free(pkey);
    return FALSE;
}

/* Function to validate that the certificate is currently within its start and
expirty dates*/
int check_dates(X509 *cert) {
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    struct tm *date;
    //Get expiry date and begin date as strings in the form yyyymmddhhmmssz
    char *expiry = (char *) ASN1_STRING_data(not_after);
    char* begin = (char *) ASN1_STRING_data(not_before);
    //Shorten the date format to yyyymmdd for date validation
    char expiry_date[50], begin_date[50];
    /*Only copies the first 8 characters, to give date in required
    format*/
    strncpy(expiry_date, expiry, DATE_SIZE);
    expiry_date[DATE_SIZE] = '\0';
    strncpy(begin_date, begin, DATE_SIZE);
    begin_date[DATE_SIZE] = '\0';
    //Initialises time struct
    char current_date[100];
    time_t current_time;
    time(&current_time);
    date = localtime(&current_time);
    //Gets current system date as a string in the form yyyymmdd
    strftime(current_date, DATE_SIZE+1,"%Y%m%d", date);
    //Checks that current date falls within the begin and expiry date bounds
    if(strcmp(current_date, expiry_date) <= 0 && strcmp(current_date,
         begin_date) >= 0 ) {
        return TRUE;
    }
    //Certificate is invalid, either expired or not yet valid
    return FALSE;
}

/* Function to validate extended key usage
    Adapted from sample code provided by Professor Chris Culnane */
int check_extended_key_usage(X509 *cert) {
    //Initiates extended key object and gets extension
    ASN1_OBJECT *obj = NULL;
    X509_EXTENSION *extended_key = X509_get_ext(cert,
        X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    if(extended_key!= NULL) {
        obj = X509_EXTENSION_get_object(extended_key);
    }
    if(obj == NULL) {
        return FALSE;
    }
    //Reads extension and converts extened key object to string
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, extended_key, 0, 0))  {
        fprintf(stderr, "Error in reading extensions");
        BIO_free_all(bio);
        return FALSE;
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    //bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    char* extended_key_check = EXTENDED_KEY_VALIDATION;
    //Checks that one of the extended key usage values is as required
    if (strstr(buf, extended_key_check) != NULL) {
        BIO_free_all(bio);
        return TRUE;
    }
    BIO_free_all(bio);
    //Fails Extended Key Check Validation
    return FALSE;
}

/* Calls necessary methods to check if URL falls within either Common name
or Subject Alternative Name */
int check_domain(char* url, X509 *cert) {
    if (check_subject_alternative_name(url, cert) == TRUE ||
        check_common_name(url, cert) == TRUE) {
            return TRUE;
    }
    //URL could not be found in SAN or Common Name
    return FALSE;
}

//Checks if URL can be found in Subject Alternative Names field
int check_subject_alternative_name(char* url, X509 *cert) {
    GENERAL_NAME *one_SAN = NULL;
    //Defines a stack object to hold the Subject Alternative Name
    STACK_OF(ASN1_OBJECT) *subject_alt_names = NULL;
    subject_alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name,
        NULL, NULL);
    if (subject_alt_names != NULL) {
        //For all names in the stack, compare url to see if found
        while (sk_GENERAL_NAME_num(subject_alt_names) > 0)   {
            //Pops the first name from the stack
            one_SAN = sk_GENERAL_NAME_pop(subject_alt_names);x
            //Ensures element is a Subject Alternative Name
            if (one_SAN->type == GEN_DNS) {
                //Converts SAN to string
                char *SAN_name = (char *) ASN1_STRING_data(one_SAN->d.dNSName);
                //Checks if SAN is a wildcard and if so, checks if URL is valid
                printf("SAN NAME %s\n\n", SAN_name);
                if(SAN_name[0] == '*') {
                    if(strstr(url, SAN_name+1)!= NULL) {
                        return TRUE;
                    }
                }
                //If not wildcard, checks if URL is valid
                else {
                    if(strcmp(url, SAN_name) == 0) {
                        return TRUE;
                    }
                }
            }
        }
    }
    //URL not found in SAN
    return FALSE;
}

/* Checks URL with Common Name given in the certificate */
int check_common_name(char* url, X509 *cert) {
    X509_NAME *subject_name = NULL;
    /* Gets the certificate subject name */
    subject_name = X509_get_subject_name(cert);
    char subject_cn[256] = COMMON_NAME_NOT_FOUND;
    if(subject_cn == NULL) {
        return FALSE;
    }
    /*Gets certificate common name*/
    X509_NAME_get_text_by_NID(subject_name, NID_commonName, subject_cn, 256);
    if(strcmp(subject_cn, COMMON_NAME_NOT_FOUND) == 0 || subject_cn == NULL) {
        return FALSE;
    }
    /*Checks if certificate is wildcard */
    if(subject_cn[0] == WILDCARD) {
        /*If common name is wildcard, check if wildcard is a
            substring of the given url */
        if(strstr(url, subject_cn+1)!= NULL) {
            return TRUE;
        }
        //URL not valid
        return FALSE;
    }
    /* If not wildcard, just check if url and common name are same */
    else {
        if(strcmp(url, subject_cn) ==0) {
            return TRUE;
        }
        //URL not valid
        return FALSE;
    }
}

/* Initialises the X509 certificate used to validate TLS certificate
    Adapted from sample code provided by professor Chris Culnane*/
X509* initialise_certificate(BIO *certificate_bio, char* cert_path) {
    X509 *cert = NULL;
    if (!(BIO_read_filename(certificate_bio, cert_path))) {
        fprintf(stderr, "Error in reading cert BIO filename");
        return NULL;
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate");
        return NULL;
    }
    return cert;
}
