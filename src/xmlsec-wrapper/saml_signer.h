// saml_signer.h
#ifndef SAML_SIGNER_H
#define SAML_SIGNER_H

#ifdef __cplusplus
extern "C" {
#endif

int saml_signer_init(void);   // optional explicit init
void saml_signer_shutdown(void); // optional

int sign_xml_xpath(const char *xml_input,
                   const char *xpath_expr,
                   const char *key_file,
                   const char *cert_file,
                   char **signed_xml_out);

int verify_xml_signature(const char *xml_input, const char *cert_pem);

#ifdef __cplusplus
}
#endif

#endif