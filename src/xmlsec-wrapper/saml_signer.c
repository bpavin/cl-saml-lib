// saml_signer.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/xmlIO.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/strings.h>
#include <xmlsec/xmltree.h>
#include "saml_signer.h"

/* ---------------------------
   Error codes
--------------------------- */

typedef enum {
    SAML_SIGNER_ERROR_INIT = -1,
    SAML_SIGNER_SUCCESS = 0,
    SAML_SIGNER_ERROR_INIT_FAILED = 10,
    SAML_SIGNER_ERROR_XML_PARSE = 11,
    SAML_SIGNER_ERROR_XPATH_NOT_FOUND = 12,
    SAML_SIGNER_ERROR_TEMPLATE_CREATE = 13,
    SAML_SIGNER_ERROR_REFERENCE_CREATE = 14,
    SAML_SIGNER_ERROR_KEYINFO_CREATE = 15,
    SAML_SIGNER_ERROR_DSIG_CTX_CREATE = 16,
    SAML_SIGNER_ERROR_KEY_LOAD = 17,
    SAML_SIGNER_ERROR_CERT_LOAD = 18,
    SAML_SIGNER_ERROR_SIGN = 19,
    SAML_SIGNER_ERROR_URI_MISMATCH = 20
} saml_signer_error_t;

/**
 * Convert error code to string representation.
 */
const char* saml_signer_error_to_string(int error_code) {
    switch (error_code) {
        case SAML_SIGNER_ERROR_INIT:
            return "Initialization failed";
        case SAML_SIGNER_SUCCESS:
            return "Success";
        case SAML_SIGNER_ERROR_INIT_FAILED:
            return "Signer initialization failed";
        case SAML_SIGNER_ERROR_XML_PARSE:
            return "XML parsing failed or no root element";
        case SAML_SIGNER_ERROR_XPATH_NOT_FOUND:
            return "XPath node not found";
        case SAML_SIGNER_ERROR_TEMPLATE_CREATE:
            return "Signature template creation failed or ID attribute not found";
        case SAML_SIGNER_ERROR_REFERENCE_CREATE:
            return "Reference creation failed or Signature node not found";
        case SAML_SIGNER_ERROR_KEYINFO_CREATE:
            return "KeyInfo/KeyManager/DSig context creation failed";
        case SAML_SIGNER_ERROR_DSIG_CTX_CREATE:
            return "DSig context creation or certificate loading failed";
        case SAML_SIGNER_ERROR_KEY_LOAD:
            return "Key is NULL or signature verification failed";
        case SAML_SIGNER_ERROR_CERT_LOAD:
            return "Certificate loading failed or no references exist";
        case SAML_SIGNER_ERROR_SIGN:
            return "xmlSecDSigCtxSign() failed";
        case SAML_SIGNER_ERROR_URI_MISMATCH:
            return "Reference URI mismatch";
        default:
            return "Unknown error";
    }
}

/* ---------------------------
   Global init state
--------------------------- */
static pthread_once_t g_xmlsec_once = PTHREAD_ONCE_INIT;
static int g_xmlsec_ready = 0;
static int g_xmlsec_failed = 0;
static pthread_mutex_t g_xmlsec_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------
   One-time init function
--------------------------- */

static void xmlsec_global_init_once(void)
{
    int ret = -1;

    xmlInitParser();

    if (xmlSecInit() < 0)
        goto done;

    if (xmlSecCheckVersion() != 1)
        goto done;

    if (xmlSecCryptoAppInit(NULL) < 0)
        goto done;

    if (xmlSecCryptoInit() < 0)
        goto done;

    ret = 0;

done:
    pthread_mutex_lock(&g_xmlsec_lock);

    if (ret == 0) {
        g_xmlsec_ready = 1;
        g_xmlsec_failed = 0;
    } else {
        g_xmlsec_ready = 0;
        g_xmlsec_failed = 1;

        /* best-effort cleanup if partially initialized */
        xmlSecCryptoShutdown();
        xmlSecShutdown();
        xmlCleanupParser();
    }

    pthread_mutex_unlock(&g_xmlsec_lock);
}

/* ---------------------------
   Public init (optional)
--------------------------- */

int saml_signer_init(void) {
    pthread_once(&g_xmlsec_once, xmlsec_global_init_once);

    pthread_mutex_lock(&g_xmlsec_lock);

    int ok = g_xmlsec_ready;
    int failed = g_xmlsec_failed;

    pthread_mutex_unlock(&g_xmlsec_lock);

    if (failed)
        return SAML_SIGNER_ERROR_INIT;

    if (!ok)
        return SAML_SIGNER_ERROR_INIT;

    return SAML_SIGNER_SUCCESS;
}

/* ---------------------------
   Optional shutdown
   (ONLY call at process end)
--------------------------- */

void saml_signer_shutdown(void) {
    pthread_mutex_lock(&g_xmlsec_lock);

    if (!g_xmlsec_ready) {
        pthread_mutex_unlock(&g_xmlsec_lock);
        return;
    }

    g_xmlsec_ready = 0;
    g_xmlsec_failed = 0;

    xmlSecCryptoShutdown();
    xmlSecShutdown();
    xmlCleanupParser();

    pthread_mutex_unlock(&g_xmlsec_lock);
}

/* ---------------------------
   XPath helper
--------------------------- */

static xmlNodePtr find_node_by_xpath(xmlDocPtr doc, const char *xpath_expr) {
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if(ctx == NULL) return NULL;

    xmlXPathRegisterNs(ctx, BAD_CAST "saml",
        BAD_CAST "urn:oasis:names:tc:SAML:2.0:assertion");
    xmlXPathRegisterNs(ctx, BAD_CAST "samlp",
        BAD_CAST "urn:oasis:names:tc:SAML:2.0:protocol");

    xmlXPathObjectPtr obj =
        xmlXPathEvalExpression(BAD_CAST xpath_expr, ctx);

    if(obj == NULL || xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
        xmlXPathFreeContext(ctx);
        return NULL;
    }

    xmlNodePtr node = obj->nodesetval->nodeTab[0];

    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
    return node;
}

/* ---------------------------
   Cleanup helper
--------------------------- */

static void cleanup_signing(xmlSecDSigCtxPtr dsigCtx, xmlNodePtr target, xmlNodePtr signNode, xmlDocPtr doc) {
    if(target != NULL) xmlFree(target);
    if(signNode != NULL) {
        xmlUnlinkNode(signNode);
        xmlFreeNode(signNode);
        signNode = NULL;
    }
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
}

/* ---------------------------
   XML parsing helper
--------------------------- */

static xmlDocPtr parse_xml_document(const char *xml_input) {
    return xmlParseMemory(xml_input, strlen(xml_input));
}

/* ---------------------------
   DSig context helper
--------------------------- */

static xmlSecDSigCtxPtr create_dsig_context(void) {
    return xmlSecDSigCtxCreate(NULL);
}

/* ---------------------------
   Main signing function
--------------------------- */

int sign_xml_xpath(const char *xml_input,
                   const char *xpath_expr,
                   const char *key_pem,
                   const char *cert_pem,
                   char **signed_xml_out) {
    if(saml_signer_init() != 0) return SAML_SIGNER_ERROR_INIT_FAILED;

    xmlDocPtr doc = parse_xml_document(xml_input);
    if(doc == NULL) return SAML_SIGNER_ERROR_XML_PARSE;

    xmlNodePtr target = find_node_by_xpath(doc, xpath_expr);
    if(target == NULL) {
        cleanup_signing(NULL, NULL, NULL, doc);
        return SAML_SIGNER_ERROR_XPATH_NOT_FOUND;
    }

    /* Ensure ID attribute is registered */
    xmlChar *id = xmlGetProp(target, BAD_CAST "ID");
    if(id != NULL) {
        xmlAttrPtr attr = xmlHasProp(target, BAD_CAST "ID");
        xmlAddID(NULL, doc, id, attr);
    }

    /* Create Signature template */
    xmlNodePtr signNode = xmlSecTmplSignatureCreate(
        doc,
        xmlSecTransformExclC14NId,
        xmlSecTransformRsaSha256Id,
        NULL
    );

    if(signNode == NULL) {
        cleanup_signing(NULL, NULL, NULL, doc);
        return SAML_SIGNER_ERROR_TEMPLATE_CREATE;
    }

    /* Insert after Issuer (SAML convention) */
    xmlNodePtr issuer = NULL;
    for(xmlNodePtr cur = target->children; cur; cur = cur->next) {
        if(cur->type == XML_ELEMENT_NODE &&
           xmlStrcmp(cur->name, BAD_CAST "Issuer") == 0) {
            issuer = cur;
            break;
        }
    }

    if(issuer != NULL) {
        xmlAddNextSibling(issuer, signNode);
    } else {
        xmlAddChild(target, signNode);
    }

    /* Build reference URI */
    xmlChar uri[256];
    xmlChar *uri_ptr = NULL;

    if(id != NULL) {
        snprintf((char*)uri, sizeof(uri), "#%s", (char*)id);
        uri_ptr = uri;
    }

    xmlNodePtr ref = xmlSecTmplSignatureAddReference(
        signNode,
        xmlSecTransformSha256Id,
        NULL,
        uri_ptr,
        NULL
    );

    if(ref == NULL) {
        cleanup_signing(NULL, NULL, signNode, doc);
        return SAML_SIGNER_ERROR_REFERENCE_CREATE;
    }

    xmlSecTmplReferenceAddTransform(ref, xmlSecTransformEnvelopedId);
    xmlSecTmplReferenceAddTransform(ref, xmlSecTransformExclC14NId);

    /* KeyInfo */
    xmlNodePtr keyInfo = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfo == NULL) {
        cleanup_signing(NULL, NULL, signNode, doc);
        return SAML_SIGNER_ERROR_KEYINFO_CREATE;
    }

    xmlSecTmplKeyInfoAddX509Data(keyInfo);

    /* Create signing context */
    xmlSecDSigCtxPtr dsigCtx = create_dsig_context();
    if(dsigCtx == NULL) {
        cleanup_signing(NULL, NULL, signNode, doc);
        return SAML_SIGNER_ERROR_DSIG_CTX_CREATE;
    }

    /* === KEY LOADED FROM MEMORY === */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory(
        (const xmlSecByte*)key_pem,
        strlen(key_pem),
        xmlSecKeyDataFormatPem,
        NULL, NULL, NULL
    );

    if(dsigCtx->signKey == NULL) {
        cleanup_signing(dsigCtx, NULL, signNode, doc);
        return SAML_SIGNER_ERROR_KEY_LOAD;
    }

    /* Attach certificate (optional but required for SAML interoperability) */
    if(cert_pem != NULL) {
        if(xmlSecCryptoAppKeyCertLoadMemory(
                dsigCtx->signKey,
                (const xmlSecByte*)cert_pem,
                strlen(cert_pem),
                xmlSecKeyDataFormatPem) < 0) {
            cleanup_signing(dsigCtx, NULL, signNode, doc);
            return SAML_SIGNER_ERROR_CERT_LOAD;
        }
    }

    /* Sign */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        cleanup_signing(dsigCtx, NULL, signNode, doc);
        return SAML_SIGNER_ERROR_SIGN;
    }

    /* Serialize full document */
    xmlChar *buf;
    int size;
    xmlDocDumpMemory(doc, &buf, &size);

    *signed_xml_out = (char*)malloc(size + 1);
    memcpy(*signed_xml_out, buf, size);
    (*signed_xml_out)[size] = '\0';

    xmlFree(buf);
    xmlSecDSigCtxDestroy(dsigCtx);
    xmlFreeDoc(doc);

    return SAML_SIGNER_SUCCESS;
}

/* ---------------------------
   XML signature verification
--------------------------- */

int verify_xml_signature_xpath(const char *xml_input,
                               const char *xpath_expr,
                               const char *cert_pem)
{
    if (saml_signer_init() != 0)
        return SAML_SIGNER_ERROR_INIT_FAILED;

    xmlDocPtr doc = parse_xml_document(xml_input);
    if (doc == NULL)
        return SAML_SIGNER_ERROR_XML_PARSE;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_XML_PARSE;
    }

    /* -----------------------------
       IMPORTANT: register SAML IDs correctly
       ----------------------------- */
    const xmlChar* ids[] = {
        BAD_CAST "ID",
        BAD_CAST "Id",
        NULL
    };

    xmlSecAddIDs(doc, root, ids);

    /* Find target via XPath */
    xmlNodePtr target = find_node_by_xpath(doc, xpath_expr);
    if (target == NULL) {
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_XPATH_NOT_FOUND;
    }

    /* Extract ID */
    xmlChar *id = xmlGetProp(target, BAD_CAST "ID");
    if (id == NULL)
        id = xmlGetProp(target, BAD_CAST "Id");

    if (id == NULL) {
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_TEMPLATE_CREATE;
    }

    /* -----------------------------
       FIX: Proper xml ID registration for signature resolution
       ----------------------------- */
    xmlAttrPtr idAttr = NULL;

    if (xmlHasProp(target, BAD_CAST "ID") != NULL)
        idAttr = xmlHasProp(target, BAD_CAST "ID");
    else
        idAttr = xmlHasProp(target, BAD_CAST "Id");

    if (idAttr != NULL) {
        /* THIS is the critical fix */
        xmlAddID(NULL, doc, id, idAttr);
    }

    /* Find Signature inside target */
    xmlNodePtr sigNode =
        xmlSecFindNode(target, xmlSecNodeSignature, xmlSecDSigNs);

    if (sigNode == NULL) {
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_REFERENCE_CREATE;
    }

    /* -----------------------------
       Key Manager (STRICT TRUST MODEL)
       ----------------------------- */
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_KEYINFO_CREATE;
    }

    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_KEYINFO_CREATE;
    }

    /* Load ONLY trusted IdP certificate */
    if (cert_pem != NULL) {
      if (xmlSecCryptoAppKeysMngrCertLoadMemory(
                mngr,
                (const xmlSecByte*)cert_pem,
                strlen(cert_pem),
                xmlSecKeyDataFormatPem,
                xmlSecKeyDataTypeTrusted) < 0) {

            xmlSecKeysMngrDestroy(mngr);
            xmlFree(id);
            xmlFreeDoc(doc);
            return SAML_SIGNER_ERROR_DSIG_CTX_CREATE;
        }
    }

    /* -----------------------------
       Signature verification
       ----------------------------- */
    xmlSecDSigCtxPtr dsigCtx = xmlSecDSigCtxCreate(mngr);
    if (dsigCtx == NULL) {
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_KEYINFO_CREATE;
    }

    int ret = xmlSecDSigCtxVerify(dsigCtx, sigNode);

    if (ret < 0 || dsigCtx->status != xmlSecDSigStatusSucceeded) {
        xmlSecDSigCtxDestroy(dsigCtx);
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_KEY_LOAD;
    }

    /* Ensure references exist */
    xmlSecSize refsSize =
        xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences));

    if (refsSize == 0) {
        xmlSecDSigCtxDestroy(dsigCtx);
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_CERT_LOAD;
    }

    /* Validate Reference URI matches expected ID */
    int found = 0;

    for (xmlSecSize i = 0; i < refsSize; i++) {
        xmlSecDSigReferenceCtxPtr ref =
            (xmlSecDSigReferenceCtxPtr)
            xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), i);

        if (ref != NULL && ref->uri != NULL && ref->uri[0] == '#') {
            if (xmlStrcmp(ref->uri + 1, id) == 0) {
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        xmlSecDSigCtxDestroy(dsigCtx);
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return SAML_SIGNER_ERROR_URI_MISMATCH;
    }

    /* Cleanup */
    xmlSecDSigCtxDestroy(dsigCtx);
    xmlSecKeysMngrDestroy(mngr);
    xmlFree(id);
    xmlFreeDoc(doc);

    return SAML_SIGNER_SUCCESS;
}
