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
        return -1;

    if (!ok)
        return -1;

    return 0;
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
   Generic cleanup helper
--------------------------- */

static void cleanup_xml_ctx(xmlSecDSigCtxPtr dsigCtx, xmlDocPtr doc) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    xmlCleanupParser();
}

/* ---------------------------
   Main signing function
--------------------------- */

int sign_xml_xpath(const char *xml_input,
                   const char *xpath_expr,
                   const char *key_pem,
                   const char *cert_pem,
                   char **signed_xml_out) {

    if(saml_signer_init() != 0) return 10;

    xmlDocPtr doc = parse_xml_document(xml_input);
    if(doc == NULL) return 11;

    xmlNodePtr target = find_node_by_xpath(doc, xpath_expr);
    if(target == NULL) {
        cleanup_signing(NULL, NULL, NULL, doc);
        return 12;
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
        return 13;
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
        return 14;
    }

    xmlSecTmplReferenceAddTransform(ref, xmlSecTransformEnvelopedId);
    xmlSecTmplReferenceAddTransform(ref, xmlSecTransformExclC14NId);

    /* KeyInfo */
    xmlNodePtr keyInfo = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfo == NULL) {
        cleanup_signing(NULL, NULL, signNode, doc);
        return 15;
    }

    xmlSecTmplKeyInfoAddX509Data(keyInfo);

    /* Create signing context */
    xmlSecDSigCtxPtr dsigCtx = create_dsig_context();
    if(dsigCtx == NULL) {
        cleanup_signing(NULL, NULL, signNode, doc);
        return 16;
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
        return 17;
    }

    /* Attach certificate (optional but required for SAML interoperability) */
    if(cert_pem != NULL) {
        if(xmlSecCryptoAppKeyCertLoadMemory(
                dsigCtx->signKey,
                (const xmlSecByte*)cert_pem,
                strlen(cert_pem),
                xmlSecKeyDataFormatPem) < 0) {
            cleanup_signing(dsigCtx, NULL, signNode, doc);
            return 18;
        }
    }

    /* Sign */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        cleanup_signing(dsigCtx, NULL, signNode, doc);
        return 19;
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

    return 0;
}

/* ---------------------------
   XML signature verification
--------------------------- */

int verify_xml_signature_xpath(const char *xml_input,
                               const char *xpath_expr,
                               const char *cert_pem)
{
    if (saml_signer_init() != 0)
        return 10;

    xmlDocPtr doc = parse_xml_document(xml_input);
    if (doc == NULL)
        return 11;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 11;
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
        return 12;
    }

    /* Extract ID */
    xmlChar *id = xmlGetProp(target, BAD_CAST "ID");
    if (id == NULL)
        id = xmlGetProp(target, BAD_CAST "Id");

    if (id == NULL) {
        xmlFreeDoc(doc);
        return 13;
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
        return 14;
    }

    /* -----------------------------
       Key Manager (STRICT TRUST MODEL)
       ----------------------------- */
    xmlSecKeysMngrPtr mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        xmlFree(id);
        xmlFreeDoc(doc);
        return 15;
    }

    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return 15;
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
            return 16;
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
        return 15;
    }

    int ret = xmlSecDSigCtxVerify(dsigCtx, sigNode);

    if (ret < 0 || dsigCtx->status != xmlSecDSigStatusSucceeded) {
        xmlSecDSigCtxDestroy(dsigCtx);
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return 17;
    }

    /* Ensure references exist */
    xmlSecSize refsSize =
        xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences));

    if (refsSize == 0) {
        xmlSecDSigCtxDestroy(dsigCtx);
        xmlSecKeysMngrDestroy(mngr);
        xmlFree(id);
        xmlFreeDoc(doc);
        return 18;
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
        return 20;
    }

    /* Cleanup */
    xmlSecDSigCtxDestroy(dsigCtx);
    xmlSecKeysMngrDestroy(mngr);
    xmlFree(id);
    xmlFreeDoc(doc);

    return 0;
}
