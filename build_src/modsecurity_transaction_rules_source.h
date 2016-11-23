/*
 * modsecurity.h section
 */

typedef struct ModSecurity_t ModSecurity;

#include "modsecurity/intervention.h"
#include "modsecurity/transaction.h"
#include "modsecurity/debug_log.h"

/**
 * TAG_NUM:
 *
 * Alpha  - 001
 * Beta   - 002
 * Dev    - 010
 * Rc1    - 051
 * Rc2    - 052
 * ...    - ...
 * Release- 100
 *
 */

#define MODSECURITY_MAJOR "3"
#define MODSECURITY_MINOR "0"
#define MODSECURITY_PATCHLEVEL "0"
#define MODSECURITY_TAG "-alpha"
#define MODSECURITY_TAG_NUM "001"

#define MODSECURITY_VERSION MODSECURITY_MAJOR "." \
    MODSECURITY_MINOR "." MODSECURITY_PATCHLEVEL \
    MODSECURITY_TAG

#define MODSECURITY_VERSION_NUM MODSECURITY_MAJOR \
    MODSECURITY_MINOR MODSECURITY_PATCHLEVEL MODSECURITY_TAG_NUM

typedef void (*LogCb) (void *, const char *);

/** @ingroup ModSecurity_C_API */
ModSecurity *msc_init(void);
/** @ingroup ModSecurity_C_API */
const char *msc_who_am_i(ModSecurity *msc);
/** @ingroup ModSecurity_C_API */
void msc_set_connector_info(ModSecurity *msc, const char *connector);
/** @ingroup ModSecurity_C_API */
void msc_set_log_cb(ModSecurity *msc, LogCb cb);
/** @ingroup ModSecurity_C_API */
void msc_cleanup(ModSecurity *msc);

/*
 * transaction.h section
 */

#include <stdlib.h>
#include <stddef.h>

#include "modsecurity/intervention.h"
#include "modsecurity/collection/collections.h"
#include "modsecurity/collection/variable.h"
#include "modsecurity/collection/collection.h"

typedef struct ModSecurity_t ModSecurity;
typedef struct ModSecurityIntervention_t ModsecurityIntervention;
typedef struct Transaction_t Transaction;
typedef struct Rules_t Rules;

#define LOGFY_ADD(a, b) \
    yajl_gen_string(g, reinterpret_cast<const unsigned char*>(a), strlen(a)); \
    if (b == NULL) { \
      yajl_gen_string(g, reinterpret_cast<const unsigned char*>(""), \
          strlen("")); \
    } else { \
      yajl_gen_string(g, reinterpret_cast<const unsigned char*>(b), \
          strlen(b)); \
	  }

#define LOGFY_ADD_INT(a, b) \
    yajl_gen_string(g, reinterpret_cast<const unsigned char*>(a), strlen(a)); \
    yajl_gen_number(g, reinterpret_cast<const char*>(b), strlen(b));

#define LOGFY_ADD_NUM(a, b) \
    yajl_gen_string(g, reinterpret_cast<const unsigned char*>(a), strlen(a)); \
    yajl_gen_integer(g, b);

Transaction *msc_new_transaction(ModSecurity *ms,
    Rules *rules, void *logCbData);

/** @ingroup ModSecurity_C_API */
int msc_process_connection(Transaction *transaction,
    const char *client, int cPort, const char *server, int sPort);

/** @ingroup ModSecurity_C_API */
int msc_process_request_headers(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_add_request_header(Transaction *transaction, const unsigned char *key,
    const unsigned char *value);

/** @ingroup ModSecurity_C_API */
int msc_process_request_body(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_append_request_body(Transaction *transaction,
    const unsigned char *body, size_t size);

/** @ingroup ModSecurity_C_API */
int msc_request_body_from_file(Transaction *transaction, const char *path);

/** @ingroup ModSecurity_C_API */
int msc_process_response_headers(Transaction *transaction, int code,
    const char* protocol);

/** @ingroup ModSecurity_C_API */
int msc_add_response_header(Transaction *transaction,
    const unsigned char *key, const unsigned char *value);

/** @ingroup ModSecurity_C_API */
int msc_process_response_body(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_append_response_body(Transaction *transaction,
    const unsigned char *body, size_t size);

/** @ingroup ModSecurity_C_API */
int msc_process_uri(Transaction *transaction, const char *uri,
    const char *protocol, const char *http_version);

/** @ingroup ModSecurity_C_API */
const char *msc_get_response_body(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_get_response_body_length(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
void msc_transaction_cleanup(Transaction *transaction);

/** @ingroup ModSecurity_C_API */
int msc_intervention(Transaction *transaction, ModSecurityIntervention *it);

/** @ingroup ModSecurity_C_API */
int msc_process_logging(Transaction *transaction);

/*
 * rules.h section
 */

#include <stdio.h>
#include <string.h>

#include "modsecurity/rules_properties.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"

typedef struct Rules_t Rules;

Rules *msc_create_rules_set(void);
void msc_rules_dump(Rules *rules);
int msc_rules_merge(Rules *rules_dst, Rules *rules_from);
int msc_rules_add_remote(Rules *rules, const char *key, const char *uri,
    const char **error);
int msc_rules_add_file(Rules *rules, const char *file, const char **error);
int msc_rules_add(Rules *rules, const char *plain_rules, const char **error);
int msc_rules_cleanup(Rules *rules);

