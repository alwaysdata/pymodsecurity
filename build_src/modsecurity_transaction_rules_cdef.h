/*
 * modsecurity.h section
 */

typedef struct ModSecurity_t ModSecurity;
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

typedef struct ModSecurity_t ModSecurity;
typedef struct ModSecurityIntervention_t {    
    int status;
    int pause;
    const char *url;
    const char *log;
    int disruptive;
}ModSecurityIntervention;
typedef struct Transaction_t Transaction;
typedef struct Rules_t Rules;


/** @ingroup ModSecurity_C_API */
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

typedef struct Rules_t Rules;

Rules *msc_create_rules_set(void);
void msc_rules_dump(Rules *rules);
int msc_rules_merge(Rules *rules_dst, Rules *rules_from);
int msc_rules_add_remote(Rules *rules, const char *key, const char *uri,
    const char **error);
int msc_rules_add_file(Rules *rules, const char *file, const char **error);
int msc_rules_add(Rules *rules, const char *plain_rules, const char **error);
int msc_rules_cleanup(Rules *rules);
