/**
 **
 ** (C)2026 akstel.org
 **/
#ifndef EMPBX_SERVICE_SIP_H
#define EMPBX_SERVICE_SIP_H
#include <empbx-core.h>

typedef enum {
    EMPBX_SESS_INBOUND,     // from gw
    EMPBX_SESS_OUTBOUND,    // to gw
    EMPBX_SESS_INTERCOM     // user <> user
} empbx_session_type_e;

typedef struct {
    mutex_t                 *mutex;
    empbx_user_entry_t      *user;          // refs
    char                    *user_id;
    char                    *realm;
    char                    *display_name;
    char                    *contact;       // sip:id@ip:port
    char                    *contact_str;   // from sip message
    char                    *ua_conf;       // for ua client
    ua_t                    *ua;            // baresip sip us
    uri_t                   contact_uri;    // ref to contact_str
    uint32_t                lifetime;       // sec
    uint32_t                expires;
    uint32_t                refs;
    bool                    fl_entity_updating;
} empbx_registration_user_t;

typedef struct {
    mutex_t                 *mutex;
    char                    *gw_name;   // refs
    char                    *user_id;   // refs
    char                    *realm;     // refs
    char                    *ua_conf;   // refs
    ua_t                    *ua;        // baresip sip us
    uint32_t                refs;
} empbx_registration_gateway_t;

typedef struct {
    mutex_t                 *mutex;
    empbx_queue_t           *dtmfq;
    call_t                  *lega;
    call_t                  *legb;
    char                    *id;
    char                    *legb_aor;
    char                    *lega_aor;
    char                    *lega_contact;
    empbx_session_type_e    type;
    uint32_t                started;
    uint32_t                refs;
    bool                    fl_hangup_req;
    bool                    fl_setup_done;
} empbx_session_t;

typedef void (empbx_dialplan_app_unload_h)(void);
typedef empbx_status_t (empbx_dialplan_app_perform_h)(ua_t *ua, call_t *call, const char *args);
typedef struct {
    mutex_t                         *mutex;
    char                            *name;
    empbx_dialplan_app_unload_h     *unload_h;
    empbx_dialplan_app_perform_h    *perform_h;
    uint32_t                        refs;
} empbx_dialplan_app_t;

typedef enum {
    EMPBX_XUD_NONE = 0,
    EMPBX_XUD_USER,
    EMPBX_XUD_GATEWAY,
    EMPBX_XUD_SESSION,
} empbx_xuser_data_type_e;

typedef struct {
    void                    *data;
    bool                    destroyable; // destroy_data;
    empbx_xuser_data_type_e type;
} empbx_xuser_data_t;

typedef struct {
    empbx_dialplan_rule_t   *rule;          // refs
    char                    *dst_number;    // real distination
} empbx_dialplan_lookup_result_t;

typedef struct {
    const char      *dst_number;
    const char      *caller_id_name;
    const char      *caller_id_number;
    const char      *gateway;
} empbx_dialplan_lookup_prams_t;


/* service-sip */
empbx_status_t empbx_service_sip_start();
empbx_status_t empbx_service_sip_stop();

/* user */
empbx_registration_user_t *empbx_registation_user_lookup(char *user_id);
void empbx_registration_user_release(empbx_registration_user_t *reg);
bool empbx_registration_user_take(empbx_registration_user_t *reg);

/* gateway */
empbx_registration_gateway_t *empbx_registation_gateway_lookup(char *user_id);
empbx_registration_gateway_t *empbx_registation_gateway_lookup_by_name(char *name);
void empbx_registration_gateway_release(empbx_registration_gateway_t *reg);
bool empbx_registration_gateway_take(empbx_registration_gateway_t *reg);

/* session */
empbx_session_t *empbx_session_lookup(char *sid);
bool empbx_session_take(empbx_session_t *sess);
void empbx_session_release(empbx_session_t *sess);

/* dialplan */
empbx_status_t empbx_dialplan_lookup(empbx_dialplan_lookup_result_t *result, empbx_dialplan_lookup_prams_t *lparams);

/* applications */
empbx_status_t empbx_dialplan_application_register(const char *name, empbx_dialplan_app_unload_h *uh, empbx_dialplan_app_perform_h *ph);
empbx_dialplan_app_t *empbx_dialplan_application_lookup(char *name);
bool empbx_dialplan_application_take(empbx_dialplan_app_t *app);
void empbx_dialplan_application_release(empbx_dialplan_app_t *app);

/* common */
empbx_xuser_data_t *empbx_xuser_data_alloc(void *data, empbx_xuser_data_type_e type, bool destroy_data);
empbx_status_t empbx_extract_number_from_uri(char *buf, size_t bufsz, const char *uri_str);

#endif
