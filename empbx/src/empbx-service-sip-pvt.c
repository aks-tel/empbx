/**
 **
 ** (C)2026 akstel.org
 **/
#include <empbx.h>
#include "empbx-service-sip-pvt.h"

extern empbx_global_t *global;
extern sipd_runtime_t sipd_runtime;

static void destructor__empbx_xuser_data_t(void *arg) {
    empbx_xuser_data_t *obj = (empbx_xuser_data_t *)arg;

    if(!obj) { return; }

    if(obj->type == EMPBX_XUD_GATEWAY) {
        empbx_registration_gateway_release((empbx_registration_gateway_t *)obj->data);
    } else if(obj->type == EMPBX_XUD_USER) {
        empbx_registration_user_release((empbx_registration_user_t *)obj->data);
    } 

    if(obj->destroy_data) {
        obj->data = mem_deref(obj->data);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
empbx_xuser_data_t *empbx_xuser_data_alloc(void *data, empbx_xuser_data_type_e type, bool destroy_data) {
    empbx_xuser_data_t *result = NULL;

    result = mem_zalloc(sizeof(empbx_xuser_data_t), destructor__empbx_xuser_data_t);
    if(!result) {
        log_mem_fail();
        goto out;
    }
    if(type == EMPBX_XUD_GATEWAY) {
        empbx_registration_gateway_take((empbx_registration_gateway_t *)data);
    } else if(type == EMPBX_XUD_USER) {
        empbx_registration_user_take((empbx_registration_user_t *)data);
    }

    result->data = data;
    result->type = type;
    result->destroy_data = destroy_data;
out:
    return result;
}

empbx_status_t empbx_extract_number_from_uri(char *buf, size_t bufsz, const char *uri_str) {
    uri_t uri = {0};
    pl_t uri_pl = {0};

    if(!buf || !bufsz || !uri_str) {
        return EMPBX_STATUS_FALSE;
    }

    uri_pl.p = uri_str;
    uri_pl.l = strlen(uri_str);

    if(uri_decode(&uri, &uri_pl)) {
        log_error("Unable to decode uri (%s)", uri_str);
        return EMPBX_STATUS_FALSE;
    }

    if(uri.user.l) {
        re_snprintf(buf, bufsz, "%r", &uri.user);
        return EMPBX_STATUS_SUCCESS;
    }

    return EMPBX_STATUS_FALSE;
}
