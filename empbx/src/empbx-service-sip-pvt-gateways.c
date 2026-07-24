/**
 **
 ** (C)2026 akstel.org
 **/
#include <empbx.h>
#include "empbx-service-sip-pvt.h"

extern empbx_global_t *global;
extern sipd_runtime_t sipd_runtime;

static void destructor__empbx_registration_gateway_t(void *arg) {
    empbx_registration_gateway_t *obj = (empbx_registration_gateway_t *)arg;

    log_debug("Deleting gateway-registarion (%p) [gw-name=%s, refs=%d, ua=%p]", obj, obj->gw_name, obj->refs, obj->ua);

    if(obj->refs && obj->mutex) {
        bool flw = true;
        while(flw) {
            mtx_lock(obj->mutex);
            flw = obj->refs > 0;
            mtx_unlock(obj->mutex);
            sys_msleep(250);
        }
    }

    mem_deref(obj->mutex);

    log_debug("registarion deleted (%p)", obj);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
empbx_registration_gateway_t *empbx_registation_gateway_lookup(char *user_id) {
    empbx_registration_gateway_t *entry = NULL;

    if(zstr(user_id) || !sipd_runtime.regmap_gateways) {
        return NULL;
    }

    mtx_lock(sipd_runtime.regmap_gateways_mutex);
    entry = empbx_hash_find(sipd_runtime.regmap_gateways, user_id);
    if(entry && entry->mutex) {
        mtx_lock(entry->mutex);
        entry->refs++;
        mtx_unlock(entry->mutex);
    }
    mtx_unlock(sipd_runtime.regmap_gateways_mutex);

    return entry;
}

empbx_registration_gateway_t *empbx_registation_gateway_lookup_by_name(char *name) {
    empbx_registration_gateway_t *entry = NULL;
    empbx_registration_gateway_t *tmpv = NULL;
    empbx_hash_index_t *hidx = NULL;

    if(zstr(name) || !sipd_runtime.regmap_gateways) {
        return NULL;
    }

    mtx_lock(sipd_runtime.regmap_gateways_mutex);
    for(hidx = empbx_hash_first_iter(sipd_runtime.regmap_gateways, hidx); hidx; hidx = empbx_hash_next(&hidx)) {
        empbx_hash_this(hidx, NULL, NULL, (void *)&tmpv);
        if(tmpv && !str_casecmp(tmpv->gw_name, name)) {
            entry = tmpv;
            break;
        }
    }
    mem_deref(hidx);

    if(entry && entry->mutex) {
        mtx_lock(entry->mutex);
        entry->refs++;
        mtx_unlock(entry->mutex);
    }
    mtx_unlock(sipd_runtime.regmap_gateways_mutex);

    return entry;
}

bool empbx_registration_gateway_take(empbx_registration_gateway_t *reg) {
    if(!reg || !reg->mutex) return false;
    mtx_lock(reg->mutex);
    reg->refs++;
    mtx_unlock(reg->mutex);
    return true;
}

void empbx_registration_gateway_release(empbx_registration_gateway_t *reg) {
    if(reg) {
        mtx_lock(reg->mutex);
        if(reg->refs > 0) reg->refs--;
        mtx_unlock(reg->mutex);
    }
}

empbx_status_t empbx_registration_gateway_add(empbx_gateway_entry_t *entry) {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;
    empbx_registration_gateway_t *reg = NULL;
    bool ua_failed = false;
    int err = 0;

    if(!entry) {
        return EMPBX_STATUS_FALSE;
    }

    reg = mem_zalloc(sizeof(empbx_registration_gateway_t), destructor__empbx_registration_gateway_t);
    if(!reg) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(mutex_alloc(&reg->mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    reg->refs = 0;
    reg->gw_name = entry->name;
    reg->user_id = entry->user_id;
    reg->realm = entry->realm;
    reg->ua_conf = entry->config;

    // update ua
    mtx_lock(sipd_runtime.baresip_mutex);
    if(ua_alloc(&reg->ua, reg->ua_conf) == LIBRE_SUCCESS) {
        account_t *acc = ua_account(reg->ua);
        if(acc) {
            ua_set_catchall(reg->ua, true);
            empbx_baresip_ua_set_xdata(reg->ua, empbx_xuser_data_alloc(reg, EMPBX_XUD_GATEWAY, false), true);
            if(account_regint(acc)) {
                if(!account_prio(acc)) {
                    err = ua_register(reg->ua);
                } else {
                    err = ua_fallback(reg->ua);
                }
                if(err) {
                    log_warn("Gateway registration failed (%s) [err=%i]\n", account_aor(acc), err);
                }
            }
        } else {
            log_error("ua_account() failed");
            ua_failed = true;
        }
    } else {
        log_error("ua_alloc() failed");
        ua_failed = true;
    }
    mtx_unlock(sipd_runtime.baresip_mutex);

    if(ua_failed) {
        empbx_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    /* add to map */
    mtx_lock(sipd_runtime.regmap_gateways_mutex);
    status = empbx_hash_insert_ex(sipd_runtime.regmap_gateways, reg->user_id, reg, true);
    mtx_unlock(sipd_runtime.regmap_gateways_mutex);

out:
    if(status == EMPBX_STATUS_SUCCESS) {
        log_debug("Gateway registered (%s) ua=%p", reg->gw_name, reg->ua);
    } else {
        if(reg && reg->ua) { empbx_ua_destroy(&reg->ua); }
        mem_deref(reg);
    }
    return status;
}
