/**
 **
 ** (C)2026 akstel.org
 **/
#include <empbx.h>
#include "empbx-service-sip-pvt.h"

extern empbx_global_t *global;
extern sipd_runtime_t sipd_runtime;

static void destructor__empbx_registration_user_t(void *arg) {
    empbx_registration_user_t *obj = (empbx_registration_user_t *)arg;

    log_debug("delete user-registarion (%p) [user=%s, refs=%d, ua=%p]", obj, obj->user_id, obj->refs, obj->ua);

    if(obj->refs && obj->mutex) {
        bool flw = true;
        while(flw) {
            mtx_lock(obj->mutex);
            flw = obj->refs > 0;
            mtx_unlock(obj->mutex);
            sys_msleep(250);
        }
    }

    mem_deref(obj->user_id);
    mem_deref(obj->realm);
    mem_deref(obj->contact);
    mem_deref(obj->contact_str);
    mem_deref(obj->display_name);
    mem_deref(obj->ua_conf);
    mem_deref(obj->mutex);

    log_debug("registarion deleted (%p)", obj);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
empbx_registration_user_t *empbx_registation_user_lookup(char *user_id) {
    empbx_registration_user_t *entry = NULL;

    if(zstr(user_id) || !sipd_runtime.regmap_users) {
        return NULL;
    }

    mtx_lock(sipd_runtime.regmap_users_mutex);
    entry = empbx_hash_find(sipd_runtime.regmap_users, user_id);
    if(entry && entry->mutex) {
        mtx_lock(entry->mutex);
        entry->refs++;
        mtx_unlock(entry->mutex);
    }
    mtx_unlock(sipd_runtime.regmap_users_mutex);

    return entry;
}

void empbx_registration_user_release(empbx_registration_user_t *reg) {
    if(reg) {
        if(!reg->fl_entity_updating) { mtx_lock(reg->mutex); }
        if(reg->refs > 0) reg->refs--;
        if(!reg->fl_entity_updating) { mtx_unlock(reg->mutex); }
    }
}

bool empbx_registration_user_take(empbx_registration_user_t *reg) {
    if(!reg || !reg->mutex) return false;

    if(!reg->fl_entity_updating) { mtx_lock(reg->mutex); }
    reg->refs++;
    if(!reg->fl_entity_updating) { mtx_unlock(reg->mutex); }

    return true;
}

void empbx_registration_user_delete(char *user_id) {
    if(zstr(user_id) || !sipd_runtime.regmap_users) {
        return;
    }

    mtx_lock(sipd_runtime.regmap_users_mutex);
    empbx_hash_delete(sipd_runtime.regmap_users, user_id);
    mtx_unlock(sipd_runtime.regmap_users_mutex);
}

empbx_status_t empbx_registration_user_update(empbx_registration_user_t *reg, char *contact, const sip_msg_t *sip_msg) {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;
    mbuf_t *mbuf = NULL;
    bool ua_rebuild = false, ua_failed = false;

    if(!reg || !contact || !sip_msg) {
        return EMPBX_STATUS_FALSE;
    }

    mtx_lock(reg->mutex);
    reg->fl_entity_updating = true;

    if(str_casecmp(reg->contact_str, contact)) {
        pl_t cpl = {0};

        reg->contact_str = mem_deref(reg->contact_str);
        if(str_dup(&reg->contact_str, contact) != 0) {
            log_mem_fail();
            empbx_goto_status(EMPBX_STATUS_FALSE, out);
        }

        cpl.p = reg->contact_str;
        cpl.l = strlen(reg->contact_str);
        if(uri_decode(&reg->contact_uri, &cpl) != 0) {
            log_error("Unable to decode contact uri");
            empbx_goto_status(EMPBX_STATUS_FALSE, out);
        }

        reg->contact = mem_deref(reg->contact);
        re_sdprintf(&reg->contact, "sip:%r@%r:%d", &reg->contact_uri.user, &reg->contact_uri.host, reg->contact_uri.port);
        if(!reg->contact) {
            mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
        }

        reg->display_name = mem_deref(reg->display_name);
        if(pl_strdup(&reg->display_name, &sip_msg->from.dname) != 0) {
            mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
        }

        if(reg->contact_uri.params.l) {
            pl_t num = {0};
            if(re_regex(reg->contact_uri.params.p, reg->contact_uri.params.l, "expires=[0-9]+", &num) == 0 && num.l) {
                reg->lifetime = pl_u32(&num);
            }
        }

        ua_rebuild = true;
    }

    if(ua_rebuild) {
        if(!(mbuf = mbuf_alloc(1024))) {
            mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
        }
        if(reg->display_name) {
            mbuf_write_str(mbuf, "\"");
            mbuf_write_str(mbuf, reg->display_name);
            mbuf_write_str(mbuf, "\" ");
        }
        mbuf_write_u8(mbuf, '<');
        mbuf_write_str(mbuf, "sip:");
        mbuf_write_str(mbuf, reg->user_id);
        mbuf_write_u8(mbuf, '@');
        mbuf_write_str(mbuf, reg->realm);
        mbuf_write_u8(mbuf, '>');
        if(!zstr(reg->user->sip_password)) {
            mbuf_write_str(mbuf, ";auth_pass=");
            mbuf_write_str(mbuf, reg->user->sip_password);
        }
        mbuf_write_str(mbuf, ";regint=0");

        /* update ua */
        mtx_lock(sipd_runtime.baresip_mutex);
        empbx_ua_destroy(&reg->ua);
        reg->ua_conf = mem_deref(reg->ua_conf);

        mbuf->pos = 0;
        mbuf_strdup(mbuf, &reg->ua_conf, mbuf->end);
        if(reg->ua_conf) {
            if(ua_alloc(&reg->ua, reg->ua_conf) == LIBRE_SUCCESS) {
                 empbx_baresip_ua_set_xdata(reg->ua, empbx_xuser_data_alloc(reg, EMPBX_XUD_USER, false), true);
                 ua_set_catchall(reg->ua, true);
            } else {
                log_error("ua_alloc() failed");
                ua_failed = true;
            }
        } else {
            log_mem_fail();
            ua_failed = true;
        }
        mtx_unlock(sipd_runtime.baresip_mutex);
    }
    if(ua_failed) {
        empbx_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    reg->lifetime = (reg->lifetime ? reg->lifetime + 3 : REG_DEFAULT_LIFETIME_SEC);
    reg->expires = reg->lifetime ? (empbx_time_epoch_now() + reg->lifetime) : 0;

    log_debug("Registration updated (%s) / displayName=[%s], lifetime=[%d], contact=[%s] contact-uri=[%s], ua=%p", reg->user_id, reg->display_name, reg->lifetime, reg->contact, reg->contact_str, reg->ua);

out:
    reg->fl_entity_updating = false;
    mtx_unlock(reg->mutex);
    mem_deref(mbuf);
    return status;
}

empbx_status_t empbx_registration_user_new(char *user_id, char *realm, char *contact, empbx_user_entry_t *user, const sip_msg_t *sip_msg) {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;
    empbx_registration_user_t *reg = NULL;
    mbuf_t *mbuf = NULL;
    pl_t cpl = {0};
    bool ua_failed = false;

    if(!user_id || !contact || !user || !sip_msg) {
        return EMPBX_STATUS_FALSE;
    }

    reg = mem_zalloc(sizeof(empbx_registration_user_t), destructor__empbx_registration_user_t);
    if(!reg) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(mutex_alloc(&reg->mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    reg->refs = 0;
    reg->user = user;

    if(str_dup(&reg->user_id, user_id) != 0) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(str_dup(&reg->realm, realm) != 0) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(str_dup(&reg->contact_str, contact) != 0) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    // display name
    if(sip_msg->from.dname.l) {
        if(pl_strdup(&reg->display_name, &sip_msg->from.dname) != 0) {
            mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
        }
    }
    // uri
    cpl.p = reg->contact_str;
    cpl.l = strlen(reg->contact_str);
    if(uri_decode(&reg->contact_uri, &cpl) != 0) {
        log_error("Unable to decode contact uri");
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    // plain contact uri
    re_sdprintf(&reg->contact, "sip:%r@%r:%d",&reg->contact_uri.user, &reg->contact_uri.host, reg->contact_uri.port);
    if(!reg->contact) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    // ua_conf
    if(!(mbuf = mbuf_alloc(1024))) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(reg->display_name) {
        mbuf_write_str(mbuf, "\"");
        mbuf_write_str(mbuf, reg->display_name);
        mbuf_write_str(mbuf, "\" ");
    }
    mbuf_write_u8(mbuf, '<');
    mbuf_write_str(mbuf, "sip:");
    mbuf_write_str(mbuf, reg->user_id);
    mbuf_write_u8(mbuf, '@');
    mbuf_write_str(mbuf, reg->realm);
    mbuf_write_u8(mbuf, '>');
    if(!zstr(user->sip_password)) {
        mbuf_write_str(mbuf, ";auth_pass=");
        mbuf_write_str(mbuf, user->sip_password);
    }
    mbuf_write_str(mbuf, ";regint=0");
    mbuf->pos = 0;
    mbuf_strdup(mbuf, &reg->ua_conf, mbuf->end);
    if(!reg->ua_conf) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    // update ua
    mtx_lock(sipd_runtime.baresip_mutex);
    if(ua_alloc(&reg->ua, reg->ua_conf) == LIBRE_SUCCESS) {
        ua_set_catchall(reg->ua, true);
        empbx_baresip_ua_set_xdata(reg->ua, empbx_xuser_data_alloc(reg, EMPBX_XUD_USER, false), true);
    } else {
        log_error("ua_alloc() failed");
        ua_failed = true;
    }
    mtx_unlock(sipd_runtime.baresip_mutex);

    if(ua_failed) {
        empbx_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    // lifetime
    if(reg->contact_uri.params.l) {
        pl_t num = {0};
        if(re_regex(reg->contact_uri.params.p, reg->contact_uri.params.l, "expires=[0-9]+", &num) == 0 && num.l) {
            reg->lifetime = pl_u32(&num);
        }
    }

    reg->lifetime = (reg->lifetime ? reg->lifetime + 3 : REG_DEFAULT_LIFETIME_SEC);
    reg->expires = reg->lifetime ? (empbx_time_epoch_now() + reg->lifetime) : 0;

    mtx_lock(sipd_runtime.regmap_users_mutex);
    status = empbx_hash_insert_ex(sipd_runtime.regmap_users, reg->user_id, reg, true);
    mtx_unlock(sipd_runtime.regmap_users_mutex);

out:
    if(status == EMPBX_STATUS_SUCCESS) {
        log_debug("User registered (%s) / displayName=[%s], lifetime=[%d], contact=[%s] contact-uri=[%s], ua=%p", reg->user_id, reg->display_name, reg->lifetime, reg->contact, reg->contact_str, reg->ua);
    } else {
        if(reg && reg->ua) { empbx_ua_destroy(&reg->ua); }
        mem_deref(reg);
    }
    mem_deref(mbuf);
    return status;
}
