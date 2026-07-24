/**
 **
 ** (C)2026 akstel.org
 **/
#include <empbx.h>
#include "empbx-service-sip-pvt.h"

extern empbx_global_t *global;
sipd_runtime_t sipd_runtime;

// -----------------------------------------------------------------------------------------------------------------------------------
// threds
// -----------------------------------------------------------------------------------------------------------------------------------
static int sipd_registrar_maintenance_thread(void *udata) {
    empbx_list_t *del_list = NULL;
    time_t reg_timer = 0;

    if(empbx_list_create(&del_list) != EMPBX_STATUS_SUCCESS) {
        log_mem_fail();
    }

    while(true) {
        if(global->fl_shutdown) {
            break;
        }
        if(!global->fl_ready) {
            sys_msleep(100);
            continue;
        }
        if(!reg_timer) {
            reg_timer = empbx_time_epoch_now() + REGS_CHECK_INTERVAL_SEC;
        }

        /* check expired regs */
        if(reg_timer && reg_timer <= empbx_time_epoch_now()) {
            if(!empbx_hash_is_empty(sipd_runtime.regmap_users)) {
                empbx_hash_index_t *hidx = NULL;
                empbx_registration_user_t *val=NULL;

                mtx_lock(sipd_runtime.regmap_users_mutex);
                for(hidx = empbx_hash_first_iter(sipd_runtime.regmap_users, hidx); hidx; hidx = empbx_hash_next(&hidx)) {
                    empbx_hash_this(hidx, NULL, NULL, (void *)&val);
                    if(val && val->expires && val->expires <= empbx_time_epoch_now()) {
                        empbx_list_add_tail(del_list, val, NULL);
                    }
                }

                if(!empbx_list_is_empty(del_list)) {
                    empbx_registration_user_t *entry = NULL;

                    while((entry = empbx_list_pop(del_list))) {
                        if(entry->ua) {
                            mtx_lock(sipd_runtime.baresip_mutex);
                            empbx_ua_destroy(&entry->ua);
                            mtx_unlock(sipd_runtime.baresip_mutex);
                        }
                        empbx_hash_delete(sipd_runtime.regmap_users, entry->user_id);
                    }
                }
                mtx_unlock(sipd_runtime.regmap_users_mutex);
            }
            reg_timer = 0;
        }

        sys_msleep(1000);
    }

    mem_deref(del_list);
    empbx_thread_finished();
    return 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------
// handlers
// -----------------------------------------------------------------------------------------------------------------------------------
static bool ua_sip_request_handler(const sip_msg_t *msg, void *arg) {
    ua_t *from_ua = (ua_t *)arg;
    char *to_user_id = NULL, *to_realm = NULL;
    char *from_user_id = NULL, *from_realm = NULL, *from_contact = NULL;
    bool hresult = false;

    if(!from_ua) {
        from_ua = uag_find_msg(msg);
    }

    if(!pl_strcmp(&msg->met, "INVITE")) {
        empbx_xuser_data_t *xuserd = NULL;
        empbx_registration_gateway_t *gwreg = NULL;
        empbx_registration_user_t *sureg = NULL;
        bool fl_release_entity = false;

        hresult = true;

        pl_strdup(&from_user_id, &msg->from.uri.user);
        pl_strdup(&from_realm, &msg->from.uri.host);
        pl_strdup(&to_user_id, &msg->to.uri.user);
        pl_strdup(&to_realm, &msg->to.uri.host);

        if(from_ua) {
            xuserd = (empbx_xuser_data_t *)empbx_baresip_ua_get_xdata(from_ua);
            if(!xuserd) {
                log_error("Call rejected (%s@%s) => (%s@%s) [unknown originator]", from_user_id, from_realm, to_user_id, to_realm);
                sip_treply(NULL, uag_sip(), msg, 404, "Not Found");
                goto out;
            }

            if(xuserd->type == EMPBX_XUD_GATEWAY) {
                gwreg = (empbx_registration_gateway_t *)xuserd->data;
            } else if(xuserd->type == EMPBX_XUD_USER) {
                sureg = (empbx_registration_user_t *)xuserd->data;
            } else {
                log_error("Call rejected (%s@%s) => (%s@%s) [unsupported type]", from_user_id, from_realm, to_user_id, to_realm);
                sip_treply(NULL, uag_sip(), msg, 404, "Not Found");
                goto out;
            }
        } else {
            sureg = empbx_registation_user_lookup(from_user_id);
            if(sureg) {
                from_ua = sureg->ua;
                fl_release_entity = true;
            } else {
                gwreg = empbx_registation_gateway_lookup(from_user_id);
                if(gwreg) {
                    from_ua = gwreg->ua;
                    fl_release_entity = true;
                }
            }
        }

        if(gwreg) {
            if(ua_req_check_origin(from_ua, msg)) {
                ua_accept(from_ua, msg);
            } else {
                log_error("Call rejected (%s@%s) => (%s@%s) [unallowed origin]", from_user_id, from_realm, to_user_id, to_realm);
                sip_treply(NULL, uag_sip(), msg, 403, "Forbidden");
            }

            if(fl_release_entity) {
                empbx_registration_gateway_release(gwreg);
            }
            goto out;
        }

        if(sureg) {
            if(!zstr(sureg->user->sip_password)) {
                const sip_hdr_t *auth_hdr = sip_msg_hdr(msg, SIP_HDR_AUTHORIZATION);
                if(!auth_hdr) {
                    if(empbx_authentication_challenge_start(from_realm, msg) != EMPBX_STATUS_SUCCESS) {
                        sip_treply(NULL, uag_sip(), msg, 500, "Server internal error");
                    }
                    if(fl_release_entity) {
                        empbx_registration_user_release(sureg);
                    }
                    goto out;
                }
                if(empbx_authentication_challenge_check(sureg->user, auth_hdr, msg) != EMPBX_STATUS_SUCCESS) {
                    if(fl_release_entity) {
                        empbx_registration_user_release(sureg);
                    }
                    sip_treply(NULL, uag_sip(), msg, 403, "Forbidden");
                    goto out;
                }
            }

            if(ua_req_check_origin(from_ua, msg)) {
                ua_accept(from_ua, msg);
            } else {
                log_error("Call rejected (%s@%s) => (%s@%s) [unallowed origin]", from_user_id, from_realm, to_user_id, to_realm);
                sip_treply(NULL, uag_sip(), msg, 403, "Forbidden");
            }

            if(fl_release_entity) {
                empbx_registration_user_release(sureg);
            }
            goto out;
        }

        log_error("Call rejected (%s@%s) => (%s@%s) [unknown originator]", from_user_id, from_realm, to_user_id, to_realm);
        sip_treply(NULL, uag_sip(), msg, 404, "Not Found");

        goto out;
    }

    if(!pl_strcmp(&msg->met, "REGISTER")) {
        const sip_hdr_t *contact_hdr = NULL;
        const sip_hdr_t *auth_hdr = NULL;
        empbx_user_entry_t *user = NULL;

        hresult = true;

        auth_hdr = sip_msg_hdr(msg, SIP_HDR_AUTHORIZATION);
        contact_hdr = sip_msg_hdr(msg, SIP_HDR_CONTACT);
        if(!contact_hdr) {
            sip_treply(NULL, uag_sip(), msg, 400, "Bad request");
            goto out;
        }

        pl_strdup(&from_user_id, &msg->from.uri.user);
        pl_strdup(&from_realm, &msg->from.uri.host);
        pl_strdup(&from_contact, &contact_hdr->val);

        user = empbx_config_user_lookup(from_user_id);
        if(user) {
            if(zstr(user->sip_password)) {
                empbx_registration_user_t *reg = empbx_registation_user_lookup(from_user_id);
                if(reg) {
                    if(empbx_registration_user_update(reg, from_contact, msg) != EMPBX_STATUS_SUCCESS) {
                        log_error("Unable to update user registration (%s)", from_user_id);
                        sip_treply(NULL, uag_sip(), msg, 500, "Server internal error");
                    } else {
                        empbx_reply(uag_sip(), msg, 200, "OK");
                    }
                    empbx_registration_user_release(reg);
                } else {
                    if(empbx_registration_user_new(from_user_id, from_realm, from_contact, user, msg) != EMPBX_STATUS_SUCCESS) {
                        log_error("Unable to register user (%s)", from_user_id);
                        sip_treply(NULL, uag_sip(), msg, 500, "Server internal error");
                    } else {
                        empbx_reply(uag_sip(), msg, 200, "OK");
                    }
                }
                goto out;
            }
        } else {
            if(auth_hdr) {
                log_error("Subscriber not found (%s@%s) [%s]", from_user_id, from_realm, from_contact);
                sip_treply(NULL, uag_sip(), msg, 403, "Forbidden");
                goto out;
            }
        }

        if(!auth_hdr) {
            if(empbx_authentication_challenge_start(from_realm, msg) != EMPBX_STATUS_SUCCESS) {
                sip_treply(NULL, uag_sip(), msg, 500, "Server internal error");
            }
            goto out;
        }

        if(empbx_authentication_challenge_check(user, auth_hdr, msg) == EMPBX_STATUS_SUCCESS) {
            empbx_registration_user_t *reg = empbx_registation_user_lookup(from_user_id);
            if(reg) {
                if(empbx_registration_user_update(reg, from_contact, msg) != EMPBX_STATUS_SUCCESS) {
                    log_error("Unable to update user registration (%s)", from_user_id);
                    sip_treply(NULL, uag_sip(), msg, 500, "Server internal error");
                } else {
                    empbx_reply(uag_sip(), msg, 200, "OK");
                }
                empbx_registration_user_release(reg);
            } else {
                if(empbx_registration_user_new(from_user_id, from_realm, from_contact, user, msg) != EMPBX_STATUS_SUCCESS) {
                    log_error("Unable to register user (%s)", from_user_id);
                    sip_treply(NULL, uag_sip(), msg, 500, "Server internal error");
                } else {
                    empbx_reply(uag_sip(), msg, 200, "OK");
                }
            }
            goto out;
        }

        log_warn("Auth challenge (REGISTER) failed. (%s@%s)", from_user_id, from_realm);
        sip_treply(NULL, uag_sip(), msg, 403, "Forbidden");
    }

out:
    mem_deref(from_contact);
    mem_deref(from_user_id);
    mem_deref(from_realm);
    mem_deref(to_user_id);
    mem_deref(to_realm);
    return hresult;
}

static void ua_bsevent_handler(enum bevent_ev ev, struct bevent *event, void *arg) {
    empbx_xuser_data_t *xuserd = NULL;
    call_t *call = NULL;
    ua_t *uua = NULL;

    if(global->fl_shutdown || !global->fl_ready) {
        return;
    }

    uua = bevent_get_ua(event);
    call = bevent_get_call(event);
    xuserd = (empbx_xuser_data_t *)empbx_baresip_ua_get_xdata(uua);

    switch(ev) {
        case BEVENT_CALL_INCOMING: {
            if(!xuserd) {
                log_error("Call rejected (%s) => (%s) [illegal UA state]", call_peeruri(call), call_localuri(call));
                call_hangup(call, 603, HC_CALL_REJECTED);
                break;
            }

            if(xuserd->type == EMPBX_XUD_GATEWAY) { /* call from gateway */
                empbx_registration_gateway_t *from_gw = (empbx_registration_gateway_t *)xuserd->data;
                empbx_dialplan_lookup_result_t lpresult = {0};
                empbx_dialplan_lookup_prams_t lparams = {0};
                empbx_dialplan_app_t *application = NULL;
                const char *dst_aor = call_localuri(call);
                char dst_number[64] = {0};

                if(empbx_extract_number_from_uri(dst_number, sizeof(dst_number), dst_aor) != EMPBX_STATUS_SUCCESS) {
                    log_error("Unable to extract dst-number (%s)", dst_aor);
                    call_hangup(call, 500, HC_NORMAL_FALURE);
                    break;
                }

                lparams.gateway =  from_gw->gw_name;
                lparams.dst_number = dst_number;

                if(empbx_dialplan_lookup(&lpresult, &lparams) == EMPBX_STATUS_SUCCESS) {
                    empbx_dialplan_app_t *application = NULL;

                    if(!zstr(lpresult.rule->app_name)) {
                        application = empbx_dialplan_application_lookup(lpresult.rule->app_name);
                    }

                    if(application) {
                        if(application->perform_h(uua, call, lpresult.dst_number) != EMPBX_STATUS_SUCCESS) {
                            call_hangup(call, 500, HC_NORMAL_FALURE);
                        }
                        empbx_dialplan_application_release(application);
                    } else {
                        log_error("Unknown application (%s)", lpresult.rule->app_name ? lpresult.rule->app_name : "null");
                        call_hangup(call, 500, HC_NORMAL_FALURE);
                    }

                    mem_deref(lpresult.dst_number);
                } else {
                    call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
                }
            } else if(xuserd->type == EMPBX_XUD_USER) { /* call from user */
                empbx_registration_user_t *from_user = (empbx_registration_user_t *)xuserd->data;
                empbx_dialplan_lookup_result_t lpresult = {0};
                empbx_dialplan_lookup_prams_t lparams = {0};
                char dst_number[64] = {0};
                const char *dst_aor = call_localuri(call);

                if(empbx_extract_number_from_uri(dst_number, sizeof(dst_number), dst_aor) != EMPBX_STATUS_SUCCESS) {
                    log_error("Unable to extract dst-number (%s)", dst_aor);
                    call_hangup(call, 500, HC_NORMAL_FALURE);
                    break;
                }

                lparams.dst_number = dst_number;

                if(empbx_dialplan_lookup(&lpresult, &lparams) == EMPBX_STATUS_SUCCESS) {
                    empbx_dialplan_app_t *application = NULL;

                    if(!zstr(lpresult.rule->app_name)) {
                        application = empbx_dialplan_application_lookup(lpresult.rule->app_name);
                    }

                    if(application) {
                        if(application->perform_h(uua, call, lpresult.dst_number) != EMPBX_STATUS_SUCCESS) {
                            call_hangup(call, 500, HC_NORMAL_FALURE);
                        }
                        empbx_dialplan_application_release(application);
                    } else {
                        log_error("Unknown application (%s)", lpresult.rule->app_name ? lpresult.rule->app_name : "null");
                        call_hangup(call, 500, HC_NORMAL_FALURE);
                    }

                    mem_deref(lpresult.dst_number);
                } else {
                    call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------------------------------------------------------------------------
empbx_status_t empbx_service_sip_start() {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;

    memset(&sipd_runtime, 0, sizeof(sipd_runtime_t));

    if(mutex_alloc(&sipd_runtime.baresip_mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(mutex_alloc(&sipd_runtime.regmap_users_mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(mutex_alloc(&sipd_runtime.regmap_gateways_mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(mutex_alloc(&sipd_runtime.regmap_sessions_mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(mutex_alloc(&sipd_runtime.apps_map_mutex) != LIBRE_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    if(empbx_hash_create(&sipd_runtime.apps_map) != EMPBX_STATUS_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(empbx_hash_create(&sipd_runtime.regmap_users) != EMPBX_STATUS_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(empbx_hash_create(&sipd_runtime.regmap_gateways) != EMPBX_STATUS_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }
    if(empbx_hash_create(&sipd_runtime.regmap_sessions) != EMPBX_STATUS_SUCCESS) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }


    /* bresip */
    conf_path_set(global->path_config);

    if(global->bsip_config && global->bsip_config->end) {
        if(conf_configure_buf(global->bsip_config->buf, global->bsip_config->end) != LIBRE_SUCCESS) {
            log_error("conf_configure_buf() failed");
            empbx_goto_status(EMPBX_STATUS_FALSE, out);
        }
    } else {
        log_warn("Using default sip configuration!");
    }

    if(baresip_init(conf_config()) != LIBRE_SUCCESS) {
        log_error("baresip_init() failed");
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    play_set_path(baresip_player(), global->path_sounds);

    if(ua_init(global->sip_server_ident, true, true, false) != LIBRE_SUCCESS) {
        log_error("ua_init() failed");
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    if(global->fl_debug_enabled) {
        log_enable_debug(true);
    }
    if(global->fl_sip_debug_enabled) {
        uag_enable_sip_trace(true);
    }

    sipd_runtime.fl_ua_init_ok = true;
    bevent_register(ua_bsevent_handler, NULL);
    empbx_baresip_uag_set_custom_sip_handler(ua_sip_request_handler);

    bsmod_load__g729();
    empbx_application_register__bridge();

    if(conf_modules()) {
        log_error("conf_modules() failed");
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    if(!empbx_hash_is_empty(global->gateways_map)) {
        empbx_hash_index_t *hidx = NULL;
        empbx_gateway_entry_t *entry = NULL;

        for(hidx = empbx_hash_first_iter(global->gateways_map, hidx); hidx; hidx = empbx_hash_next(&hidx)) {
            empbx_hash_this(hidx, NULL, NULL, (void *)&entry);
            if(entry) {
                if(empbx_registration_gateway_add(entry) != EMPBX_STATUS_SUCCESS) {
                    log_warn("Unable to add gateway (%s)", entry->name);
                }
            }
        }
    }


    if((status = empbx_thread_launch(sipd_registrar_maintenance_thread, NULL)) != EMPBX_STATUS_SUCCESS) {
        goto out;
    }

out:
    return status;
}

empbx_status_t empbx_service_sip_stop() {
    ua_stop_all(sipd_runtime.fl_ua_init_ok);
    ua_close();

    module_app_unload();

    conf_close();
    baresip_close();

    bsmod_unload__g729();
    mod_close();

    if(sipd_runtime.regmap_sessions_mutex) {
        mtx_lock(sipd_runtime.regmap_sessions_mutex);
        mem_deref(sipd_runtime.regmap_sessions);
        mtx_unlock(sipd_runtime.regmap_sessions_mutex);
    } else {
        mem_deref(sipd_runtime.regmap_sessions);
    }

    if(sipd_runtime.regmap_users_mutex) {
        mtx_lock(sipd_runtime.regmap_users_mutex);
        mem_deref(sipd_runtime.regmap_users);
        mtx_unlock(sipd_runtime.regmap_users_mutex);
    } else {
        mem_deref(sipd_runtime.regmap_users);
    }

    if(sipd_runtime.regmap_gateways_mutex) {
        mtx_lock(sipd_runtime.regmap_gateways_mutex);
        mem_deref(sipd_runtime.regmap_gateways);
        mtx_unlock(sipd_runtime.regmap_gateways_mutex);
    } else {
        mem_deref(sipd_runtime.regmap_gateways);
    }

    if(sipd_runtime.apps_map_mutex) {
        mtx_lock(sipd_runtime.apps_map_mutex);
        mem_deref(sipd_runtime.apps_map);
        mtx_unlock(sipd_runtime.apps_map_mutex);
    } else {
        mem_deref(sipd_runtime.apps_map);
    }

    mem_deref(sipd_runtime.apps_map_mutex);
    mem_deref(sipd_runtime.regmap_users_mutex);
    mem_deref(sipd_runtime.regmap_gateways_mutex);
    mem_deref(sipd_runtime.regmap_sessions_mutex);
    mem_deref(sipd_runtime.baresip_mutex);

    return EMPBX_STATUS_SUCCESS;
}


