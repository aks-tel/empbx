/**
 **
 ** (C)2026 akstel.org
 **/
#include <empbx.h>
#include "empbx-service-sip-pvt.h"

static void session_handler_dtmf(call_t *call, char key, void *arg) {
    empbx_session_t *sess = (empbx_session_t *)arg;
    call_t *call2 = (sess->lega == call ? sess->legb : sess->lega);

    if((key >= '0' && key <= '9') || (key >= 'A' && key <= 'F') || key == '*' || key == '#') {
        char digits[2] = {key, 0x0};
        if(!empbx_queue_is_full(sess->dtmfq)) {
            empbx_queue_push(sess->dtmfq, empbx_strndup(digits, 2));
        }
    }
}

static void session_handler_call_events(call_t *call, enum call_event ev, const char *str, void *arg) {
    empbx_session_t *sess = (empbx_session_t *)arg;
    call_t *call2 = (sess->lega == call ? sess->legb : sess->lega);

    switch (ev) {
        case CALL_EVENT_ESTABLISHED:
                call_answer(call2, 200, call_has_video(call) ? VIDMODE_ON : VIDMODE_OFF);
                break;

        case CALL_EVENT_CLOSED:
                call_hangup(call2, call_scode(call), "");
                empbx_session_delete(sess->id);
                break;

        default:
                break;
    }
}

static empbx_status_t perform_handler(ua_t *ua, call_t *call, const char *args) {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;
    empbx_xuser_data_t *xuserd = NULL;
    empbx_session_t *session = NULL;
    char *args_local = NULL;

    if(zstr(args)) {
        call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
        goto out;
    }

    xuserd = (empbx_xuser_data_t *)empbx_baresip_ua_get_xdata(ua);
    if(!xuserd) {
        log_error("Illegal UA state");
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    if(strstr(args, "user/")) {
        char *ptr = (char *)(args + 5);
        empbx_registration_user_t *to_user = NULL;

        if(zstr(ptr)) {
            log_error("Malformed destination (null)");
            call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
            goto out;
        }

        to_user = empbx_registation_user_lookup(ptr);
        if(!to_user) {
            log_warn("User not registered (%s)", ptr);
            call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
            goto out;
        }

        if(xuserd->type == EMPBX_XUD_GATEWAY) {
            if(empbx_session_inbound_new(&session, call, to_user) != EMPBX_STATUS_SUCCESS) {
                log_error("Unable to create inbound session (%s)", to_user->contact);
                empbx_goto_status(EMPBX_STATUS_FALSE, out);
            }
        } else if(xuserd->type == EMPBX_XUD_USER) {
            if(empbx_session_intercom_new(&session, call, to_user) != EMPBX_STATUS_SUCCESS) {
                log_error("Unable to create intercom session (%s)", to_user->contact);
                empbx_goto_status(EMPBX_STATUS_FALSE, out);
            }
        }

        if(session) {
            char deva[64] = {0};
            char devb[64] = {0};

            re_snprintf(deva, sizeof(deva), "a-%s", session->id);
            re_snprintf(devb, sizeof(devb), "b-%s", session->id);

            audio_set_devicename(call_audio(session->lega), deva, devb);
            audio_set_devicename(call_audio(session->legb), devb, deva);
            video_set_devicename(call_video(session->lega), deva, devb);
            video_set_devicename(call_video(session->legb), devb, deva);

            empbx_baresip_audio_set_xdata(call_audio(session->lega), session, false);
            empbx_baresip_audio_set_xdata(call_audio(session->legb), session, false);
            empbx_baresip_video_set_xdata(call_video(session->lega), session, false);
            empbx_baresip_video_set_xdata(call_video(session->legb), session, false);

            call_set_handlers(session->lega, session_handler_call_events, session_handler_dtmf, session);
            call_set_handlers(session->legb, session_handler_call_events, session_handler_dtmf, session);

            session->fl_setup_done = true;
            empbx_session_release(session);
        }

        empbx_registration_user_release(to_user);
        goto out;
    }

    if(strstr(args, "gateway/")) {
        char *ptr = (char *)(args + 8);
        char *ptr2 = NULL;
        empbx_registration_gateway_t *to_gw = NULL;

        if(xuserd->type != EMPBX_XUD_USER) {
            log_error("Call rejected (%s) => (%s) [unallowed destination]", call_peeruri(call), call_localuri(call));
            call_hangup(call, 603, HC_CALL_REJECTED);
            goto out;
        }

        if(zstr(ptr)) {
            log_error("Malformed destination (null)");
            call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
            goto out;
        }

        if(str_dup(&args_local, ptr)) {
            mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
        }

        ptr = args_local;
        for(int i=0; i < strlen(ptr); i++) {
            if(ptr[i] == '/') { ptr[i] = 0x0; ptr2 = ptr + i + 1; break; }
        }

        to_gw = empbx_registation_gateway_lookup_by_name(ptr);
        if(!to_gw) {
            log_warn("Gateway not found (%s)", ptr);
            call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);
            goto out;
        }

        if(empbx_session_outbound_new(&session, call, to_gw, (const char *)ptr2) != EMPBX_STATUS_SUCCESS) {
            log_error("Unable to create outbound session (via: %s) (%s)", to_gw->gw_name, ptr2);
            empbx_goto_status(EMPBX_STATUS_FALSE, out);
        } else {
            char deva[64] = {0};
            char devb[64] = {0};

            re_snprintf(deva, sizeof(deva), "a-%s", session->id);
            re_snprintf(devb, sizeof(devb), "b-%s", session->id);

            audio_set_devicename(call_audio(session->lega), deva, devb);
            audio_set_devicename(call_audio(session->legb), devb, deva);
            video_set_devicename(call_video(session->lega), deva, devb);
            video_set_devicename(call_video(session->legb), devb, deva);

            empbx_baresip_audio_set_xdata(call_audio(session->lega), session, false);
            empbx_baresip_audio_set_xdata(call_audio(session->legb), session, false);
            empbx_baresip_video_set_xdata(call_video(session->lega), session, false);
            empbx_baresip_video_set_xdata(call_video(session->legb), session, false);

            call_set_handlers(session->lega, session_handler_call_events, session_handler_dtmf, session);
            call_set_handlers(session->legb, session_handler_call_events, session_handler_dtmf, session);

            session->fl_setup_done = true;
            empbx_session_release(session);
        }

        empbx_registration_gateway_release(to_gw);
        goto out;
    }

    log_error("Unsupported destination (%s)", args);
    call_hangup(call, 404, HC_NO_ROUTE_DESTINATION);

out:
    mem_deref(args_local);
    return status;
}



// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
// init
// ------------------------------------------------------------------------------------------------------------------------------------------------------------------
empbx_status_t empbx_application_register__bridge() {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;

    status = empbx_dialplan_application_register("bridge", NULL, perform_handler);

    return status;
}

