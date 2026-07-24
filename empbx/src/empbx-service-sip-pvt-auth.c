/**
 **
 ** (C)2026 akstel.org
 **/
#include <empbx.h>
#include "empbx-service-sip-pvt.h"

extern empbx_global_t *global;
extern sipd_runtime_t sipd_runtime;

/* see: re-4.5.0/src/sip/msg.c  */
static void destructor__re_sip_hdr_t(void *arg) {
    sip_hdr_t *hdr = arg;
    list_unlink(&hdr->le);
    hash_unlink(&hdr->he);
}


static empbx_status_t gen_nonce(char **noncep, const char *realm, time_t ts, const sip_msg_t *msg) {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;
    uint8_t key[MD5_SIZE];
    char *lnonce = NULL;
    mbuf_t *mbuf = NULL;

    if(!noncep || !msg || !realm)  {
        return EMPBX_STATUS_FALSE;
    }

    if(!(mbuf = mbuf_alloc(40))) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    if(!ts) {
        ts = empbx_time_epoch_now();
    }

    if(mbuf_printf(mbuf,"%u%j%s", (uint32_t)ts, &msg->src, realm)) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    md5(mbuf->buf, mbuf->end, key);
    mbuf_rewind(mbuf);

    if(mbuf_printf(mbuf,"%w%08x", key, sizeof(key), (uint32_t)ts)) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    mbuf_set_pos(mbuf, 0);
    if(mbuf_strdup(mbuf, &lnonce, mbuf_get_left(mbuf))) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    *noncep = lnonce;

out:
    if(status != EMPBX_STATUS_SUCCESS) {
        mem_deref(lnonce);
    }
    mem_deref(mbuf);
    return status;
}

static bool check_nonce(const pl_t *nonce, const char *realm, const sip_msg_t *msg) {
    pl_t npl = *nonce;
    char *cnonce = NULL;
    time_t nts = 0, cts = 0;
    bool result = false;

    if(!nonce || !msg || !realm)  {
        return false;
    }
    if(npl.l < AUTH_NONCE_LMIN_LEN) {
        return false;
    }

    npl.p = npl.p + (npl.l - 8);
    npl.l = 8;
    nts = (time_t)pl_x64(&npl);

    cts = empbx_time_epoch_now();
    if((cts - nts) > AUTH_NONCE_LIFETIME_SEC) {
        return false;
    }

    if(gen_nonce(&cnonce, realm, nts, msg) != EMPBX_STATUS_SUCCESS) {
        log_error("gen_nonce() failed");
        result = false; goto out;
    }

    if(!pl_strcasecmp(nonce, cnonce)) {
        result = true;
    }

out:
    mem_deref(cnonce);
    return result;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// public
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
empbx_status_t empbx_authentication_challenge_start(const char *realm, const sip_msg_t *msg) {
    empbx_status_t status = EMPBX_STATUS_SUCCESS;
    sip_hdr_t *ahdr = NULL;
    char *hval = NULL, *nonce = NULL;

    if(zstr(realm) || !msg) {
        return EMPBX_STATUS_FALSE;
    }

    if(gen_nonce(&nonce, realm, 0, msg) != EMPBX_STATUS_SUCCESS) {
        log_error("gen_nonce() failed");
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    if(re_sdprintf(&hval, "Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5", realm, nonce)) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    ahdr = mem_zalloc(sizeof(sip_hdr_t), destructor__re_sip_hdr_t);
    if(!ahdr) {
        mem_fail_goto_status(EMPBX_STATUS_MEM_FAIL, out);
    }

    ahdr->id = SIP_HDR_AUTHORIZATION;
    ahdr->name.p = SIP_AUTH_HDR_NAME;
    ahdr->name.l = strlen(SIP_AUTH_HDR_NAME);
    ahdr->val.p = hval;
    ahdr->val.l = strlen(hval);

    list_append((struct list *)&msg->hdrl, &ahdr->le, mem_ref(ahdr));
    empbx_reply(uag_sip(), msg, 401, "Unauthorized");

out:
    mem_deref(ahdr);
    mem_deref(hval);
    mem_deref(nonce);
    return status;
}

empbx_status_t empbx_authentication_challenge_check(empbx_user_entry_t *user, const sip_hdr_t *ahdr, const sip_msg_t *msg) {
    empbx_status_t status = EMPBX_STATUS_FALSE;
    httpauth_digest_resp_t resp = {0};
    uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE];
    uint8_t digest[MD5_SIZE], response[MD5_SIZE];
    char *from_realm = NULL, *ptr = NULL;
    int i;

    if(!user || !ahdr || !msg) {
        return EMPBX_STATUS_FALSE;
    }

    if(httpauth_digest_response_decode(&resp, &ahdr->val)) {
        return EMPBX_STATUS_FALSE;
    }

    if(pl_strdup(&from_realm, &msg->from.uri.host)) {
        mem_fail_goto_status(EMPBX_STATUS_FALSE, out);
    }

    if(!check_nonce(&resp.nonce, from_realm, msg)) {
        empbx_goto_status(EMPBX_STATUS_FALSE, out);
    }

    if(!zstr(user->sip_password)) {
        if(md5_printf(ha1, "%s:%s:%s", user->id, from_realm, user->sip_password)) {
            mem_fail_goto_status(EMPBX_STATUS_FALSE, out);
        }
        if(md5_printf(ha2, "%r:%r", &msg->met, &resp.uri))  {
            mem_fail_goto_status(EMPBX_STATUS_FALSE, out);
        }
        if(md5_printf(digest, "%w:%r:%w", ha1, (size_t)MD5_SIZE, &resp.nonce, ha2, (size_t)MD5_SIZE)) {
            mem_fail_goto_status(EMPBX_STATUS_FALSE, out);
        }

        for(i=0, ptr = (char *)resp.response.p; i < sizeof(response); i++) {
            response[i]  = ch_hex(*ptr++) << 4;
            response[i] += ch_hex(*ptr++);
        }

        if(memcmp(digest, response, MD5_SIZE) == 0) {
            status = EMPBX_STATUS_SUCCESS;
        }
    }

out:
    mem_deref(from_realm);
    return status;
}
