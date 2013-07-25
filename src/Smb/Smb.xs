#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "samba-loadparm.h"
#include "samba-credentials.h"
#include "samba-smb.h"

#include <stdbool.h>
#include <util/time.h>
#include <util/data_blob.h>
#include <core/ntstatus.h>
#include <smb_cliraw.h>


MODULE = Samba::Smb     PACKAGE = Samba::Smb
PROTOTYPES: ENABLE

Smb *
new(class, lp, creds, hostname, service)
    SV *class
    LoadParm *lp
    Credentials *creds
    char *hostname
    char *service
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    Smb *ctx = NULL;
    bool ret;
    NTSTATUS status;
    const char *classname;

    if (sv_isobject(class)) {
        classname = sv_reftype(SvRV(class), 1);
    } else {
        if (!SvPOK(class))
            croak("%s: Need an object or class name as "
                  "first argument to the constructor", __func__);
        classname = SvPV_nolen(class);
    }

    mem_ctx = talloc_named(NULL, 0, "Samba::Smb");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating talloc context", __func__);
        XSRETURN_UNDEF;
    }

    ctx = talloc_zero(mem_ctx, Smb);
    if (ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating private_data", __func__);
        XSRETURN_UNDEF;
    }

    ctx->mem_ctx = mem_ctx;

    //cli_credentials_set_password(spdata->creds, "Zentyal1234", CRED_SPECIFIED);
    //cli_credentials_set_username(spdata->creds, "administrator", CRED_SPECIFIED);
    //cli_credentials_set_domain(spdata->creds, "KERNEVIL", CRED_SPECIFIED);
    //cli_credentials_set_kerberos_state(spdata->creds, CRED_AUTO_USE_KERBEROS);
    //cli_credentials_set_workstation(spdata->creds, "zentyal311", CRED_SPECIFIED);
    //cli_credentials_set_conf(spdata->creds, spdata->lp_ctx);
    //cli_credentials_set_realm(spdata->creds, "KERNEVIL.LAN", CRED_SPECIFIED);
    //cli_credentials_set_secure_channel_type(spdata->creds, SEC_CHAN_WKSTA);

    //cli_credentials_guess(spdata->creds, spdata->lp_ctx);

    ctx->ev_ctx = tevent_context_init(mem_ctx);
    if (ctx->ev_ctx == NULL) {
        talloc_free(mem_ctx);
        croak("No memory allocating ev_ctx");
        XSRETURN_UNDEF;
    }
    tevent_loop_allow_nesting(ctx->ev_ctx);

    gensec_init();

    struct smbcli_options options;
    struct smbcli_session_options session_options;

    lpcfg_smbcli_options(lp->lp_ctx, &options);
    lpcfg_smbcli_session_options(lp->lp_ctx, &session_options);

    struct smbcli_tree *tree;
    status = smbcli_tree_full_connection(
                mem_ctx,
                &tree,
                hostname,
                lpcfg_smb_ports(lp->lp_ctx),
                service,
                NULL,
                lpcfg_socket_options(lp->lp_ctx),
                creds->ccreds,
                lpcfg_resolve_context(lp->lp_ctx),
                ctx->ev_ctx,
                &options,
                &session_options,
                lpcfg_gensec_settings(mem_ctx, lp->lp_ctx));
    if (!NT_STATUS_IS_OK(status)) {
        talloc_free(mem_ctx);
        croak(nt_errstr(status));
        XSRETURN_UNDEF;
    }

    RETVAL = ctx;
OUTPUT:
    RETVAL
