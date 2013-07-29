#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "samba-loadparm.h"
#include "samba-credentials.h"
#include "samba-descriptor.h"
#include "samba-smb.h"

#include <stdbool.h>
#include <util/time.h>
#include <util/data_blob.h>
#include <core/ntstatus.h>
#include <smb_cliraw.h>
#include <gen_ndr/security.h>


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
    ctx->tree = tree;

    RETVAL = ctx;
OUTPUT:
    RETVAL

MODULE = Samba::Smb     PACKAGE = SmbPtr    PREFIX = smbPtr_

int
smbPtr_open(self, file)
    Smb *self
    char *file
CODE:
    NTSTATUS status;
    union smb_open io;

    io.generic.level = RAW_OPEN_NTCREATEX;
    io.ntcreatex.in.root_fid.fnum = 0;
    io.ntcreatex.in.flags = 0;
    io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
    io.ntcreatex.in.create_options = 0;
    io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
    io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
                                   NTCREATEX_SHARE_ACCESS_WRITE;
    io.ntcreatex.in.alloc_size = 0;
    io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
    io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
    io.ntcreatex.in.security_flags = 0;
    io.ntcreatex.in.fname = file;
    status = smb_raw_open(self->tree, self->mem_ctx, &io);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to open: %s", nt_errstr(status));
    }
    RETVAL = io.ntcreatex.out.file.fnum;
OUTPUT:
    RETVAL

int
smbPtr_close(self, fd)
    Smb *self
    int fd
CODE:
    NTSTATUS status;
    union smb_close io;

    io.close.level = RAW_CLOSE_CLOSE;
    io.close.in.file.fnum = fd;
    io.close.in.write_time = 0;
    status = smb_raw_close(self->tree, &io);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to close: %s", nt_errstr(status));
    }
OUTPUT:
    RETVAL

int
smbPtr_set_sd(self, fd, flags, sd)
    Smb *self
    int fd
    int flags
    Descriptor *sd
CODE:
    NTSTATUS status;
    union smb_setfileinfo fi;

    fi.generic.level = RAW_FILEINFO_SEC_DESC;
    fi.set_secdesc.in.file.fnum = fd;
    fi.set_secdesc.in.secinfo_flags = flags;
    fi.set_secdesc.in.sd = sd->sd;

    status = smb_raw_setfileinfo(self->tree, &fi);
    if (!NT_STATUS_IS_OK(status)) {
        croak(nt_errstr(status));
    }

    RETVAL = 0;
OUTPUT:
    RETVAL
