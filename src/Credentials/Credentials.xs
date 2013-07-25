#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "samba-loadparm.h"
#include "samba-credentials.h"

MODULE = Samba::Credentials		PACKAGE = Samba::Credentials
PROTOTYPES: ENABLE

Credentials *
new(class, lp)
    SV *class
    LoadParm *lp
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    Credentials *ctx = NULL;
    const char *classname;

    if (sv_isobject(class)) {
        classname = sv_reftype(SvRV(class), 1);
    } else {
        if (!SvPOK(class))
            croak("%s: Need an object or class name as "
                  "first argument to the constructor", __func__);
        classname = SvPV_nolen(class);
    }

    mem_ctx = talloc_named(NULL, 0, "Samba::Credentials");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating talloc context", __func__);
        XSRETURN_UNDEF;
    }

    ctx = talloc_zero(mem_ctx, Credentials);
    if (ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating context", __func__);
        XSRETURN_UNDEF;
    }
    ctx->mem_ctx = mem_ctx;

    ctx->ccreds = cli_credentials_init(mem_ctx);
    if (ctx->ccreds == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating credentials", __func__);
        XSRETURN_UNDEF;
    }

    cli_credentials_guess(ctx->ccreds, lp->lp_ctx);

    RETVAL = ctx;
OUTPUT:
    RETVAL

MODULE = Samba::Credentials PACKAGE = CredentialsPtr PREFIX = credsPtr_

int
credsPtr_set_username(ctx, username)
    Credentials *ctx
    char *username
CODE:
    RETVAL = cli_credentials_set_username(ctx->ccreds, username, CRED_SPECIFIED);
OUTPUT:
    RETVAL

const char *
credsPtr_get_username(ctx)
    Credentials *ctx
CODE:
    RETVAL = cli_credentials_get_username(ctx->ccreds);
OUTPUT:
    RETVAL

int
credsPtr_set_password(ctx, password)
    Credentials *ctx
    char *password
CODE:
    RETVAL = cli_credentials_set_password(ctx->ccreds, password, CRED_SPECIFIED);
OUTPUT:
    RETVAL

void
credsPtr_DESTROY(ctx)
    Credentials *ctx
CODE:
    talloc_free(ctx->mem_ctx);

