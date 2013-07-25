#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "samba-loadparm.h"

MODULE = Samba::LoadParm        PACKAGE = Samba::LoadParm
PROTOTYPES: ENABLE

LoadParm *
new(class)
    SV *class
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    LoadParm *ctx = NULL;
    const char *classname;
    bool ret;

    if (sv_isobject(class)) {
        classname = sv_reftype(SvRV(class), 1);
    } else {
        if (!SvPOK(class))
            croak("%s: Need an object or class name as first "
                  "argument to the constructor", __func__);
        classname = SvPV_nolen(class);
    }

    mem_ctx = talloc_named(NULL, 0, "Samba::LoadParm");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating memory context", __func__);
        XSRETURN_UNDEF;
    }

    ctx = talloc_zero(mem_ctx, LoadParm);
    if (ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating private data", __func__);
        XSRETURN_UNDEF;
    }
    ctx->mem_ctx = mem_ctx;

    ctx->lp_ctx = loadparm_init(mem_ctx);
    if (ctx->lp_ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating loadparm context", __func__);
        XSRETURN_UNDEF;
    }

    ret = lpcfg_load_default(ctx->lp_ctx);
    if (!ret) {
        talloc_free(mem_ctx);
        croak("%s: Could not load default smb.conf", __func__);
        XSRETURN_UNDEF;
    }

    RETVAL = ctx;
OUTPUT:
    RETVAL


MODULE = Samba::LoadParm    PACKAGE = LoadParmPtr   PREFIX = lpPtr_

void
lpPtr_DESTROY(ctx)
    LoadParm *ctx
CODE:
    talloc_free(ctx->mem_ctx);
