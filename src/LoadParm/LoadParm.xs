/*
 Copyright (C) 2013 Zentyal S.L.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License, version 2, as
 published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "ppport.h"

#include <Samba-LoadParm.h>
#include <samba/dynconfig.h>

void do_free(LP_CTX *ctx)
{
    if (ctx->mem_ctx != NULL)
        talloc_free(ctx->mem_ctx);
    if (ctx != NULL)
        free(ctx);
}

MODULE = Samba::LoadParm        PACKAGE = Samba::LoadParm
PROTOTYPES: ENABLE

LP_CTX *
_init()
CODE:
    TALLOC_CTX *mem_ctx;
    LP_CTX *ctx;

    ctx = malloc(sizeof (LP_CTX));
    if (ctx == NULL) {
        croak("No memory");
    }

    ctx->mem_ctx = talloc_named(NULL, 0, "Samba::LoadParm");
    if (ctx->mem_ctx == NULL) {
        do_free(ctx);
        croak("No memory");
    }

    ctx->lp_ctx = loadparm_init(ctx->mem_ctx);
    if (ctx->lp_ctx == NULL) {
        do_free(ctx);
        croak("No memory");
    }
    RETVAL = ctx;
OUTPUT:
    RETVAL

const char *
_default_path(ctx)
    LP_CTX *ctx
CODE:
    RETVAL = lp_default_path();
OUTPUT:
    RETVAL

const char *
_setup_dir(ctx)
    LP_CTX *ctx
CODE:
    RETVAL = dyn_SETUPDIR;
OUTPUT:
    RETVAL

const char *
_modules_dir(ctx)
    LP_CTX *ctx
CODE:
    RETVAL = dyn_MODULESDIR;
OUTPUT:
    RETVAL

const char *
_bin_dir(ctx)
    LP_CTX *ctx
CODE:
    RETVAL = dyn_BINDIR;
OUTPUT:
    RETVAL

const char *
_sbin_dir(ctx)
    LP_CTX *ctx
CODE:
    RETVAL = dyn_SBINDIR;
OUTPUT:
    RETVAL

const char *
_private_path(ctx, name)
    LP_CTX *ctx
    const char *name
CODE:
    char *path;
    path = lpcfg_private_path(ctx->mem_ctx, ctx->lp_ctx, name);
    RETVAL = path;
    talloc_free(path);
OUTPUT:
    RETVAL

const char *
_server_role(ctx)
    LP_CTX *ctx
CODE:
    uint32_t role;
    role = lpcfg_server_role(ctx->lp_ctx);
    switch (role) {
    case ROLE_STANDALONE:
        RETVAL = "ROLE_STANDALONE";
        break;
    case ROLE_DOMAIN_MEMBER:
        RETVAL = "ROLE_DOMAINMEMBER";
        break;
    case ROLE_DOMAIN_BDC:
        RETVAL = "ROLE_DOMAIN_BDC";
        break;
    case ROLE_DOMAIN_PDC:
        RETVAL = "ROLE_DOMAIN_PDC";
        break;
    case ROLE_ACTIVE_DIRECTORY_DC:
        RETVAL = "ROLE_ACTIVE_DIRECTORY_DC";
        break;
    case ROLE_AUTO:
        RETVAL = "ROLE_AUTO";
        break;
    default:
        croak("Unknown role");
    }
OUTPUT:
    RETVAL

int
_load(ctx, filename)
    LP_CTX *ctx
    const char *filename
CODE:
    bool ret;
    ret = lpcfg_load(ctx->lp_ctx, filename);
    if (!ret) {
        croak("Unable to load file %s", filename);
    }
    RETVAL = ret;
OUTPUT:
    RETVAL

int
_load_default(ctx)
    LP_CTX *ctx
CODE:
    bool ret;
    ret = lpcfg_load_default(ctx->lp_ctx);
    if (!ret) {
        croak("Unable to load dafault file");
    }
    RETVAL = ret;
OUTPUT:
    RETVAL

int
_is_myname(ctx, name)
    LP_CTX *ctx
    const char *name
CODE:
    RETVAL = lpcfg_is_myname(ctx->lp_ctx, name);
OUTPUT:
    RETVAL

int
_is_mydomain(ctx, name)
    LP_CTX *ctx
    const char *name
CODE:
    RETVAL = lpcfg_is_mydomain(ctx->lp_ctx, name);
OUTPUT:
    RETVAL

void
_destroy(ctx)
    LP_CTX *ctx
CODE:
    do_free(ctx);
