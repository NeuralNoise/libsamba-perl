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
#include <xs_object_magic.h>

#include "ppport.h"

#include <Samba-LoadParm.h>
#include <samba/dynconfig.h>

MODULE = Samba::LoadParm    PACKAGE = Samba::LoadParm
PROTOTYPES: ENABLE

void
init(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    TALLOC_CTX *mem_ctx;
    CODE:
    mem_ctx = talloc_named(NULL, 0, "Samba::LoadParm");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating memory context", __func__);
    }

    ctx = talloc_zero(mem_ctx, LoadParmCtx);
    if (ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating private data", __func__);
    }
    ctx->mem_ctx = mem_ctx;

    ctx->lp_ctx = loadparm_init(mem_ctx);
    if (ctx->lp_ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating loadparm context", __func__);
    }
    xs_object_magic_attach_struct(aTHX_ SvRV(self), ctx);

const char *
default_path(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = lp_default_path();
    OUTPUT:
    RETVAL

const char *
setup_dir(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = dyn_SETUPDIR;
    OUTPUT:
    RETVAL

const char *
modules_dir(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = dyn_MODULESDIR;
    OUTPUT:
    RETVAL

const char *
bin_dir(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = dyn_BINDIR;
    OUTPUT:
    RETVAL

const char *
sbin_dir(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = dyn_SBINDIR;
    OUTPUT:
    RETVAL

const char *
private_path(self, name)
    SV *self
    const char *name
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    char *path;
    path = lpcfg_private_path(ctx->mem_ctx, ctx->lp_ctx, name);
    RETVAL = path;
    talloc_free(path);
    OUTPUT:
    RETVAL

const char *
server_role(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
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
load(self, filename)
    SV *self
    const char *filename
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
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
load_default(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
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
is_myname(self, name)
    SV *self
    const char *name
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = lpcfg_is_myname(ctx->lp_ctx, name);
    OUTPUT:
    RETVAL

int
is_mydomain(self, name)
    SV *self
    const char *name
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = lpcfg_is_mydomain(ctx->lp_ctx, name);
    OUTPUT:
    RETVAL

void
DESTROY(self)
    SV *self
    PREINIT:
    LoadParmCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    talloc_free(ctx->mem_ctx);
