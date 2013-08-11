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
#include <Samba-Credentials.h>

#include "const-c.inc"

MODULE = Samba::Credentials		PACKAGE = Samba::Credentials
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

void
init(self, lp)
    SV *self
    SV *lp
    INIT:
    TALLOC_CTX *mem_ctx;
    CredentialsCtx *ctx;
    CODE:

    mem_ctx = talloc_named(NULL, 0, "Samba::Credentials");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating talloc context", __func__);
    }

    ctx = talloc_zero(mem_ctx, CredentialsCtx);
    if (ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating context", __func__);
    }
    ctx->mem_ctx = mem_ctx;
    ctx->lp = xs_object_magic_get_struct_rv(aTHX_ lp);

    ctx->ccreds = cli_credentials_init(mem_ctx);
    if (ctx->ccreds == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating credentials", __func__);
    }
    xs_object_magic_attach_struct(aTHX_ SvRV(self), ctx);

const char *
username(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_username(ctx->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set credentialas username");
    }
    RETVAL = cli_credentials_get_username(ctx->ccreds);
    OUTPUT:
    RETVAL

const char *
password(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_password(ctx->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set credentials password");
    }
    RETVAL = cli_credentials_get_password(ctx->ccreds);
    OUTPUT:
    RETVAL

const char *
domain(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_domain(ctx->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set domain");
    }
    RETVAL = cli_credentials_get_domain(ctx->ccreds);
    OUTPUT:
    RETVAL

const char *
realm(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_realm(ctx->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set realm");
    }
    RETVAL = cli_credentials_get_realm(ctx->ccreds);
    OUTPUT:
    RETVAL

const char *
bind_dn(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_bind_dn(ctx->ccreds, value))
            croak("Failed to set bind dn");
    }
    RETVAL = cli_credentials_get_bind_dn(ctx->ccreds);
    OUTPUT:
    RETVAL

bool
anonymous(self, value = NO_INIT)
    SV *self
    bool value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        cli_credentials_set_anonymous(ctx->ccreds);
    }
    RETVAL = cli_credentials_is_anonymous(ctx->ccreds);
    OUTPUT:
    RETVAL

const char *
workstation(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_workstation(ctx->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set credentials workstation");
    }
    RETVAL = cli_credentials_get_workstation(ctx->ccreds);
    OUTPUT:
    RETVAL

bool
authentication_requested(self)
    SV *self
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = cli_credentials_authentication_requested(ctx->ccreds);
    OUTPUT:
    RETVAL

bool
wrong_password(self)
    SV *self
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = cli_credentials_wrong_password(ctx->ccreds);
    OUTPUT:
    RETVAL

int
kerberos_state(self, value = NO_INIT)
    SV *self
    int value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        cli_credentials_set_kerberos_state(ctx->ccreds, value);
    }
    RETVAL = cli_credentials_get_kerberos_state(ctx->ccreds);
    OUTPUT:
    RETVAL

int
kerberos_forwardable(self, value = NO_INIT)
    SV *self
    int value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        cli_credentials_set_krb_forwardable(ctx->ccreds, value);
    }
    RETVAL = cli_credentials_get_krb_forwardable(ctx->ccreds);
    OUTPUT:
    RETVAL

int
guess(self)
    SV *self
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    cli_credentials_guess(ctx->ccreds, ctx->lp->lp_ctx);
    RETVAL = 1;
    OUTPUT:
    RETVAL

void
set_machine_account(self)
    SV *self
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    NTSTATUS status;
    status = cli_credentials_set_machine_account(ctx->ccreds, ctx->lp->lp_ctx);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to set machine account: %s", nt_errstr(status));
    }

int
set_ccache(self, value)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    const char *error_str;
    int ret;

    ret = cli_credentials_set_ccache(ctx->ccreds, ctx->lp->lp_ctx,
            value, CRED_SPECIFIED, &error_str);
    if (ret) {
        croak("Failed to set ccache: %s", error_str);
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

int
set_keytab(self, value)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    int ret;
    ret = cli_credentials_set_keytab_name(ctx->ccreds, ctx->lp->lp_ctx,
            value, CRED_SPECIFIED);
    if (ret) {
        croak("Failed to set keytab path");
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

void
set_target_service(self, value)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    cli_credentials_set_target_service(ctx->ccreds, value);

unsigned int
gensec_features(self, value = NO_INIT)
    SV *self
    unsigned int value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (items > 1) {
        cli_credentials_set_gensec_features(ctx->ccreds, value);
    }
    RETVAL = cli_credentials_get_gensec_features(ctx->ccreds);
    OUTPUT:
    RETVAL

char *
principal(self, value = NO_INIT)
    SV *self
    const char *value
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    char *p;
    if (items > 1) {
        if (!cli_credentials_set_principal(ctx->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set principal");
    }
    p = (char*)cli_credentials_get_principal(ctx->ccreds, ctx->mem_ctx);
    RETVAL = p;
    talloc_free(p);
    OUTPUT:
    RETVAL

void
set_impersonate_principal(self, principal, service)
    SV *self
    const char *principal
    const char *service
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    cli_credentials_set_impersonate_principal(ctx->ccreds, principal, service);

void
DESTROY(self)
    SV *self
    PREINIT:
    CredentialsCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    talloc_free(ctx->mem_ctx);

