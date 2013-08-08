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

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "samba-loadparm.h"
#include "samba-credentials.h"

#include "const-c.inc"

MODULE = Samba::Credentials		PACKAGE = Samba::Credentials
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

Credentials *
new(class, lp)
    SV *class
    LoadParm *lp
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    Credentials *self = NULL;
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

    self = talloc_zero(mem_ctx, Credentials);
    if (self == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating context", __func__);
        XSRETURN_UNDEF;
    }
    self->mem_ctx = mem_ctx;
    self->lp = lp;

    self->ccreds = cli_credentials_init(mem_ctx);
    if (self->ccreds == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating credentials", __func__);
        XSRETURN_UNDEF;
    }
    cli_credentials_guess(self->ccreds, self->lp->lp_ctx);

    RETVAL = self;
OUTPUT:
    RETVAL

MODULE = Samba::Credentials PACKAGE = CredentialsPtr PREFIX = credsPtr_
PROTOTYPES: ENABLE

const char *
credsPtr_username(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_username(self->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set credentialas username");
    }
    RETVAL = cli_credentials_get_username(self->ccreds);
    OUTPUT:
    RETVAL

const char *
credsPtr_password(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_password(self->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set credentials password");
    }
    RETVAL = cli_credentials_get_password(self->ccreds);
    OUTPUT:
    RETVAL

const char *
credsPtr_domain(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_domain(self->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set domain");
    }
    RETVAL = cli_credentials_get_domain(self->ccreds);
    OUTPUT:
    RETVAL

const char *
credsPtr_realm(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_realm(self->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set realm");
    }
    RETVAL = cli_credentials_get_realm(self->ccreds);
    OUTPUT:
    RETVAL

const char *
credsPtr_bind_dn(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_bind_dn(self->ccreds, value))
            croak("Failed to set bind dn");
    }
    RETVAL = cli_credentials_get_bind_dn(self->ccreds);
    OUTPUT:
    RETVAL

bool
credsPtr_anonymous(self, value = NO_INIT)
    Credentials *self
    bool value
    CODE:
    if (items > 1) {
        cli_credentials_set_anonymous(self->ccreds);
    }
    RETVAL = cli_credentials_is_anonymous(self->ccreds);
    OUTPUT:
    RETVAL

const char *
credsPtr_workstation(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    if (items > 1) {
        if (!cli_credentials_set_workstation(self->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set credentials workstation");
    }
    RETVAL = cli_credentials_get_workstation(self->ccreds);
    OUTPUT:
    RETVAL

bool
credsPtr_authentication_requested(self)
    Credentials *self
    CODE:
    RETVAL = cli_credentials_authentication_requested(self->ccreds);
    OUTPUT:
    RETVAL

bool
credsPtr_wrong_password(self)
    Credentials *self
    CODE:
    RETVAL = cli_credentials_wrong_password(self->ccreds);
    OUTPUT:
    RETVAL

int
credsPtr_kerberos_state(self, value = NO_INIT)
    Credentials *self
    int value
    CODE:
    if (items > 1) {
        cli_credentials_set_kerberos_state(self->ccreds, value);
    }
    RETVAL = cli_credentials_get_kerberos_state(self->ccreds);
    OUTPUT:
    RETVAL

int
credsPtr_kerberos_forwardable(self, value = NO_INIT)
    Credentials *self
    int value
    CODE:
    if (items > 1) {
        cli_credentials_set_krb_forwardable(self->ccreds, value);
    }
    RETVAL = cli_credentials_get_krb_forwardable(self->ccreds);
    OUTPUT:
    RETVAL

void
credsPtr_guess(self)
    Credentials *self
    CODE:
    cli_credentials_guess(self->ccreds, self->lp->lp_ctx);

void
credsPtr_set_machine_account(self)
    Credentials *self
    CODE:
    NTSTATUS status;
    status = cli_credentials_set_machine_account(self->ccreds, self->lp->lp_ctx);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to set machine account: %s", nt_errstr(status));
    }

int
credsPtr_set_ccache(self, value)
    Credentials *self
    const char *value
    CODE:
    const char *error_str;
    int ret;

    ret = cli_credentials_set_ccache(self->ccreds, self->lp->lp_ctx,
            value, CRED_SPECIFIED, &error_str);
    if (ret) {
        croak("Failed to set ccache: %s", error_str);
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

int
credsPtr_set_keytab(self, value)
    Credentials *self
    const char *value
    CODE:
    int ret;
    ret = cli_credentials_set_keytab_name(self->ccreds, self->lp->lp_ctx,
            value, CRED_SPECIFIED);
    if (ret) {
        croak("Failed to set keytab path");
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

void
credsPtr_set_target_service(self, value)
    Credentials *self
    const char *value
    CODE:
    cli_credentials_set_target_service(self->ccreds, value);

unsigned int
credsPtr_gensec_features(self, value = NO_INIT)
    Credentials *self
    unsigned int value
    CODE:
    if (items > 1) {
        cli_credentials_set_gensec_features(self->ccreds, value);
    }
    RETVAL = cli_credentials_get_gensec_features(self->ccreds);
    OUTPUT:
    RETVAL

const char *
credsPtr_principal(self, value = NO_INIT)
    Credentials *self
    const char *value
    CODE:
    const char *p;
    if (items > 1) {
        if (!cli_credentials_set_principal(self->ccreds, value, CRED_SPECIFIED))
            croak("Failed to set principal");
    }
    p = cli_credentials_get_principal(self->ccreds, self->mem_ctx);
    RETVAL = p;
    OUTPUT:
    RETVAL

void
credsPtr_set_impersonate_principal(self, principal, service)
    Credentials *self
    const char *principal
    const char *service
    CODE:
    cli_credentials_set_impersonate_principal(self->ccreds, principal, service);

void
credsPtr_DESTROY(ctx)
    Credentials *ctx
    CODE:
    talloc_free(ctx->mem_ctx);


