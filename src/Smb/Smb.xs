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
#include "samba-descriptor.h"
#include "samba-smb.h"

#include <stdbool.h>
#include <util/time.h>
#include <util/data_blob.h>
#include <util/memory.h>
#include <core/ntstatus.h>
#include <smb_cliraw.h>
#include <gen_ndr/security.h>

#include "const-c.inc"


MODULE = Samba::Smb     PACKAGE = Samba::Smb
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

Smb *
new(class, lp, creds, hostname, service)
    SV *class
    LoadParm *lp
    Credentials *creds
    char *hostname
    char *service
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    Smb *self = NULL;
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

    self = talloc_zero(mem_ctx, Smb);
    if (self == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating private_data", __func__);
        XSRETURN_UNDEF;
    }
    self->mem_ctx = mem_ctx;

    self->ev_ctx = tevent_context_init(mem_ctx);
    if (self->ev_ctx == NULL) {
        talloc_free(mem_ctx);
        croak("No memory allocating ev_ctx");
        XSRETURN_UNDEF;
    }
    tevent_loop_allow_nesting(self->ev_ctx);

    status = gensec_init();
    if (NT_STATUS_IS_ERR(status)) {
        talloc_free(mem_ctx);
        croak("Failed to initalise gensec: %s", nt_errstr(status));
        XSRETURN_UNDEF;
    }

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
                self->ev_ctx,
                &options,
                &session_options,
                lpcfg_gensec_settings(mem_ctx, lp->lp_ctx));
    if (!NT_STATUS_IS_OK(status)) {
        talloc_free(mem_ctx);
        croak(nt_errstr(status));
        XSRETURN_UNDEF;
    }
    self->tree = tree;

    RETVAL = self;
OUTPUT:
    RETVAL

MODULE = Samba::Smb     PACKAGE = SmbPtr    PREFIX = smbPtr_

int
smbPtr_open(self, fname, flags, share_mode)
    Smb *self
    const char *fname
    int flags
    int share_mode
CODE:
    int fnum;

    fnum = smbcli_open(self->tree, fname, flags, share_mode);
    if (fnum == -1) {
        croak("Failed to open %s: %s", fname, smbcli_errstr(self->tree));
    }
    RETVAL = fnum;
OUTPUT:
    RETVAL

int
smbPtr_close(self, fnum)
    Smb *self
    int fnum
CODE:
    NTSTATUS status;
    status = smbcli_close(self->tree, fnum);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to close: %s (%s)", nt_errstr(status),
            smbcli_errstr(self->tree));
    }
    RETVAL = 1;
OUTPUT:
    RETVAL

int
smbPtr_mkdir(self, dname)
    Smb *self
    const char *dname
    CODE:
    NTSTATUS status;

    status = smbcli_mkdir(self->tree, dname);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to mkdir %s: %s (%s)", dname, nt_errstr(status),
            smbcli_errstr(self->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
smbPtr_rmdir(self, dname)
    Smb *self
    const char *dname
    CODE:
    NTSTATUS status;

    status = smbcli_rmdir(self->tree, dname);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to rmdir %d: %s (%s)", dname, nt_errstr(status),
            smbcli_errstr(self->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

ssize_t smbPtr_write(self, fnum, data, length)
    Smb *self
    int fnum
    const char *data
    size_t length
    CODE:
    RETVAL = smbcli_write(self->tree, fnum, 0, data, 0, length);
    OUTPUT:
    RETVAL

int
smbPtr_set_sd(self, filename, sd, flags = NO_INIT)
    Smb *self
    char *filename
    Descriptor *sd
    int flags
CODE:
    NTSTATUS status;
    union smb_open io_open;
    union smb_close io_close;
    union smb_setfileinfo io_finfo;
    int fnum;

    /* Open file */
    ZERO_STRUCT(io_open);
    io_open.generic.level = RAW_OPEN_NTCREATEX;
    io_open.ntcreatex.in.root_fid.fnum = 0;
    io_open.ntcreatex.in.flags = 0;
    io_open.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
    io_open.ntcreatex.in.create_options = 0;
    io_open.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
    io_open.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
                                        NTCREATEX_SHARE_ACCESS_WRITE;
    io_open.ntcreatex.in.alloc_size = 0;
    io_open.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
    io_open.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
    io_open.ntcreatex.in.security_flags = 0;
    io_open.ntcreatex.in.fname = filename;

    status = smb_raw_open(self->tree, self->mem_ctx, &io_open);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to open: %s", nt_errstr(status));
    }
    fnum = io_open.ntcreatex.out.file.fnum;

    /* Set security descriptor */
    ZERO_STRUCT(io_finfo);
    io_finfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
    io_finfo.set_secdesc.in.file.fnum = fnum;
    io_finfo.set_secdesc.in.sd = sd->sd;
    if (flags) {
        io_finfo.set_secdesc.in.secinfo_flags = flags;
    } else {
        io_finfo.set_secdesc.in.secinfo_flags = SECINFO_OWNER |
                                           SECINFO_GROUP |
                                           SECINFO_DACL |
                                           SECINFO_PROTECTED_DACL |
                                           SECINFO_UNPROTECTED_DACL |
                                           SECINFO_SACL |
                                           SECINFO_PROTECTED_SACL |
                                           SECINFO_UNPROTECTED_SACL;
    }
    status = smb_raw_set_secdesc(self->tree, &io_finfo);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to set security descriptor: %s", nt_errstr(status));
    }

    /* Close file */
    ZERO_STRUCT(io_close);
    io_close.close.level = RAW_CLOSE_CLOSE;
    io_close.close.in.file.fnum = fnum;
    io_close.close.in.write_time = 0;
    status = smb_raw_close(self->tree, &io_close);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to close: %s", nt_errstr(status));
    }

    RETVAL = 1;
OUTPUT:
    RETVAL
