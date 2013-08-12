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
#include <Samba-Descriptor.h>
#include <Samba-Smb.h>

#include <stdbool.h>
#include <util/time.h>
#include <util/data_blob.h>
#include <util/memory.h>
#include <core/ntstatus.h>
#include <smb_cli.h>
#include <smb_cliraw.h>
#include <gen_ndr/security.h>

#include "const-c.inc"

struct resolve_context;
struct resolve_context *lpcfg_resolve_context(struct loadparm_context *lp_ctx);

struct file_entry {
        bool is_directory;
        const char *rel_path;
};
struct file_list {
        uint32_t num_files;
        struct file_entry *files;
};

static void list_fn(struct clilist_file_info *finfo, const char *name, void *state_ptr)
{
    struct file_list *state = state_ptr;
    const char *rel_path;

    /* Ignore . and .. directory entries */
    if (strcmp(finfo->name, ".") == 0 || strcmp(finfo->name, "..") == 0) {
            return;
    }

    /* Safety check against ../.. in filenames which may occur on non-POSIX
     * platforms */
    if (strstr(finfo->name, "../")) {
            return;
    }

    rel_path = talloc_asprintf(state, "%s", finfo->name);
    if (rel_path == NULL) return;

    /* Append entry to file list */
    state->files = talloc_realloc(state, state->files,
                    struct file_entry,
                    state->num_files + 1);
    if (state->files == NULL) return;

     state->files[state->num_files].rel_path = rel_path;

     /* Directory */
     if (finfo->attrib & FILE_ATTRIBUTE_DIRECTORY) {
             state->files[state->num_files].is_directory = true;
             state->num_files++;
             return;
     }

     state->files[state->num_files].is_directory = false;
     state->num_files++;

     return;
}

MODULE = Samba::Smb     PACKAGE = Samba::Smb
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

void
init(self, lp, creds)
    SV *self
    SV *lp
    SV *creds
    PREINIT:
    NTSTATUS status;
    TALLOC_CTX *mem_ctx;
    SmbCtx *ctx;
    CODE:
    mem_ctx = talloc_named(NULL, 0, "Samba::SmbCtx");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating talloc context", __func__);
    }

    ctx = talloc_zero(mem_ctx, SmbCtx);
    if (ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating private_data", __func__);
    }
    ctx->mem_ctx = mem_ctx;

    ctx->ev_ctx = tevent_context_init(ctx->mem_ctx);
    if (ctx->ev_ctx == NULL) {
        talloc_free(mem_ctx);
        croak("No memory allocating ev_ctx");
    }
    tevent_loop_allow_nesting(ctx->ev_ctx);

    status = gensec_init();
    if (NT_STATUS_IS_ERR(status)) {
        talloc_free(mem_ctx);
        croak("Failed to initalise gensec: %s", nt_errstr(status));
    }
    ctx->lp_ctx = ((LoadParmCtx *)xs_object_magic_get_struct_rv(aTHX_ lp))->lp_ctx;
    ctx->creds = ((CredentialsCtx *)xs_object_magic_get_struct_rv(aTHX_ creds))->ccreds;
    xs_object_magic_attach_struct(aTHX_ SvRV(self), ctx);

int
connect(self, hostname, service)
    SV *self
    const char *hostname
    const char *service
    PREINIT:
    NTSTATUS status;
    SmbCtx *ctx;
    struct smbcli_options options;
    struct smbcli_session_options session_options;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    lpcfg_smbcli_options(ctx->lp_ctx, &options);
    lpcfg_smbcli_session_options(ctx->lp_ctx, &session_options);

    status = smbcli_tree_full_connection(
                ctx->mem_ctx,
                &ctx->tree,
                hostname,
                lpcfg_smb_ports(ctx->lp_ctx),
                service,
                NULL,
                lpcfg_socket_options(ctx->lp_ctx),
                ctx->creds,
                lpcfg_resolve_context(ctx->lp_ctx),
                ctx->ev_ctx,
                &options,
                &session_options,
                lpcfg_gensec_settings(ctx->mem_ctx, ctx->lp_ctx));
    if (!NT_STATUS_IS_OK(status)) {
        croak(nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
open(self, fname, flags, share_mode)
    SV *self
    const char *fname
    int flags
    int share_mode
    PREINIT:
    SmbCtx *ctx;
    int fnum;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    fnum = smbcli_open(ctx->tree, fname, flags, share_mode);
    if (fnum == -1) {
        croak("Failed to open %s: %s", fname, smbcli_errstr(ctx->tree));
    }
    RETVAL = fnum;
OUTPUT:
    RETVAL

int
close(self, fnum)
    SV *self
    int fnum
    PREINIT:
    NTSTATUS status;
    SmbCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = smbcli_close(ctx->tree, fnum);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to close: %s (%s)", nt_errstr(status),
            smbcli_errstr(ctx->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
chkpath(self, path)
    SV *self
    const char *path
    PREINIT:
    NTSTATUS status;
    SmbCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = smbcli_chkpath(ctx->tree, path);
    if (NT_STATUS_IS_OK(status)) {
        RETVAL = 1;
    } else {
        RETVAL = 0;
    }
    OUTPUT:
    RETVAL

int
mkdir(self, dname)
    SV *self
    const char *dname
    PREINIT:
    SmbCtx *ctx;
    NTSTATUS status;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = smbcli_mkdir(ctx->tree, dname);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to mkdir %s: %s (%s)", dname, nt_errstr(status),
            smbcli_errstr(ctx->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
rmdir(self, dname)
    SV *self
    const char *dname
    PREINIT:
    NTSTATUS status;
    SmbCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = smbcli_rmdir(ctx->tree, dname);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to rmdir %d: %s (%s)", dname, nt_errstr(status),
            smbcli_errstr(ctx->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
deltree(self, dname)
    SV *self
    const char *dname
    PREINIT:
    int ret;
    SmbCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    ret = smbcli_deltree(ctx->tree, dname);
    if (ret == -1) {
        croak("Failed to deltree: %s", smbcli_errstr(ctx->tree));
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

int
rename(self, src, dst)
    SV *self
    const char *src
    const char *dst
    PREINIT:
    SmbCtx *ctx;
    NTSTATUS status;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = smbcli_rename(ctx->tree, src, dst);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to rename (%s): %s", nt_errstr(status),
            smbcli_errstr(ctx->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
unlink(self, fname)
    SV *self
    const char *fname
    PREINIT:
    SmbCtx *ctx;
    NTSTATUS status;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = smbcli_unlink(ctx->tree, fname);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to unlink (%s): %s", nt_errstr(status),
            smbcli_errstr(ctx->tree));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

ssize_t
write(self, fnum, data, length)
    SV *self
    int fnum
    const char *data
    size_t length
    PREINIT:
    SmbCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    RETVAL = smbcli_write(ctx->tree, fnum, 0, data, 0, length);
    OUTPUT:
    RETVAL

int
set_sd(self, filename, sd, flags = NO_INIT)
    SV *self
    char *filename
    SV *sd
    int flags
    PREINIT:
    SmbCtx *ctx;
    DescriptorCtx *sd_ctx;
    NTSTATUS status;
    union smb_open io_open;
    union smb_close io_close;
    union smb_setfileinfo io_finfo;
    int fnum;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    sd_ctx = xs_object_magic_get_struct_rv(aTHX_ sd);
    CODE:
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

    status = smb_raw_open(ctx->tree, ctx->mem_ctx, &io_open);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to open: %s", nt_errstr(status));
    }
    fnum = io_open.ntcreatex.out.file.fnum;

    /* Set security descriptor */
    ZERO_STRUCT(io_finfo);
    io_finfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
    io_finfo.set_secdesc.in.file.fnum = fnum;
    io_finfo.set_secdesc.in.sd = sd_ctx->sd;
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
    status = smb_raw_set_secdesc(ctx->tree, &io_finfo);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to set security descriptor: %s", nt_errstr(status));
    }

    /* Close file */
    ZERO_STRUCT(io_close);
    io_close.close.level = RAW_CLOSE_CLOSE;
    io_close.close.in.file.fnum = fnum;
    io_close.close.in.write_time = 0;
    status = smb_raw_close(ctx->tree, &io_close);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to close: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

SV *
getattr(self, fnum)
    SV *self
    int fnum
    PREINIT:
    SmbCtx *ctx;
    NTSTATUS status;
    HV *ret;
    uint16_t mode;
    time_t change_time, access_time, write_time;
    off_t size;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    ret = (HV *) sv_2mortal ((SV *) newHV ());
    CODE:
    status = smbcli_getattrE(ctx->tree, fnum, &mode, &size, &change_time,
                             &access_time, &write_time);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to get attributes: %s", smbcli_errstr(ctx->tree));
    }
    hv_store(ret, "mode", 4, newSVuv(mode), 0);
    hv_store(ret, "size", 4, newSVuv(size), 0);
    hv_store(ret, "change_time", 11, newSVuv(change_time), 0);
    hv_store(ret, "access_time", 11, newSVuv(access_time), 0);
    hv_store(ret, "write_time", 10, newSVuv(write_time), 0);
    RETVAL = newRV((SV *)ret);
    OUTPUT:
    RETVAL

SV *
list(self, mask, attributes)
    SV * self
    const char *mask
    uint16_t attributes
    PREINIT:
    SmbCtx *ctx;
    NTSTATUS status;
    struct file_list *state;
    int rv, i;
    AV *ret;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    state = talloc_zero(ctx->mem_ctx, struct file_list);
    ret = (AV *) sv_2mortal ((SV *) newAV ());
    CODE:
    rv = smbcli_list(ctx->tree, mask, attributes, list_fn, state);
    if (rv == -1) {
        croak("Failed to list directory: %s", smbcli_errstr(ctx->tree));
    }
    for (i = 0; i < state->num_files; i++) {
        const char *fname = state->files[i].rel_path;
        bool dir = state->files[i].is_directory;

        HV *rh = (HV *) sv_2mortal ((SV *) newHV ());
        hv_store(rh, "name", 4, newSVpv(fname, strlen(fname)), 0);
        hv_store(rh, "is_directory", 12, newSViv(dir), 0);
        av_push(ret, newRV((SV *)rh));
    }
    RETVAL = newRV((SV *)ret);
    talloc_free(state);
    OUTPUT:
    RETVAL

void
DESTROY(self)
    SV *self
    PREINIT:
    SmbCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    talloc_free(ctx->mem_ctx);

