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

#define TEVENT_DEPRECATED 1

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <xs_object_magic.h>


#include "ppport.h"

#include <stdbool.h>

#include <Samba-LoadParm.h>
#include <Samba-Credentials.h>
#include <Samba-Descriptor.h>
#include <Samba-Smb.h>

#include <util/time.h>
#include <util/data_blob.h>
#include <util/memory.h>
#include <core/ntstatus.h>
#include <smb_cli.h>
#include <smb_cliraw.h>
#include <gen_ndr/security.h>
#include <tevent.h>
#include <gensec.h>

#include "const-c.inc"

struct resolve_context;
struct resolve_context *lpcfg_resolve_context(struct loadparm_context *lp_ctx);

struct file_entry {
    const char *name;
    uint64_t size;
    uint16_t attrib;
    time_t mtime;
    bool is_directory;
};

struct file_list {
    uint32_t num_files;
    struct file_entry *files;
};

struct list_state {
    struct smbcli_tree *tree;
    uint8_t depth;
    uint8_t max_depth;

    const char *cur_base_dir;
    const char *mask;
    uint16_t attributes;

    struct file_list list;
};

static NTSTATUS do_list(const char *, struct list_state *);
static void list_fn(struct clilist_file_info *finfo, const char *name, void *state_ptr)
{
    struct list_state *state = state_ptr;

    /* Ignore . and .. directory entries */
    if (strcmp(finfo->name, ".") == 0 || strcmp(finfo->name, "..") == 0) {
            return;
    }

    /* Safety check against ../.. in filenames which may occur on non-POSIX
     * platforms */
    if (strstr(finfo->name, "../")) {
            return;
    }

    /* Append entry to file list */
    state->list.files = talloc_realloc(state, state->list.files,
            struct file_entry, state->list.num_files + 1);
    if (state->list.files == NULL) return;

    state->list.files[state->list.num_files].name =
        talloc_asprintf(state, "%s/%s", state->cur_base_dir, finfo->name);
    state->list.files[state->list.num_files].size = finfo->size;
    state->list.files[state->list.num_files].attrib = finfo->attrib;
    state->list.files[state->list.num_files].mtime = finfo->mtime;

    if (finfo->attrib & FILE_ATTRIBUTE_DIRECTORY) {
        state->list.files[state->list.num_files].is_directory = true;
        state->list.num_files++;

        if (state->depth < state->max_depth) {
            char *base_dir = talloc_asprintf(state, "%s/%s", state->cur_base_dir, finfo->name);
            do_list(base_dir, state);
        }
        return;
    }

    state->list.files[state->list.num_files].is_directory = false;
    state->list.num_files++;

    return;
}

static NTSTATUS do_list(const char *base_dir, struct list_state *state)
{
    int rv;
    char *mask;
    const char *old_base_dir;

    /* Update the relative paths, while buffering the parent */
    old_base_dir = state->cur_base_dir;
    state->cur_base_dir = base_dir;
    state->depth++;

    /* Get the current mask */
    mask = talloc_asprintf(state, "%s/%s", base_dir, state->mask);
    NT_STATUS_HAVE_NO_MEMORY(mask);
    rv = smbcli_list(state->tree, mask, state->attributes, list_fn, state);
    talloc_free(mask);

    /* Go back to the state of the parent */
    state->cur_base_dir = old_base_dir;
    state->depth--;

    if (rv == -1)
        return NT_STATUS_UNSUCCESSFUL;

    return NT_STATUS_OK;
}



void call_method_sv(SV * obj, char * method)
{
    int cnt;
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    EXTEND(SP, 1);
    PUSHs(obj);
    PUTBACK;

    cnt = perl_call_method(method, G_VOID);

    SPAGAIN;

    if (cnt != 0) {
        croak("init method call failed");
    }

    POPs;

    FREETMPS;
    LEAVE;
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
    ctx->tree = NULL;
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
    struct smbcli_state *smb_state;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    lpcfg_smbcli_options(ctx->lp_ctx, &options);
    lpcfg_smbcli_session_options(ctx->lp_ctx, &session_options);

    status = smbcli_full_connection(
                ctx->mem_ctx,
                &smb_state,
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
        croak("Failed to connect: %s", nt_errstr(status));
    }
    ctx->tree = smb_state->tree;
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
    status = smbcli_chkpath(ctx->tree, path);
    if (NT_STATUS_IS_OK(status)) {
        RETVAL = 1;
    } else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_A_DIRECTORY)) {
        RETVAL = 1;
    } else if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
        RETVAL = 0;
    } else {
        croak("Failed to check path '%s': %s", path, nt_errstr(status));
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
    status = smbcli_rmdir(ctx->tree, dname);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to rmdir %s: %s (%s)", dname, nt_errstr(status),
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
    RETVAL = smbcli_write(ctx->tree, fnum, 0, data, 0, length);
    OUTPUT:
    RETVAL

ssize_t
read(self, fnum, buffer, offset, chunk_size)
    SV *self
    int fnum
    SV *buffer = NO_INIT
    off_t offset
    size_t chunk_size
    PREINIT:
    SmbCtx *ctx;
    char *buf;
    ssize_t bytes;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
    buf = malloc(chunk_size);
    if (buf == NULL) {
        croak("No memory");
    }
    bytes = smbcli_read(ctx->tree, fnum, buf, offset, chunk_size);
    if (bytes < 0) {
        croak("Failed to read: %s", smbcli_errstr(ctx->tree));
    }
    RETVAL = bytes;
    sv_setpvn(ST(2), buf, bytes);
    free(buf);
    OUTPUT:
    RETVAL

int
set_sd(self, fname, sd, sinfo = (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL | SECINFO_PROTECTED_DACL | SECINFO_UNPROTECTED_DACL | SECINFO_SACL | SECINFO_PROTECTED_SACL | SECINFO_UNPROTECTED_SACL), access_mask = SEC_FLAG_MAXIMUM_ALLOWED)
    SV *self
    char *fname
    SV *sd
    uint32_t sinfo
    int access_mask
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
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
    /* Open file */
    ZERO_STRUCT(io_open);
    io_open.generic.level = RAW_OPEN_NTCREATEX;
    io_open.ntcreatex.in.root_fid.fnum = 0;
    io_open.ntcreatex.in.flags = 0;
    io_open.ntcreatex.in.access_mask = access_mask;
    io_open.ntcreatex.in.create_options = 0;
    io_open.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
    io_open.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
                                        NTCREATEX_SHARE_ACCESS_WRITE;
    io_open.ntcreatex.in.alloc_size = 0;
    io_open.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
    io_open.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
    io_open.ntcreatex.in.security_flags = 0;
    io_open.ntcreatex.in.fname = fname;

    status = smb_raw_open(ctx->tree, ctx->mem_ctx, &io_open);
    if (!NT_STATUS_IS_OK(status)) {
        croak("Failed to open: %s", nt_errstr(status));
    }
    fnum = io_open.ntcreatex.out.file.fnum;

    /* Set security descriptor */
    ZERO_STRUCT(io_finfo);
    io_finfo.generic.level = RAW_SFILEINFO_SEC_DESC;
    io_finfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
    io_finfo.set_secdesc.in.file.fnum = fnum;
    io_finfo.set_secdesc.in.sd = sd_ctx->sd;
    io_finfo.set_secdesc.in.secinfo_flags = sinfo;
    status = smb_raw_setfileinfo(ctx->tree, &io_finfo);
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
get_sd(self, fname, sinfo = (SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL | SECINFO_PROTECTED_DACL | SECINFO_UNPROTECTED_DACL | SECINFO_SACL | SECINFO_PROTECTED_SACL | SECINFO_UNPROTECTED_SACL), access_mask = SEC_FLAG_MAXIMUM_ALLOWED)
    SV *self
    const char *fname
    uint32_t sinfo
    int access_mask
    PREINIT:
    SmbCtx *ctx;
    DescriptorCtx *sd_ctx;
    HV *hash;
    SV * obj;
    int fnum;
    NTSTATUS status;
    union smb_open io_open;
    union smb_fileinfo fio;
    union smb_close io_close;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
    /* Open file */
    ZERO_STRUCT(io_open);
    io_open.generic.level = RAW_OPEN_NTCREATEX;
    io_open.ntcreatex.in.root_fid.fnum = 0;
    io_open.ntcreatex.in.flags = 0;
    io_open.ntcreatex.in.access_mask = access_mask;
    io_open.ntcreatex.in.create_options = 0;
    io_open.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
    io_open.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
                                    NTCREATEX_SHARE_ACCESS_WRITE;
    io_open.ntcreatex.in.alloc_size = 0;
    io_open.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
    io_open.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
    io_open.ntcreatex.in.security_flags = 0;
    io_open.ntcreatex.in.fname = fname;

    status = smb_raw_open(ctx->tree, ctx->mem_ctx, &io_open);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to open: %s", nt_errstr(status));
    }
    fnum = io_open.ntcreatex.out.file.fnum;

    /* Get security descriptor */
    ZERO_STRUCT(fio);
    fio.generic.level = RAW_FILEINFO_SEC_DESC;
    fio.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
    fio.query_secdesc.in.file.fnum = fnum;
    fio.query_secdesc.in.secinfo_flags = sinfo;
    status = smb_raw_fileinfo(ctx->tree, ctx->mem_ctx, &fio);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to query security descriptor: %s", nt_errstr(status));
    }

    /* Close file */
    ZERO_STRUCT(io_close);
    io_close.close.level = RAW_CLOSE_CLOSE;
    io_close.close.in.file.fnum = fnum;
    io_close.close.in.write_time = 0;
    status = smb_raw_close(ctx->tree, &io_close);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to close: %s", nt_errstr(status));
    }

    /* Create a Samba::Security::Descriptor and initialize it */
    hash = newHV();
    obj = newRV_noinc((SV*)hash);
    sv_bless(obj, gv_stashpv("Samba::Security::Descriptor", 0));
    call_method_sv(obj, "init");

    /* Get the DescriptorCtx */
    sd_ctx = xs_object_magic_get_struct_rv(aTHX_ obj);

    /* Set and realloc SD on the object memory context */
    sd_ctx->sd = talloc_move(sd_ctx->mem_ctx, &fio.query_secdesc.out.sd);

    RETVAL = obj;
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
    size_t size;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    ret = (HV *) sv_2mortal ((SV *) newHV ());
    CODE:
    if (ctx->tree == NULL) {
        croak("Not connected");
    }
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

# Must have bits in attibutes must be shifted 8 bits to left, see source4/torture/basic/dir.c
SV *
_list(self, base_dir, user_mask = NULL, attributes = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE, recursive = false)
    SV * self
    const char *base_dir
    const char *user_mask
    uint16_t attributes
    bool recursive
    PREINIT:
    SmbCtx *ctx;
    NTSTATUS status;
    struct list_state *state;
    int i;
    AV *ret;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    state = talloc_zero(ctx->mem_ctx, struct list_state);
    ret = (AV *) sv_2mortal ((SV *) newAV ());
    CODE:
    if (state == NULL) {
        croak("No memory");
    }

    if (ctx->tree == NULL) {
        talloc_free(state);
        croak("Not connected");
    }

    state->tree = ctx->tree;
    state->attributes = attributes;
    state->cur_base_dir = talloc_strdup(state, base_dir);
    if (user_mask == NULL) {
        state->mask = talloc_asprintf(state, "*");
    } else {
        state->mask = talloc_asprintf(state, "%s", user_mask);
    }

    if (recursive) {
        state->max_depth = UCHAR_MAX;
    } else {
        state->max_depth = 1;
    }

    status = do_list(state->cur_base_dir, state);
    if (NT_STATUS_IS_ERR(status)) {
        talloc_free(state);
        croak("Failed to list directory '%s': %s", state->cur_base_dir,
                smbcli_errstr(ctx->tree));
    }

    for (i = 0; i < state->list.num_files; i++) {
        const char *fname = state->list.files[i].name;
        bool dir = state->list.files[i].is_directory;
        uint64_t size = state->list.files[i].size;
        uint16_t attrs = state->list.files[i].attrib;
        time_t mtime = state->list.files[i].mtime;

        HV *rh = (HV *) sv_2mortal ((SV *) newHV ());
        hv_store(rh, "name", 4, newSVpv(fname, strlen(fname)), 0);
        hv_store(rh, "size", 4, newSVuv(size), 0);
        hv_store(rh, "attributes", 10, newSVuv(attrs), 0);
        hv_store(rh, "mtime", 5, newSVuv(mtime), 0);
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

