#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "util/data_blob.h"

#include "samba-descriptor.h"
#include "samba-ace.h"
#include "gen_ndr/security.h"
#include "security/security_descriptor.h"
#include "security/sddl.h"
#include "security/dom_sid.h"

#include "const-c.inc"

/* Takes the access mask of a DS ACE and transform them in a File ACE mask */
uint32_t ldapmask2filemask(uint32_t ldm)
{
    uint32_t RIGHT_DS_CREATE_CHILD     = 0x00000001;
    uint32_t RIGHT_DS_DELETE_CHILD     = 0x00000002;
    uint32_t RIGHT_DS_LIST_CONTENTS    = 0x00000004;
    uint32_t ACTRL_DS_SELF             = 0x00000008;
    uint32_t RIGHT_DS_READ_PROPERTY    = 0x00000010;
    uint32_t RIGHT_DS_WRITE_PROPERTY   = 0x00000020;
    uint32_t RIGHT_DS_DELETE_TREE      = 0x00000040;
    uint32_t RIGHT_DS_LIST_OBJECT      = 0x00000080;
    uint32_t RIGHT_DS_CONTROL_ACCESS   = 0x00000100;
    uint32_t FILE_READ_DATA            = 0x0001;
    uint32_t FILE_LIST_DIRECTORY       = 0x0001;
    uint32_t FILE_WRITE_DATA           = 0x0002;
    uint32_t FILE_ADD_FILE             = 0x0002;
    uint32_t FILE_APPEND_DATA          = 0x0004;
    uint32_t FILE_ADD_SUBDIRECTORY     = 0x0004;
    uint32_t FILE_CREATE_PIPE_INSTANCE = 0x0004;
    uint32_t FILE_READ_EA              = 0x0008;
    uint32_t FILE_WRITE_EA             = 0x0010;
    uint32_t FILE_EXECUTE              = 0x0020;
    uint32_t FILE_TRAVERSE             = 0x0020;
    uint32_t FILE_DELETE_CHILD         = 0x0040;
    uint32_t FILE_READ_ATTRIBUTES      = 0x0080;
    uint32_t FILE_WRITE_ATTRIBUTES     = 0x0100;
    uint32_t DELETE                    = 0x00010000;
    uint32_t READ_CONTROL              = 0x00020000;
    uint32_t WRITE_DAC                 = 0x00040000;
    uint32_t WRITE_OWNER               = 0x00080000;
    uint32_t SYNCHRONIZE               = 0x00100000;
    uint32_t STANDARD_RIGHTS_ALL       = 0x001F0000;

    uint32_t filemask = ldm & STANDARD_RIGHTS_ALL;

    if ((ldm & RIGHT_DS_READ_PROPERTY) && (ldm & RIGHT_DS_LIST_CONTENTS)) {
         filemask |= (SYNCHRONIZE | FILE_LIST_DIRECTORY |
                      FILE_READ_ATTRIBUTES | FILE_READ_EA |
                      FILE_READ_DATA | FILE_EXECUTE);
    }

     if (ldm & RIGHT_DS_WRITE_PROPERTY) {
         filemask |= (SYNCHRONIZE | FILE_WRITE_DATA |
                      FILE_APPEND_DATA | FILE_WRITE_EA |
                      FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE |
                      FILE_ADD_SUBDIRECTORY);
     }

     if (ldm & RIGHT_DS_CREATE_CHILD) {
         filemask |= (FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE);
     }

     if (ldm & RIGHT_DS_DELETE_CHILD) {
         filemask |= FILE_DELETE_CHILD;
     }

     return filemask;
}

MODULE = Samba::Security::Descriptor    PACKAGE = Samba::Security::Descriptor
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

Descriptor *
new(class)
    SV *class
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    const char *classname;
    Descriptor *self = NULL;

    if (sv_isobject(class)) {
        classname = sv_reftype(SvRV(class), 1);
    } else {
        if (!SvPOK(class))
            croak("%s: Need an object or class name as "
                  "first argument to the constructor", __func__);
        classname = SvPV_nolen(class);
    }

    mem_ctx = talloc_named(NULL, 0, "Samba::Security::Descriptor");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating talloc context", __func__);
        XSRETURN_UNDEF;
    }

    self = talloc_zero(mem_ctx, Descriptor);
    if (self == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating context", __func__);
        XSRETURN_UNDEF;
    }
    self->mem_ctx = mem_ctx;

    self->sd = security_descriptor_initialise(mem_ctx);
    if (self->sd == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating security descriptor", __func__);
        XSRETURN_UNDEF;
    }

    RETVAL = self;
OUTPUT:
    RETVAL

MODULE = Samba::Security::Descriptor PACKAGE = DescriptorPtr PREFIX=sdPtr_

const char *
as_sddl(self)
    Descriptor *self
    CODE:
    char *text = NULL;
    text = sddl_encode(self->mem_ctx, self->sd, self->domain_sid);
    if (text == NULL) {
        croak("Failed to encode SD in SDDL format");
    }
    RETVAL = text;
    talloc_free(text);
    OUTPUT:
    RETVAL

int
from_sddl(self, sddl, domain_sid)
    Descriptor *self
    const char *sddl
    const char *domain_sid
    CODE:
    struct dom_sid *new_domain_sid = NULL;
    struct security_descriptor *new_sd = NULL;

    new_domain_sid = dom_sid_parse_talloc(self->mem_ctx, domain_sid);
    if (new_domain_sid == NULL) {
        croak("Cannot parse SID string %s", domain_sid);
    } else {
        talloc_free(self->domain_sid);
        self->domain_sid = new_domain_sid;
    }

    new_sd = sddl_decode(self->mem_ctx, sddl, self->domain_sid);
    if (new_sd == NULL) {
        talloc_free(self->domain_sid);
        talloc_free(self->sd);
        self->domain_sid = NULL;
        self->sd = NULL;
        croak("Cannot parse SDDL string '%s'", sddl);
    } else {
        self->sd = new_sd;
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
unmarshall(self, blob, length, domain_sid)
    Descriptor *self
    char *blob
    unsigned int length
    const char *domain_sid
    CODE:
    NTSTATUS status;
    struct dom_sid *new_domain_sid = NULL;
    struct security_descriptor *new_sd = NULL;

    new_domain_sid = dom_sid_parse_talloc(self->mem_ctx, domain_sid);
    if (new_domain_sid == NULL) {
        croak("Cannot parse SID string %s", domain_sid);
    } else {
        talloc_free(self->domain_sid);
        self->domain_sid = new_domain_sid;
    }

    status = unmarshall_sec_desc(self->mem_ctx, blob, length, &self->sd);
    if (NT_STATUS_IS_ERR(status)) {
        talloc_free(self->domain_sid);
        talloc_free(self->sd);
        self->domain_sid = NULL;
        self->sd = NULL;
        croak("Cannot unmarshall security descriptor: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

SV *
marshall(self)
    Descriptor *self
    CODE:
    NTSTATUS status;
    uint8_t *blob = NULL;
    size_t length;
    SV *foo;

    if (self->sd == NULL) {
        croak("Security descriptor not initialised");
    }

    status = marshall_sec_desc(self->mem_ctx, self->sd, &blob, &length);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Cannot marshall security descriptor: %s", nt_errstr(status));
    }
    RETVAL = newSV(0);
    sv_setpvn(RETVAL, blob, length);
    OUTPUT:
    RETVAL

int
to_fs_sd(self)
    Descriptor *self
    CODE:
    int i;
    NTSTATUS status;
    struct security_descriptor *fs_sd = NULL;
    struct security_acl *acl = NULL;

    if (self->domain_sid == NULL) {
        croak("Domain SID not initialized");
    }
    if (self->sd == NULL) {
        croak("Security Descriptor not initialized");
    }

    fs_sd = security_descriptor_initialise(self->mem_ctx);
    fs_sd->owner_sid = dom_sid_dup(fs_sd, self->sd->owner_sid);
    fs_sd->group_sid = dom_sid_dup(fs_sd, self->sd->group_sid);
    fs_sd->type = self->sd->type;
    fs_sd->revision = self->sd->revision;
    acl = self->sd->dacl;

    for (i = 0; i < acl->num_aces; i++) {
        struct security_ace *ace = &(acl->aces[i]);
        char *ace_sid_str = dom_sid_string(self->mem_ctx, &ace->trustee);
        if (!ace->type & SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT &&
                strcmp(ace_sid_str, SID_BUILTIN_PREW2K) != 0) {
            ace->flags |= (SEC_ACE_FLAG_OBJECT_INHERIT |
                           SEC_ACE_FLAG_CONTAINER_INHERIT);
            if (strcmp(ace_sid_str, SID_CREATOR_OWNER) == 0) {
                ace->flags |= SEC_ACE_FLAG_INHERIT_ONLY;
            }
            ace->access_mask = ldapmask2filemask(ace->access_mask);

            struct security_ace *new_ace = security_ace_create(
                fs_sd->dacl, ace_sid_str, ace->type, ace->access_mask,
                ace->flags);
            status = security_descriptor_dacl_add(fs_sd, new_ace);
            if (NT_STATUS_IS_ERR(status)) {
                croak("Failed to add DACL: %s", nt_errstr(status));
            }
        }
        talloc_free(ace_sid_str);
    }
    //talloc_free(self->sd);
    self->sd = fs_sd;
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
sacl_del(self, trustee_str)
    Descriptor *self
    const char *trustee_str
    CODE:
    NTSTATUS status;
    struct dom_sid *trustee = NULL;

    if (self->sd == NULL) {
        croak("Security descriptor not initialized");
    }
    if (self->domain_sid == NULL) {
        croak("Domain SID not initialized");
    }

    trustee = dom_sid_parse_talloc(self->mem_ctx, trustee_str);
    if (trustee == NULL) {
        croak("Cannot parse SID string '%s'", trustee_str);
    }

    status = security_descriptor_sacl_del(self->sd, trustee);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to delete SACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
sacl_add(self, ace)
    Descriptor *self
    AccessControlEntry *ace
    CODE:
    NTSTATUS status;

    if (self->sd == NULL) {
        croak("Security descriptor not initialized");
    }
    if (self->domain_sid == NULL) {
        croak("Domain SID not initialized");
    }

    status = security_descriptor_sacl_add(self->sd, &ace->ace);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to add SACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
dacl_del(self, trustee_str)
    Descriptor *self
    const char *trustee_str
    CODE:
    NTSTATUS status;
    struct dom_sid *trustee = NULL;

    if (self->sd == NULL) {
        croak("Security descriptor not initialized");
    }
    if (self->domain_sid == NULL) {
        croak("Domain SID not initialized");
    }

    trustee = dom_sid_parse_talloc(self->mem_ctx, trustee_str);
    if (trustee == NULL) {
        croak("Cannot parse SID string '%s'", trustee_str);
    }

    status = security_descriptor_dacl_del(self->sd, trustee);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to delete DACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
dacl_add(self, ace)
    Descriptor *self
    AccessControlEntry *ace
    CODE:
    NTSTATUS status;

    if (self->sd == NULL) {
        croak("Security descriptor not initialized");
    }
    if (self->domain_sid == NULL) {
        croak("Domain SID not initialized");
    }

    status = security_descriptor_dacl_add(self->sd, &ace->ace);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to add DACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

void
sdPtr_DESTROY(self)
    Descriptor *self
CODE:
    talloc_free(self->mem_ctx);
