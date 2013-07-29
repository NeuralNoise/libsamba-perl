#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "util/data_blob.h"

#include "samba-descriptor.h"

#include "const-c.inc"

/*
  return a blank security descriptor (no owners, dacl or sacl)
*/
struct security_descriptor *security_descriptor_initialise(TALLOC_CTX *mem_ctx) 
{
        struct security_descriptor *sd;

        sd = talloc(mem_ctx, struct security_descriptor);
        if (!sd) {
                return NULL;
        }

        sd->revision = SD_REVISION;
        /* we mark as self relative, even though it isn't while it remains
           a pointer in memory because this simplifies the ndr code later.
           All SDs that we store/emit are in fact SELF_RELATIVE
        */
        sd->type = SEC_DESC_SELF_RELATIVE;

        sd->owner_sid = NULL;
        sd->group_sid = NULL;
        sd->sacl = NULL;
        sd->dacl = NULL;

        return sd;
}

MODULE = Samba::Security::Descriptor    PACKAGE = Samba::Security::Descriptor
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

Descriptor *
new(class)
    SV *class
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    struct security_descriptor *sd = NULL;
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

    sd = security_descriptor_initialise(mem_ctx);
    if (sd == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating security descriptor", __func__);
        XSRETURN_UNDEF;
    }

    self->mem_ctx = mem_ctx;
    self->sd = sd;

    RETVAL = self;
OUTPUT:
    RETVAL

MODULE = Samba::Security::Descriptor    PACKAGE = DescriptorPtr     PREFIX=sdPtr_

void
sdPtr_DESTROY(self)
    Descriptor *self
CODE:
    talloc_free(self->mem_ctx);

