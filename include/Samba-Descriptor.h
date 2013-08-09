#ifndef __SAMBA_DESCRIPTOR_H__
#define __SAMBA_DESCRIPTOR_H__

#include <talloc.h>
#include <gen_ndr/security.h>

typedef struct {
    TALLOC_CTX *mem_ctx;
    struct security_descriptor *sd;
    struct dom_sid *domain_sid;
} Descriptor;

#endif
