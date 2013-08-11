#ifndef __SAMBA_ACE_H__
#define __SAMBA_ACE_H__

#include <talloc.h>
#include <gen_ndr/security.h>

typedef struct {
    struct security_ace ace;
} AccessControlEntryCtx;

#endif
