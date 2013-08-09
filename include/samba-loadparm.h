#ifndef __SAMBA_LOADPARM_H__
#define __SAMBA_LOADPARM_H__

#include <talloc.h>
#include <param.h>

typedef struct {
    TALLOC_CTX *mem_ctx;
    struct loadparm_context *lp_ctx;
} LoadParm;

#endif
