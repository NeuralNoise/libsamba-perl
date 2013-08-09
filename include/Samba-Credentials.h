#ifndef __SAMBA_CREDENTIALS_H__
#define __SAMBA_CREDENTIALS_H__

#include <talloc.h>
#include <credentials.h>
#include <Samba-LoadParm.h>

typedef struct {
    TALLOC_CTX *mem_ctx;
    struct cli_credentials *ccreds;
    LoadParm *lp;
} Credentials;

#endif
