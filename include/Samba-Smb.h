#ifndef __SAMBA_SMB_H__
#define __SAMBA_SMB_H__

#include <talloc.h>
#include <tevent.h>

struct loadparm_context;
struct cli_credentials;
struct smbcli_tree;

typedef struct {
    struct TALLOC_CTX *mem_ctx;
    struct tevent_context *ev_ctx;
    struct smbcli_tree *tree;
    struct loadparm_context *lp_ctx;
    struct cli_credentials *creds;
} SmbCtx;

#endif
