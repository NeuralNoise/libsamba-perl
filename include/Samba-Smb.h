#ifndef __SAMBA_SMB_H__
#define __SAMBA_SMB_H__

#include <talloc.h>
#include <tevent.h>

typedef struct {
    struct TALLOC_CTX *mem_ctx;
    struct tevent_context *ev_ctx;
    struct smbcli_tree *tree;
} Smb;

#endif
