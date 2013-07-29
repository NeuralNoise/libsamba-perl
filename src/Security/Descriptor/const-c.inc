#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_12 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SECINFO_DACL SECINFO_SACL SEC_ADS_LIST SEC_DIR_LIST SEC_FILE_ALL */
  /* Offset 6 gives the best switch position.  */
  switch (name[6]) {
  case 'L':
    if (memEQ(name, "SEC_FILE_ALL", 12)) {
    /*                     ^            */
#ifdef SEC_FILE_ALL
      *iv_return = SEC_FILE_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SECINFO_DACL", 12)) {
    /*                     ^            */
#ifdef SECINFO_DACL
      *iv_return = SECINFO_DACL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SECINFO_SACL", 12)) {
    /*                     ^            */
#ifdef SECINFO_SACL
      *iv_return = SECINFO_SACL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_DIR_LIST", 12)) {
    /*                     ^            */
#ifdef SEC_DIR_LIST
      *iv_return = SEC_DIR_LIST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_ADS_LIST", 12)) {
    /*                     ^            */
#ifdef SEC_ADS_LIST
      *iv_return = SEC_ADS_LIST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_13 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SECINFO_GROUP SECINFO_LABEL SECINFO_OWNER */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'L':
    if (memEQ(name, "SECINFO_LABE", 12)) {
    /*                           L      */
#ifdef SECINFO_LABEL
      *iv_return = SECINFO_LABEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "SECINFO_GROU", 12)) {
    /*                           P      */
#ifdef SECINFO_GROUP
      *iv_return = SECINFO_GROUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SECINFO_OWNE", 12)) {
    /*                           R      */
#ifdef SECINFO_OWNER
      *iv_return = SECINFO_OWNER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_14 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DOMAIN_RID_DCS SEC_MASK_FLAGS SEC_PRIV_DEBUG SEC_REG_NOTIFY SEC_STD_DELETE
     */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'A':
    if (memEQ(name, "SEC_MASK_FLAGS", 14)) {
    /*                          ^         */
#ifdef SEC_MASK_FLAGS
      *iv_return = SEC_MASK_FLAGS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "SEC_PRIV_DEBUG", 14)) {
    /*                          ^         */
#ifdef SEC_PRIV_DEBUG
      *iv_return = SEC_PRIV_DEBUG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "DOMAIN_RID_DCS", 14)) {
    /*                          ^         */
#ifdef DOMAIN_RID_DCS
      *iv_return = DOMAIN_RID_DCS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_STD_DELETE", 14)) {
    /*                          ^         */
#ifdef SEC_STD_DELETE
      *iv_return = SEC_STD_DELETE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_REG_NOTIFY", 14)) {
    /*                          ^         */
#ifdef SEC_REG_NOTIFY
      *iv_return = SEC_REG_NOTIFY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_15 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SEC_DIR_READ_EA SEC_GENERIC_ALL SEC_PRIV_BACKUP SEC_PRIV_UNDOCK */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'A':
    if (memEQ(name, "SEC_DIR_READ_E", 14)) {
    /*                             A      */
#ifdef SEC_DIR_READ_EA
      *iv_return = SEC_DIR_READ_EA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "SEC_PRIV_UNDOC", 14)) {
    /*                             K      */
#ifdef SEC_PRIV_UNDOCK
      *iv_return = SEC_PRIV_UNDOCK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SEC_GENERIC_AL", 14)) {
    /*                             L      */
#ifdef SEC_GENERIC_ALL
      *iv_return = SEC_GENERIC_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "SEC_PRIV_BACKU", 14)) {
    /*                             P      */
#ifdef SEC_PRIV_BACKUP
      *iv_return = SEC_PRIV_BACKUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DOMAIN_RID_GUEST DOMAIN_RID_LOGON DOMAIN_RID_USERS NT4_ACL_REVISION
     SEC_DIR_ADD_FILE SEC_DIR_TRAVERSE SEC_DIR_WRITE_EA SEC_FILE_EXECUTE
     SEC_FILE_READ_EA SEC_GENERIC_READ SEC_MASK_GENERIC SEC_MASK_INVALID
     SEC_PRIV_INVALID SEC_PRIV_RESTORE SEC_STD_REQUIRED */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'A':
    if (memEQ(name, "SEC_MASK_INVALID", 16)) {
    /*                           ^          */
#ifdef SEC_MASK_INVALID
      *iv_return = SEC_MASK_INVALID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_INVALID", 16)) {
    /*                           ^          */
#ifdef SEC_PRIV_INVALID
      *iv_return = SEC_PRIV_INVALID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "SEC_FILE_EXECUTE", 16)) {
    /*                           ^          */
#ifdef SEC_FILE_EXECUTE
      *iv_return = SEC_FILE_EXECUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SEC_FILE_READ_EA", 16)) {
    /*                           ^          */
#ifdef SEC_FILE_READ_EA
      *iv_return = SEC_FILE_READ_EA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_DIR_TRAVERSE", 16)) {
    /*                           ^          */
#ifdef SEC_DIR_TRAVERSE
      *iv_return = SEC_DIR_TRAVERSE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DIR_WRITE_EA", 16)) {
    /*                           ^          */
#ifdef SEC_DIR_WRITE_EA
      *iv_return = SEC_DIR_WRITE_EA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_MASK_GENERIC", 16)) {
    /*                           ^          */
#ifdef SEC_MASK_GENERIC
      *iv_return = SEC_MASK_GENERIC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SEC_DIR_ADD_FILE", 16)) {
    /*                           ^          */
#ifdef SEC_DIR_ADD_FILE
      *iv_return = SEC_DIR_ADD_FILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_STD_REQUIRED", 16)) {
    /*                           ^          */
#ifdef SEC_STD_REQUIRED
      *iv_return = SEC_STD_REQUIRED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "DOMAIN_RID_LOGON", 16)) {
    /*                           ^          */
#ifdef DOMAIN_RID_LOGON
      *iv_return = DOMAIN_RID_LOGON;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_GENERIC_READ", 16)) {
    /*                           ^          */
#ifdef SEC_GENERIC_READ
      *iv_return = SEC_GENERIC_READ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "DOMAIN_RID_USERS", 16)) {
    /*                           ^          */
#ifdef DOMAIN_RID_USERS
      *iv_return = DOMAIN_RID_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "NT4_ACL_REVISION", 16)) {
    /*                           ^          */
#ifdef NT4_ACL_REVISION
      *iv_return = NT4_ACL_REVISION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SEC_PRIV_RESTORE", 16)) {
    /*                           ^          */
#ifdef SEC_PRIV_RESTORE
      *iv_return = SEC_PRIV_RESTORE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "DOMAIN_RID_GUEST", 16)) {
    /*                           ^          */
#ifdef DOMAIN_RID_GUEST
      *iv_return = DOMAIN_RID_GUEST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_17 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_USERS DOMAIN_RID_ADMINS DOMAIN_RID_GUESTS DOMAIN_RID_KRBTGT
     SEC_ADS_READ_PROP SEC_FILE_WRITE_EA SEC_GENERIC_WRITE SEC_MASK_SPECIFIC
     SEC_MASK_STANDARD SEC_PRIV_SECURITY SEC_PRIV_SHUTDOWN SEC_REG_SET_VALUE
     SEC_STD_WRITE_DAC */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'A':
    if (memEQ(name, "SEC_MASK_STANDARD", 17)) {
    /*                             ^         */
#ifdef SEC_MASK_STANDARD
      *iv_return = SEC_MASK_STANDARD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SEC_STD_WRITE_DAC", 17)) {
    /*                             ^         */
#ifdef SEC_STD_WRITE_DAC
      *iv_return = SEC_STD_WRITE_DAC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "BUILTIN_RID_USERS", 17)) {
    /*                             ^         */
#ifdef BUILTIN_RID_USERS
      *iv_return = BUILTIN_RID_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SEC_MASK_SPECIFIC", 17)) {
    /*                             ^         */
#ifdef SEC_MASK_SPECIFIC
      *iv_return = SEC_MASK_SPECIFIC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "DOMAIN_RID_ADMINS", 17)) {
    /*                             ^         */
#ifdef DOMAIN_RID_ADMINS
      *iv_return = DOMAIN_RID_ADMINS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_GENERIC_WRITE", 17)) {
    /*                             ^         */
#ifdef SEC_GENERIC_WRITE
      *iv_return = SEC_GENERIC_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_SECURITY", 17)) {
    /*                             ^         */
#ifdef SEC_PRIV_SECURITY
      *iv_return = SEC_PRIV_SECURITY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SEC_REG_SET_VALUE", 17)) {
    /*                             ^         */
#ifdef SEC_REG_SET_VALUE
      *iv_return = SEC_REG_SET_VALUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SEC_PRIV_SHUTDOWN", 17)) {
    /*                             ^         */
#ifdef SEC_PRIV_SHUTDOWN
      *iv_return = SEC_PRIV_SHUTDOWN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_ADS_READ_PROP", 17)) {
    /*                             ^         */
#ifdef SEC_ADS_READ_PROP
      *iv_return = SEC_ADS_READ_PROP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "DOMAIN_RID_GUESTS", 17)) {
    /*                             ^         */
#ifdef DOMAIN_RID_GUESTS
      *iv_return = DOMAIN_RID_GUESTS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "DOMAIN_RID_KRBTGT", 17)) {
    /*                             ^         */
#ifdef DOMAIN_RID_KRBTGT
      *iv_return = DOMAIN_RID_KRBTGT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SEC_FILE_WRITE_EA", 17)) {
    /*                             ^         */
#ifdef SEC_FILE_WRITE_EA
      *iv_return = SEC_FILE_WRITE_EA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_GUESTS SEC_ADS_SELF_WRITE SEC_ADS_WRITE_PROP
     SEC_DIR_ADD_SUBDIR SEC_FILE_READ_DATA SEC_PRIV_ADD_USERS
     SEC_PRIV_DEBUG_BIT SEC_RIGHTS_DIR_ALL */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'A':
    if (memEQ(name, "SEC_FILE_READ_DATA", 18)) {
    /*                              ^         */
#ifdef SEC_FILE_READ_DATA
      *iv_return = SEC_FILE_READ_DATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_RIGHTS_DIR_ALL", 18)) {
    /*                              ^         */
#ifdef SEC_RIGHTS_DIR_ALL
      *iv_return = SEC_RIGHTS_DIR_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "SEC_PRIV_DEBUG_BIT", 18)) {
    /*                              ^         */
#ifdef SEC_PRIV_DEBUG_BIT
      *iv_return = SEC_PRIV_DEBUG_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SEC_DIR_ADD_SUBDIR", 18)) {
    /*                              ^         */
#ifdef SEC_DIR_ADD_SUBDIR
      *iv_return = SEC_DIR_ADD_SUBDIR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_PRIV_ADD_USERS", 18)) {
    /*                              ^         */
#ifdef SEC_PRIV_ADD_USERS
      *iv_return = SEC_PRIV_ADD_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_ADS_SELF_WRITE", 18)) {
    /*                              ^         */
#ifdef SEC_ADS_SELF_WRITE
      *iv_return = SEC_ADS_SELF_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_ADS_WRITE_PROP", 18)) {
    /*                              ^         */
#ifdef SEC_ADS_WRITE_PROP
      *iv_return = SEC_ADS_WRITE_PROP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "BUILTIN_RID_GUESTS", 18)) {
    /*                              ^         */
#ifdef BUILTIN_RID_GUESTS
      *iv_return = BUILTIN_RID_GUESTS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LSA_POLICY_MODE_ALL SEC_ADS_DELETE_TREE SEC_ADS_GENERIC_ALL
     SEC_ADS_LIST_OBJECT SEC_FILE_WRITE_DATA SEC_GENERIC_EXECUTE
     SEC_PRIV_BACKUP_BIT SEC_PRIV_SYSTEMTIME SEC_PRIV_UNDOCK_BIT
     SEC_REG_CREATE_LINK SEC_REG_QUERY_VALUE SEC_RIGHTS_DIR_READ
     SEC_RIGHTS_FILE_ALL SEC_STD_SYNCHRONIZE SEC_STD_WRITE_OWNER */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'A':
    if (memEQ(name, "SEC_REG_CREATE_LINK", 19)) {
    /*                          ^              */
#ifdef SEC_REG_CREATE_LINK
      *iv_return = SEC_REG_CREATE_LINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "SEC_PRIV_BACKUP_BIT", 19)) {
    /*                          ^              */
#ifdef SEC_PRIV_BACKUP_BIT
      *iv_return = SEC_PRIV_BACKUP_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_STD_SYNCHRONIZE", 19)) {
    /*                          ^              */
#ifdef SEC_STD_SYNCHRONIZE
      *iv_return = SEC_STD_SYNCHRONIZE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SEC_PRIV_UNDOCK_BIT", 19)) {
    /*                          ^              */
#ifdef SEC_PRIV_UNDOCK_BIT
      *iv_return = SEC_PRIV_UNDOCK_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_RIGHTS_DIR_READ", 19)) {
    /*                          ^              */
#ifdef SEC_RIGHTS_DIR_READ
      *iv_return = SEC_RIGHTS_DIR_READ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_ADS_DELETE_TREE", 19)) {
    /*                          ^              */
#ifdef SEC_ADS_DELETE_TREE
      *iv_return = SEC_ADS_DELETE_TREE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_ADS_GENERIC_ALL", 19)) {
    /*                          ^              */
#ifdef SEC_ADS_GENERIC_ALL
      *iv_return = SEC_ADS_GENERIC_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SEC_RIGHTS_FILE_ALL", 19)) {
    /*                          ^              */
#ifdef SEC_RIGHTS_FILE_ALL
      *iv_return = SEC_RIGHTS_FILE_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_FILE_WRITE_DATA", 19)) {
    /*                          ^              */
#ifdef SEC_FILE_WRITE_DATA
      *iv_return = SEC_FILE_WRITE_DATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "LSA_POLICY_MODE_ALL", 19)) {
    /*                          ^              */
#ifdef LSA_POLICY_MODE_ALL
      *iv_return = LSA_POLICY_MODE_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_REG_QUERY_VALUE", 19)) {
    /*                          ^              */
#ifdef SEC_REG_QUERY_VALUE
      *iv_return = SEC_REG_QUERY_VALUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_PRIV_SYSTEMTIME", 19)) {
    /*                          ^              */
#ifdef SEC_PRIV_SYSTEMTIME
      *iv_return = SEC_PRIV_SYSTEMTIME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SEC_ADS_LIST_OBJECT", 19)) {
    /*                          ^              */
#ifdef SEC_ADS_LIST_OBJECT
      *iv_return = SEC_ADS_LIST_OBJECT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_STD_WRITE_OWNER", 19)) {
    /*                          ^              */
#ifdef SEC_STD_WRITE_OWNER
      *iv_return = SEC_STD_WRITE_OWNER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SEC_GENERIC_EXECUTE", 19)) {
    /*                          ^              */
#ifdef SEC_GENERIC_EXECUTE
      *iv_return = SEC_GENERIC_EXECUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_20 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DOMAIN_RID_RODC_DENY SEC_ADS_CREATE_CHILD SEC_ADS_DELETE_CHILD
     SEC_ADS_GENERIC_READ SEC_DIR_DELETE_CHILD SEC_FILE_APPEND_DATA
     SEC_PRIV_IMPERSONATE SEC_PRIV_LOAD_DRIVER SEC_PRIV_RESTORE_BIT
     SEC_REG_ENUM_SUBKEYS SEC_RIGHTS_DIR_WRITE SEC_RIGHTS_FILE_READ
     SEC_STD_READ_CONTROL */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'C':
    if (memEQ(name, "SEC_STD_READ_CONTROL", 20)) {
    /*                            ^             */
#ifdef SEC_STD_READ_CONTROL
      *iv_return = SEC_STD_READ_CONTROL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "DOMAIN_RID_RODC_DENY", 20)) {
    /*                            ^             */
#ifdef DOMAIN_RID_RODC_DENY
      *iv_return = DOMAIN_RID_RODC_DENY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_ADS_CREATE_CHILD", 20)) {
    /*                            ^             */
#ifdef SEC_ADS_CREATE_CHILD
      *iv_return = SEC_ADS_CREATE_CHILD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_ADS_DELETE_CHILD", 20)) {
    /*                            ^             */
#ifdef SEC_ADS_DELETE_CHILD
      *iv_return = SEC_ADS_DELETE_CHILD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DIR_DELETE_CHILD", 20)) {
    /*                            ^             */
#ifdef SEC_DIR_DELETE_CHILD
      *iv_return = SEC_DIR_DELETE_CHILD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_ADS_GENERIC_READ", 20)) {
    /*                            ^             */
#ifdef SEC_ADS_GENERIC_READ
      *iv_return = SEC_ADS_GENERIC_READ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SEC_RIGHTS_FILE_READ", 20)) {
    /*                            ^             */
#ifdef SEC_RIGHTS_FILE_READ
      *iv_return = SEC_RIGHTS_FILE_READ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SEC_FILE_APPEND_DATA", 20)) {
    /*                            ^             */
#ifdef SEC_FILE_APPEND_DATA
      *iv_return = SEC_FILE_APPEND_DATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SEC_PRIV_RESTORE_BIT", 20)) {
    /*                            ^             */
#ifdef SEC_PRIV_RESTORE_BIT
      *iv_return = SEC_PRIV_RESTORE_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_PRIV_IMPERSONATE", 20)) {
    /*                            ^             */
#ifdef SEC_PRIV_IMPERSONATE
      *iv_return = SEC_PRIV_IMPERSONATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_RIGHTS_DIR_WRITE", 20)) {
    /*                            ^             */
#ifdef SEC_RIGHTS_DIR_WRITE
      *iv_return = SEC_RIGHTS_DIR_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_REG_ENUM_SUBKEYS", 20)) {
    /*                            ^             */
#ifdef SEC_REG_ENUM_SUBKEYS
      *iv_return = SEC_REG_ENUM_SUBKEYS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SEC_PRIV_LOAD_DRIVER", 20)) {
    /*                            ^             */
#ifdef SEC_PRIV_LOAD_DRIVER
      *iv_return = SEC_PRIV_LOAD_DRIVER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DOMAIN_RID_RODC_ALLOW LSA_POLICY_MODE_BATCH LSA_POLICY_MODE_PROXY
     SEC_ADS_GENERIC_WRITE SEC_DACL_AUTO_INHERIT SEC_DESC_DACL_PRESENT
     SEC_DESC_DACL_TRUSTED SEC_DESC_SACL_PRESENT SEC_GROUP_FROM_PARENT
     SEC_OWNER_FROM_PARENT SEC_PRIV_SECURITY_BIT SEC_PRIV_SHUTDOWN_BIT
     SEC_REG_CREATE_SUBKEY SEC_RIGHTS_FILE_WRITE SEC_SACL_AUTO_INHERIT */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case 'A':
    if (memEQ(name, "DOMAIN_RID_RODC_ALLOW", 21)) {
    /*                               ^           */
#ifdef DOMAIN_RID_RODC_ALLOW
      *iv_return = DOMAIN_RID_RODC_ALLOW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_GROUP_FROM_PARENT", 21)) {
    /*                               ^           */
#ifdef SEC_GROUP_FROM_PARENT
      *iv_return = SEC_GROUP_FROM_PARENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_OWNER_FROM_PARENT", 21)) {
    /*                               ^           */
#ifdef SEC_OWNER_FROM_PARENT
      *iv_return = SEC_OWNER_FROM_PARENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "LSA_POLICY_MODE_BATCH", 21)) {
    /*                               ^           */
#ifdef LSA_POLICY_MODE_BATCH
      *iv_return = LSA_POLICY_MODE_BATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_DESC_DACL_PRESENT", 21)) {
    /*                               ^           */
#ifdef SEC_DESC_DACL_PRESENT
      *iv_return = SEC_DESC_DACL_PRESENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DESC_SACL_PRESENT", 21)) {
    /*                               ^           */
#ifdef SEC_DESC_SACL_PRESENT
      *iv_return = SEC_DESC_SACL_PRESENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "SEC_DACL_AUTO_INHERIT", 21)) {
    /*                               ^           */
#ifdef SEC_DACL_AUTO_INHERIT
      *iv_return = SEC_DACL_AUTO_INHERIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_SACL_AUTO_INHERIT", 21)) {
    /*                               ^           */
#ifdef SEC_SACL_AUTO_INHERIT
      *iv_return = SEC_SACL_AUTO_INHERIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SEC_PRIV_SHUTDOWN_BIT", 21)) {
    /*                               ^           */
#ifdef SEC_PRIV_SHUTDOWN_BIT
      *iv_return = SEC_PRIV_SHUTDOWN_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "LSA_POLICY_MODE_PROXY", 21)) {
    /*                               ^           */
#ifdef LSA_POLICY_MODE_PROXY
      *iv_return = LSA_POLICY_MODE_PROXY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SEC_DESC_DACL_TRUSTED", 21)) {
    /*                               ^           */
#ifdef SEC_DESC_DACL_TRUSTED
      *iv_return = SEC_DESC_DACL_TRUSTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_REG_CREATE_SUBKEY", 21)) {
    /*                               ^           */
#ifdef SEC_REG_CREATE_SUBKEY
      *iv_return = SEC_REG_CREATE_SUBKEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'W':
    if (memEQ(name, "SEC_ADS_GENERIC_WRITE", 21)) {
    /*                               ^           */
#ifdef SEC_ADS_GENERIC_WRITE
      *iv_return = SEC_ADS_GENERIC_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_RIGHTS_FILE_WRITE", 21)) {
    /*                               ^           */
#ifdef SEC_RIGHTS_FILE_WRITE
      *iv_return = SEC_RIGHTS_FILE_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "SEC_PRIV_SECURITY_BIT", 21)) {
    /*                               ^           */
#ifdef SEC_PRIV_SECURITY_BIT
      *iv_return = SEC_PRIV_SECURITY_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_REPLICATOR DOMAIN_RID_CERT_ADMINS DOMAIN_RID_RAS_SERVERS
     SECINFO_PROTECTED_DACL SECINFO_PROTECTED_SACL SEC_ADS_CONTROL_ACCESS
     SEC_ADS_GENERIC_ALL_DS SEC_DEFAULT_DESCRIPTOR SEC_DESC_SELF_RELATIVE
     SEC_DIR_READ_ATTRIBUTE SEC_PRIV_ADD_USERS_BIT SEC_PRIV_CHANGE_NOTIFY
     SEC_PRIV_CREATE_GLOBAL SEC_PRIV_DISK_OPERATOR SEC_PRIV_MANAGE_VOLUME
     SEC_RIGHTS_DIR_EXECUTE SEC_RIGHTS_PRIV_BACKUP */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'A':
    if (memEQ(name, "SEC_PRIV_CREATE_GLOBAL", 22)) {
    /*                                   ^        */
#ifdef SEC_PRIV_CREATE_GLOBAL
      *iv_return = SEC_PRIV_CREATE_GLOBAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "SECINFO_PROTECTED_DACL", 22)) {
    /*                                   ^        */
#ifdef SECINFO_PROTECTED_DACL
      *iv_return = SECINFO_PROTECTED_DACL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SECINFO_PROTECTED_SACL", 22)) {
    /*                                   ^        */
#ifdef SECINFO_PROTECTED_SACL
      *iv_return = SECINFO_PROTECTED_SACL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SEC_ADS_GENERIC_ALL_DS", 22)) {
    /*                                   ^        */
#ifdef SEC_ADS_GENERIC_ALL_DS
      *iv_return = SEC_ADS_GENERIC_ALL_DS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SEC_PRIV_CHANGE_NOTIFY", 22)) {
    /*                                   ^        */
#ifdef SEC_PRIV_CHANGE_NOTIFY
      *iv_return = SEC_PRIV_CHANGE_NOTIFY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_PRIV_ADD_USERS_BIT", 22)) {
    /*                                   ^        */
#ifdef SEC_PRIV_ADD_USERS_BIT
      *iv_return = SEC_PRIV_ADD_USERS_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "SEC_PRIV_MANAGE_VOLUME", 22)) {
    /*                                   ^        */
#ifdef SEC_PRIV_MANAGE_VOLUME
      *iv_return = SEC_PRIV_MANAGE_VOLUME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "DOMAIN_RID_CERT_ADMINS", 22)) {
    /*                                   ^        */
#ifdef DOMAIN_RID_CERT_ADMINS
      *iv_return = DOMAIN_RID_CERT_ADMINS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "BUILTIN_RID_REPLICATOR", 22)) {
    /*                                   ^        */
#ifdef BUILTIN_RID_REPLICATOR
      *iv_return = BUILTIN_RID_REPLICATOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DEFAULT_DESCRIPTOR", 22)) {
    /*                                   ^        */
#ifdef SEC_DEFAULT_DESCRIPTOR
      *iv_return = SEC_DEFAULT_DESCRIPTOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_DISK_OPERATOR", 22)) {
    /*                                   ^        */
#ifdef SEC_PRIV_DISK_OPERATOR
      *iv_return = SEC_PRIV_DISK_OPERATOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "DOMAIN_RID_RAS_SERVERS", 22)) {
    /*                                   ^        */
#ifdef DOMAIN_RID_RAS_SERVERS
      *iv_return = DOMAIN_RID_RAS_SERVERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_ADS_CONTROL_ACCESS", 22)) {
    /*                                   ^        */
#ifdef SEC_ADS_CONTROL_ACCESS
      *iv_return = SEC_ADS_CONTROL_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SEC_DIR_READ_ATTRIBUTE", 22)) {
    /*                                   ^        */
#ifdef SEC_DIR_READ_ATTRIBUTE
      *iv_return = SEC_DIR_READ_ATTRIBUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_RIGHTS_DIR_EXECUTE", 22)) {
    /*                                   ^        */
#ifdef SEC_RIGHTS_DIR_EXECUTE
      *iv_return = SEC_RIGHTS_DIR_EXECUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SEC_RIGHTS_PRIV_BACKUP", 22)) {
    /*                                   ^        */
#ifdef SEC_RIGHTS_PRIV_BACKUP
      *iv_return = SEC_RIGHTS_PRIV_BACKUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "SEC_DESC_SELF_RELATIVE", 22)) {
    /*                                   ^        */
#ifdef SEC_DESC_SELF_RELATIVE
      *iv_return = SEC_DESC_SELF_RELATIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_AUTH_ACCESS BUILTIN_RID_POWER_USERS BUILTIN_RID_RAS_SERVERS
     DOMAIN_RID_READONLY_DCS LSA_POLICY_MODE_ALL_NT4 LSA_POLICY_MODE_NETWORK
     LSA_POLICY_MODE_SERVICE SEC_ADS_GENERIC_EXECUTE SEC_DESC_DACL_DEFAULTED
     SEC_DESC_DACL_PROTECTED SEC_DESC_SACL_DEFAULTED SEC_DESC_SACL_PROTECTED
     SEC_DIR_WRITE_ATTRIBUTE SEC_FILE_READ_ATTRIBUTE SEC_PRIV_INCREASE_QUOTA
     SEC_PRIV_PRINT_OPERATOR SEC_PRIV_SYSTEMTIME_BIT SEC_PRIV_SYSTEM_PROFILE
     SEC_PRIV_TAKE_OWNERSHIP SEC_RIGHTS_FILE_EXECUTE SEC_RIGHTS_PRIV_RESTORE */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'A':
    if (memEQ(name, "SEC_DIR_WRITE_ATTRIBUTE", 23)) {
    /*                             ^               */
#ifdef SEC_DIR_WRITE_ATTRIBUTE
      *iv_return = SEC_DIR_WRITE_ATTRIBUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_FILE_READ_ATTRIBUTE", 23)) {
    /*                             ^               */
#ifdef SEC_FILE_READ_ATTRIBUTE
      *iv_return = SEC_FILE_READ_ATTRIBUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_INCREASE_QUOTA", 23)) {
    /*                             ^               */
#ifdef SEC_PRIV_INCREASE_QUOTA
      *iv_return = SEC_PRIV_INCREASE_QUOTA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "SEC_ADS_GENERIC_EXECUTE", 23)) {
    /*                             ^               */
#ifdef SEC_ADS_GENERIC_EXECUTE
      *iv_return = SEC_ADS_GENERIC_EXECUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "DOMAIN_RID_READONLY_DCS", 23)) {
    /*                             ^               */
#ifdef DOMAIN_RID_READONLY_DCS
      *iv_return = DOMAIN_RID_READONLY_DCS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DESC_DACL_DEFAULTED", 23)) {
    /*                             ^               */
#ifdef SEC_DESC_DACL_DEFAULTED
      *iv_return = SEC_DESC_DACL_DEFAULTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DESC_SACL_DEFAULTED", 23)) {
    /*                             ^               */
#ifdef SEC_DESC_SACL_DEFAULTED
      *iv_return = SEC_DESC_SACL_DEFAULTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LSA_POLICY_MODE_ALL_NT4", 23)) {
    /*                             ^               */
#ifdef LSA_POLICY_MODE_ALL_NT4
      *iv_return = LSA_POLICY_MODE_ALL_NT4;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LSA_POLICY_MODE_NETWORK", 23)) {
    /*                             ^               */
#ifdef LSA_POLICY_MODE_NETWORK
      *iv_return = LSA_POLICY_MODE_NETWORK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LSA_POLICY_MODE_SERVICE", 23)) {
    /*                             ^               */
#ifdef LSA_POLICY_MODE_SERVICE
      *iv_return = LSA_POLICY_MODE_SERVICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_RIGHTS_FILE_EXECUTE", 23)) {
    /*                             ^               */
#ifdef SEC_RIGHTS_FILE_EXECUTE
      *iv_return = SEC_RIGHTS_FILE_EXECUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "SEC_PRIV_SYSTEMTIME_BIT", 23)) {
    /*                             ^               */
#ifdef SEC_PRIV_SYSTEMTIME_BIT
      *iv_return = SEC_PRIV_SYSTEMTIME_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_SYSTEM_PROFILE", 23)) {
    /*                             ^               */
#ifdef SEC_PRIV_SYSTEM_PROFILE
      *iv_return = SEC_PRIV_SYSTEM_PROFILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SEC_PRIV_TAKE_OWNERSHIP", 23)) {
    /*                             ^               */
#ifdef SEC_PRIV_TAKE_OWNERSHIP
      *iv_return = SEC_PRIV_TAKE_OWNERSHIP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "SEC_DESC_DACL_PROTECTED", 23)) {
    /*                             ^               */
#ifdef SEC_DESC_DACL_PROTECTED
      *iv_return = SEC_DESC_DACL_PROTECTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DESC_SACL_PROTECTED", 23)) {
    /*                             ^               */
#ifdef SEC_DESC_SACL_PROTECTED
      *iv_return = SEC_DESC_SACL_PROTECTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "BUILTIN_RID_RAS_SERVERS", 23)) {
    /*                             ^               */
#ifdef BUILTIN_RID_RAS_SERVERS
      *iv_return = BUILTIN_RID_RAS_SERVERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "BUILTIN_RID_AUTH_ACCESS", 23)) {
    /*                             ^               */
#ifdef BUILTIN_RID_AUTH_ACCESS
      *iv_return = BUILTIN_RID_AUTH_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "SEC_RIGHTS_PRIV_RESTORE", 23)) {
    /*                             ^               */
#ifdef SEC_RIGHTS_PRIV_RESTORE
      *iv_return = SEC_RIGHTS_PRIV_RESTORE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'W':
    if (memEQ(name, "BUILTIN_RID_POWER_USERS", 23)) {
    /*                             ^               */
#ifdef BUILTIN_RID_POWER_USERS
      *iv_return = BUILTIN_RID_POWER_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SEC_PRIV_PRINT_OPERATOR", 23)) {
    /*                             ^               */
#ifdef SEC_PRIV_PRINT_OPERATOR
      *iv_return = SEC_PRIV_PRINT_OPERATOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DOMAIN_RID_ADMINISTRATOR DOMAIN_RID_POLICY_ADMINS DOMAIN_RID_SCHEMA_ADMINS
     KERB_ENCTYPE_DES_CBC_CRC KERB_ENCTYPE_DES_CBC_MD5 SECINFO_UNPROTECTED_DACL
     SECINFO_UNPROTECTED_SACL SEC_DESC_GROUP_DEFAULTED SEC_DESC_OWNER_DEFAULTED
     SEC_DESC_SERVER_SECURITY SEC_FILE_WRITE_ATTRIBUTE SEC_FLAG_MAXIMUM_ALLOWED
     SEC_FLAG_SYSTEM_SECURITY SEC_PRIV_CREATE_PAGEFILE SEC_PRIV_IMPERSONATE_BIT
     SEC_PRIV_LOAD_DRIVER_BIT SEC_PRIV_MACHINE_ACCOUNT SEC_PRIV_REMOTE_SHUTDOWN
     */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'C':
    if (memEQ(name, "SEC_PRIV_CREATE_PAGEFILE", 24)) {
    /*                        ^                     */
#ifdef SEC_PRIV_CREATE_PAGEFILE
      *iv_return = SEC_PRIV_CREATE_PAGEFILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "DOMAIN_RID_ADMINISTRATOR", 24)) {
    /*                        ^                     */
#ifdef DOMAIN_RID_ADMINISTRATOR
      *iv_return = DOMAIN_RID_ADMINISTRATOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "DOMAIN_RID_POLICY_ADMINS", 24)) {
    /*                        ^                     */
#ifdef DOMAIN_RID_POLICY_ADMINS
      *iv_return = DOMAIN_RID_POLICY_ADMINS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "DOMAIN_RID_SCHEMA_ADMINS", 24)) {
    /*                        ^                     */
#ifdef DOMAIN_RID_SCHEMA_ADMINS
      *iv_return = DOMAIN_RID_SCHEMA_ADMINS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "SEC_DESC_GROUP_DEFAULTED", 24)) {
    /*                        ^                     */
#ifdef SEC_DESC_GROUP_DEFAULTED
      *iv_return = SEC_DESC_GROUP_DEFAULTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SEC_PRIV_IMPERSONATE_BIT", 24)) {
    /*                        ^                     */
#ifdef SEC_PRIV_IMPERSONATE_BIT
      *iv_return = SEC_PRIV_IMPERSONATE_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SEC_PRIV_LOAD_DRIVER_BIT", 24)) {
    /*                        ^                     */
#ifdef SEC_PRIV_LOAD_DRIVER_BIT
      *iv_return = SEC_PRIV_LOAD_DRIVER_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "SEC_FLAG_MAXIMUM_ALLOWED", 24)) {
    /*                        ^                     */
#ifdef SEC_FLAG_MAXIMUM_ALLOWED
      *iv_return = SEC_FLAG_MAXIMUM_ALLOWED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_MACHINE_ACCOUNT", 24)) {
    /*                        ^                     */
#ifdef SEC_PRIV_MACHINE_ACCOUNT
      *iv_return = SEC_PRIV_MACHINE_ACCOUNT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SECINFO_UNPROTECTED_DACL", 24)) {
    /*                        ^                     */
#ifdef SECINFO_UNPROTECTED_DACL
      *iv_return = SECINFO_UNPROTECTED_DACL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SECINFO_UNPROTECTED_SACL", 24)) {
    /*                        ^                     */
#ifdef SECINFO_UNPROTECTED_SACL
      *iv_return = SECINFO_UNPROTECTED_SACL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SEC_DESC_OWNER_DEFAULTED", 24)) {
    /*                        ^                     */
#ifdef SEC_DESC_OWNER_DEFAULTED
      *iv_return = SEC_DESC_OWNER_DEFAULTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_PRIV_REMOTE_SHUTDOWN", 24)) {
    /*                        ^                     */
#ifdef SEC_PRIV_REMOTE_SHUTDOWN
      *iv_return = SEC_PRIV_REMOTE_SHUTDOWN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_DESC_SERVER_SECURITY", 24)) {
    /*                        ^                     */
#ifdef SEC_DESC_SERVER_SECURITY
      *iv_return = SEC_DESC_SERVER_SECURITY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_FLAG_SYSTEM_SECURITY", 24)) {
    /*                        ^                     */
#ifdef SEC_FLAG_SYSTEM_SECURITY
      *iv_return = SEC_FLAG_SYSTEM_SECURITY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'W':
    if (memEQ(name, "SEC_FILE_WRITE_ATTRIBUTE", 24)) {
    /*                        ^                     */
#ifdef SEC_FILE_WRITE_ATTRIBUTE
      *iv_return = SEC_FILE_WRITE_ATTRIBUTE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "KERB_ENCTYPE_DES_CBC_CRC", 24)) {
    /*                        ^                     */
#ifdef KERB_ENCTYPE_DES_CBC_CRC
      *iv_return = KERB_ENCTYPE_DES_CBC_CRC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "KERB_ENCTYPE_DES_CBC_MD5", 24)) {
    /*                        ^                     */
#ifdef KERB_ENCTYPE_DES_CBC_MD5
      *iv_return = KERB_ENCTYPE_DES_CBC_MD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_PERFLOG_USERS BUILTIN_RID_PERFMON_USERS
     BUILTIN_RID_PRE_2K_ACCESS DOMAIN_RID_DOMAIN_MEMBERS
     KERB_ENCTYPE_RC4_HMAC_MD5 SECURITY_ACL_REVISION_ADS
     SECURITY_ACL_REVISION_NT4 SEC_ACE_FLAG_INHERIT_ONLY
     SEC_ACE_TYPE_SYSTEM_ALARM SEC_ACE_TYPE_SYSTEM_AUDIT
     SEC_DESC_RM_CONTROL_VALID */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case '2':
    if (memEQ(name, "BUILTIN_RID_PRE_2K_ACCESS", 25)) {
    /*                               ^               */
#ifdef BUILTIN_RID_PRE_2K_ACCESS
      *iv_return = BUILTIN_RID_PRE_2K_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_ACE_FLAG_INHERIT_ONLY", 25)) {
    /*                               ^               */
#ifdef SEC_ACE_FLAG_INHERIT_ONLY
      *iv_return = SEC_ACE_FLAG_INHERIT_ONLY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SECURITY_ACL_REVISION_ADS", 25)) {
    /*                               ^               */
      *iv_return = SECURITY_ACL_REVISION_ADS;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "SECURITY_ACL_REVISION_NT4", 25)) {
    /*                               ^               */
      *iv_return = SECURITY_ACL_REVISION_NT4;
      return PERL_constant_ISIV;
    }
    break;
  case 'L':
    if (memEQ(name, "BUILTIN_RID_PERFLOG_USERS", 25)) {
    /*                               ^               */
#ifdef BUILTIN_RID_PERFLOG_USERS
      *iv_return = BUILTIN_RID_PERFLOG_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "BUILTIN_RID_PERFMON_USERS", 25)) {
    /*                               ^               */
#ifdef BUILTIN_RID_PERFMON_USERS
      *iv_return = BUILTIN_RID_PERFMON_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "DOMAIN_RID_DOMAIN_MEMBERS", 25)) {
    /*                               ^               */
#ifdef DOMAIN_RID_DOMAIN_MEMBERS
      *iv_return = DOMAIN_RID_DOMAIN_MEMBERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_DESC_RM_CONTROL_VALID", 25)) {
    /*                               ^               */
#ifdef SEC_DESC_RM_CONTROL_VALID
      *iv_return = SEC_DESC_RM_CONTROL_VALID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SEC_ACE_TYPE_SYSTEM_ALARM", 25)) {
    /*                               ^               */
      *iv_return = SEC_ACE_TYPE_SYSTEM_ALARM;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "SEC_ACE_TYPE_SYSTEM_AUDIT", 25)) {
    /*                               ^               */
      *iv_return = SEC_ACE_TYPE_SYSTEM_AUDIT;
      return PERL_constant_ISIV;
    }
    break;
  case '_':
    if (memEQ(name, "KERB_ENCTYPE_RC4_HMAC_MD5", 25)) {
    /*                               ^               */
#ifdef KERB_ENCTYPE_RC4_HMAC_MD5
      *iv_return = KERB_ENCTYPE_RC4_HMAC_MD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_26 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_ADMINISTRATORS LSA_POLICY_MODE_DENY_BATCH
     SEC_ACE_FLAG_FAILED_ACCESS SEC_ACE_FLAG_INHERITED_ACE
     SEC_ACE_FLAG_VALID_INHERIT SEC_ACE_TYPE_ACCESS_DENIED
     SEC_PRIV_CHANGE_NOTIFY_BIT SEC_PRIV_CREATE_GLOBAL_BIT
     SEC_PRIV_DISK_OPERATOR_BIT SEC_PRIV_ENABLE_DELEGATION
     SEC_PRIV_MANAGE_VOLUME_BIT STANDARD_RIGHTS_ALL_ACCESS */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'A':
    if (memEQ(name, "SEC_ACE_FLAG_FAILED_ACCESS", 26)) {
    /*                                   ^            */
#ifdef SEC_ACE_FLAG_FAILED_ACCESS
      *iv_return = SEC_ACE_FLAG_FAILED_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_CREATE_GLOBAL_BIT", 26)) {
    /*                                   ^            */
#ifdef SEC_PRIV_CREATE_GLOBAL_BIT
      *iv_return = SEC_PRIV_CREATE_GLOBAL_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "STANDARD_RIGHTS_ALL_ACCESS", 26)) {
    /*                                   ^            */
#ifdef STANDARD_RIGHTS_ALL_ACCESS
      *iv_return = STANDARD_RIGHTS_ALL_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SEC_ACE_TYPE_ACCESS_DENIED", 26)) {
    /*                                   ^            */
      *iv_return = SEC_ACE_TYPE_ACCESS_DENIED;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_ACE_FLAG_INHERITED_ACE", 26)) {
    /*                                   ^            */
#ifdef SEC_ACE_FLAG_INHERITED_ACE
      *iv_return = SEC_ACE_FLAG_INHERITED_ACE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SEC_PRIV_CHANGE_NOTIFY_BIT", 26)) {
    /*                                   ^            */
#ifdef SEC_PRIV_CHANGE_NOTIFY_BIT
      *iv_return = SEC_PRIV_CHANGE_NOTIFY_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "SEC_PRIV_ENABLE_DELEGATION", 26)) {
    /*                                   ^            */
#ifdef SEC_PRIV_ENABLE_DELEGATION
      *iv_return = SEC_PRIV_ENABLE_DELEGATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "SEC_PRIV_MANAGE_VOLUME_BIT", 26)) {
    /*                                   ^            */
#ifdef SEC_PRIV_MANAGE_VOLUME_BIT
      *iv_return = SEC_PRIV_MANAGE_VOLUME_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SEC_ACE_FLAG_VALID_INHERIT", 26)) {
    /*                                   ^            */
#ifdef SEC_ACE_FLAG_VALID_INHERIT
      *iv_return = SEC_ACE_FLAG_VALID_INHERIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SEC_PRIV_DISK_OPERATOR_BIT", 26)) {
    /*                                   ^            */
#ifdef SEC_PRIV_DISK_OPERATOR_BIT
      *iv_return = SEC_PRIV_DISK_OPERATOR_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "BUILTIN_RID_ADMINISTRATORS", 26)) {
    /*                                   ^            */
#ifdef BUILTIN_RID_ADMINISTRATORS
      *iv_return = BUILTIN_RID_ADMINISTRATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "LSA_POLICY_MODE_DENY_BATCH", 26)) {
    /*                                   ^            */
#ifdef LSA_POLICY_MODE_DENY_BATCH
      *iv_return = LSA_POLICY_MODE_DENY_BATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_27 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_PRINT_OPERATORS LSA_POLICY_MODE_INTERACTIVE
     SEC_ACE_FLAG_OBJECT_INHERIT SEC_ACE_OBJECT_TYPE_PRESENT
     SEC_ACE_TYPE_ACCESS_ALLOWED SEC_PRIV_INCREASE_QUOTA_BIT
     SEC_PRIV_PRINT_OPERATOR_BIT SEC_PRIV_SYSTEM_ENVIRONMENT
     SEC_PRIV_SYSTEM_PROFILE_BIT SEC_PRIV_TAKE_OWNERSHIP_BIT
     STANDARD_RIGHTS_READ_ACCESS */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'C':
    if (memEQ(name, "SEC_ACE_OBJECT_TYPE_PRESENT", 27)) {
    /*                           ^                     */
#ifdef SEC_ACE_OBJECT_TYPE_PRESENT
      *iv_return = SEC_ACE_OBJECT_TYPE_PRESENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_PRIV_TAKE_OWNERSHIP_BIT", 27)) {
    /*                           ^                     */
#ifdef SEC_PRIV_TAKE_OWNERSHIP_BIT
      *iv_return = SEC_PRIV_TAKE_OWNERSHIP_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "STANDARD_RIGHTS_READ_ACCESS", 27)) {
    /*                           ^                     */
#ifdef STANDARD_RIGHTS_READ_ACCESS
      *iv_return = STANDARD_RIGHTS_READ_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SEC_PRIV_PRINT_OPERATOR_BIT", 27)) {
    /*                           ^                     */
#ifdef SEC_PRIV_PRINT_OPERATOR_BIT
      *iv_return = SEC_PRIV_PRINT_OPERATOR_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LSA_POLICY_MODE_INTERACTIVE", 27)) {
    /*                           ^                     */
#ifdef LSA_POLICY_MODE_INTERACTIVE
      *iv_return = LSA_POLICY_MODE_INTERACTIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "BUILTIN_RID_PRINT_OPERATORS", 27)) {
    /*                           ^                     */
#ifdef BUILTIN_RID_PRINT_OPERATORS
      *iv_return = BUILTIN_RID_PRINT_OPERATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SEC_PRIV_INCREASE_QUOTA_BIT", 27)) {
    /*                           ^                     */
#ifdef SEC_PRIV_INCREASE_QUOTA_BIT
      *iv_return = SEC_PRIV_INCREASE_QUOTA_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SEC_PRIV_SYSTEM_ENVIRONMENT", 27)) {
    /*                           ^                     */
#ifdef SEC_PRIV_SYSTEM_ENVIRONMENT
      *iv_return = SEC_PRIV_SYSTEM_ENVIRONMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_SYSTEM_PROFILE_BIT", 27)) {
    /*                           ^                     */
#ifdef SEC_PRIV_SYSTEM_PROFILE_BIT
      *iv_return = SEC_PRIV_SYSTEM_PROFILE_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SEC_ACE_FLAG_OBJECT_INHERIT", 27)) {
    /*                           ^                     */
#ifdef SEC_ACE_FLAG_OBJECT_INHERIT
      *iv_return = SEC_ACE_FLAG_OBJECT_INHERIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_ACE_TYPE_ACCESS_ALLOWED", 27)) {
    /*                           ^                     */
      *iv_return = SEC_ACE_TYPE_ACCESS_ALLOWED;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_28 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_BACKUP_OPERATORS BUILTIN_RID_CRYPTO_OPERATORS
     BUILTIN_RID_SERVER_OPERATORS DOMAIN_RID_ENTERPRISE_ADMINS
     LSA_POLICY_MODE_DENY_NETWORK LSA_POLICY_MODE_DENY_SERVICE
     SEC_DESC_DACL_AUTO_INHERITED SEC_DESC_SACL_AUTO_INHERITED
     SEC_PRIV_CREATE_PAGEFILE_BIT SEC_PRIV_MACHINE_ACCOUNT_BIT
     SEC_PRIV_REMOTE_SHUTDOWN_BIT STANDARD_RIGHTS_WRITE_ACCESS */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'A':
    if (memEQ(name, "SEC_PRIV_CREATE_PAGEFILE_BIT", 28)) {
    /*                           ^                      */
#ifdef SEC_PRIV_CREATE_PAGEFILE_BIT
      *iv_return = SEC_PRIV_CREATE_PAGEFILE_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "BUILTIN_RID_BACKUP_OPERATORS", 28)) {
    /*                           ^                      */
#ifdef BUILTIN_RID_BACKUP_OPERATORS
      *iv_return = BUILTIN_RID_BACKUP_OPERATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "BUILTIN_RID_CRYPTO_OPERATORS", 28)) {
    /*                           ^                      */
#ifdef BUILTIN_RID_CRYPTO_OPERATORS
      *iv_return = BUILTIN_RID_CRYPTO_OPERATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "SEC_PRIV_MACHINE_ACCOUNT_BIT", 28)) {
    /*                           ^                      */
#ifdef SEC_PRIV_MACHINE_ACCOUNT_BIT
      *iv_return = SEC_PRIV_MACHINE_ACCOUNT_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "STANDARD_RIGHTS_WRITE_ACCESS", 28)) {
    /*                           ^                      */
#ifdef STANDARD_RIGHTS_WRITE_ACCESS
      *iv_return = STANDARD_RIGHTS_WRITE_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SEC_DESC_DACL_AUTO_INHERITED", 28)) {
    /*                           ^                      */
#ifdef SEC_DESC_DACL_AUTO_INHERITED
      *iv_return = SEC_DESC_DACL_AUTO_INHERITED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DESC_SACL_AUTO_INHERITED", 28)) {
    /*                           ^                      */
#ifdef SEC_DESC_SACL_AUTO_INHERITED
      *iv_return = SEC_DESC_SACL_AUTO_INHERITED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "DOMAIN_RID_ENTERPRISE_ADMINS", 28)) {
    /*                           ^                      */
#ifdef DOMAIN_RID_ENTERPRISE_ADMINS
      *iv_return = DOMAIN_RID_ENTERPRISE_ADMINS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LSA_POLICY_MODE_DENY_NETWORK", 28)) {
    /*                           ^                      */
#ifdef LSA_POLICY_MODE_DENY_NETWORK
      *iv_return = LSA_POLICY_MODE_DENY_NETWORK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LSA_POLICY_MODE_DENY_SERVICE", 28)) {
    /*                           ^                      */
#ifdef LSA_POLICY_MODE_DENY_SERVICE
      *iv_return = LSA_POLICY_MODE_DENY_SERVICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_PRIV_REMOTE_SHUTDOWN_BIT", 28)) {
    /*                           ^                      */
#ifdef SEC_PRIV_REMOTE_SHUTDOWN_BIT
      *iv_return = SEC_PRIV_REMOTE_SHUTDOWN_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "BUILTIN_RID_SERVER_OPERATORS", 28)) {
    /*                           ^                      */
#ifdef BUILTIN_RID_SERVER_OPERATORS
      *iv_return = BUILTIN_RID_SERVER_OPERATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_29 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_ACCOUNT_OPERATORS BUILTIN_RID_EVENT_LOG_READERS
     SEC_ACE_TYPE_ALLOWED_COMPOUND STANDARD_RIGHTS_MODIFY_ACCESS */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case 'M':
    if (memEQ(name, "STANDARD_RIGHTS_MODIFY_ACCESS", 29)) {
    /*                               ^                   */
#ifdef STANDARD_RIGHTS_MODIFY_ACCESS
      *iv_return = STANDARD_RIGHTS_MODIFY_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SEC_ACE_TYPE_ALLOWED_COMPOUND", 29)) {
    /*                               ^                   */
      *iv_return = SEC_ACE_TYPE_ALLOWED_COMPOUND;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "BUILTIN_RID_EVENT_LOG_READERS", 29)) {
    /*                               ^                   */
#ifdef BUILTIN_RID_EVENT_LOG_READERS
      *iv_return = BUILTIN_RID_EVENT_LOG_READERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "BUILTIN_RID_ACCOUNT_OPERATORS", 29)) {
    /*                               ^                   */
#ifdef BUILTIN_RID_ACCOUNT_OPERATORS
      *iv_return = BUILTIN_RID_ACCOUNT_OPERATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_30 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_TS_LICENSE_SERVERS SECURITY_DESCRIPTOR_REVISION_1
     SEC_ACE_FLAG_CONTAINER_INHERIT SEC_ACE_FLAG_SUCCESSFUL_ACCESS
     SEC_DESC_DACL_AUTO_INHERIT_REQ SEC_DESC_SACL_AUTO_INHERIT_REQ
     SEC_PRIV_ENABLE_DELEGATION_BIT STANDARD_RIGHTS_EXECUTE_ACCESS */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'E':
    if (memEQ(name, "SEC_ACE_FLAG_CONTAINER_INHERIT", 30)) {
    /*                                   ^                */
#ifdef SEC_ACE_FLAG_CONTAINER_INHERIT
      *iv_return = SEC_ACE_FLAG_CONTAINER_INHERIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SEC_ACE_FLAG_SUCCESSFUL_ACCESS", 30)) {
    /*                                   ^                */
#ifdef SEC_ACE_FLAG_SUCCESSFUL_ACCESS
      *iv_return = SEC_ACE_FLAG_SUCCESSFUL_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "SEC_PRIV_ENABLE_DELEGATION_BIT", 30)) {
    /*                                   ^                */
#ifdef SEC_PRIV_ENABLE_DELEGATION_BIT
      *iv_return = SEC_PRIV_ENABLE_DELEGATION_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SEC_DESC_DACL_AUTO_INHERIT_REQ", 30)) {
    /*                                   ^                */
#ifdef SEC_DESC_DACL_AUTO_INHERIT_REQ
      *iv_return = SEC_DESC_DACL_AUTO_INHERIT_REQ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SEC_DESC_SACL_AUTO_INHERIT_REQ", 30)) {
    /*                                   ^                */
#ifdef SEC_DESC_SACL_AUTO_INHERIT_REQ
      *iv_return = SEC_DESC_SACL_AUTO_INHERIT_REQ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SECURITY_DESCRIPTOR_REVISION_1", 30)) {
    /*                                   ^                */
      *iv_return = SECURITY_DESCRIPTOR_REVISION_1;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "BUILTIN_RID_TS_LICENSE_SERVERS", 30)) {
    /*                                   ^                */
#ifdef BUILTIN_RID_TS_LICENSE_SERVERS
      *iv_return = BUILTIN_RID_TS_LICENSE_SERVERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "STANDARD_RIGHTS_EXECUTE_ACCESS", 30)) {
    /*                                   ^                */
#ifdef STANDARD_RIGHTS_EXECUTE_ACCESS
      *iv_return = STANDARD_RIGHTS_EXECUTE_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_31 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SEC_PRIV_INCREASE_BASE_PRIORITY SEC_PRIV_PROFILE_SINGLE_PROCESS
     SEC_PRIV_SYSTEM_ENVIRONMENT_BIT STANDARD_RIGHTS_REQUIRED_ACCESS */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'I':
    if (memEQ(name, "SEC_PRIV_INCREASE_BASE_PRIORITY", 31)) {
    /*                        ^                            */
#ifdef SEC_PRIV_INCREASE_BASE_PRIORITY
      *iv_return = SEC_PRIV_INCREASE_BASE_PRIORITY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "SEC_PRIV_PROFILE_SINGLE_PROCESS", 31)) {
    /*                        ^                            */
#ifdef SEC_PRIV_PROFILE_SINGLE_PROCESS
      *iv_return = SEC_PRIV_PROFILE_SINGLE_PROCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "STANDARD_RIGHTS_REQUIRED_ACCESS", 31)) {
    /*                        ^                            */
#ifdef STANDARD_RIGHTS_REQUIRED_ACCESS
      *iv_return = STANDARD_RIGHTS_REQUIRED_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_PRIV_SYSTEM_ENVIRONMENT_BIT", 31)) {
    /*                        ^                            */
#ifdef SEC_PRIV_SYSTEM_ENVIRONMENT_BIT
      *iv_return = SEC_PRIV_SYSTEM_ENVIRONMENT_BIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_32 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_REMOTE_DESKTOP_USERS LSA_POLICY_MODE_DENY_INTERACTIVE
     SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT */
  /* Offset 21 gives the best switch position.  */
  switch (name[21]) {
  case 'I':
    if (memEQ(name, "LSA_POLICY_MODE_DENY_INTERACTIVE", 32)) {
    /*                                    ^                 */
#ifdef LSA_POLICY_MODE_DENY_INTERACTIVE
      *iv_return = LSA_POLICY_MODE_DENY_INTERACTIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT", 32)) {
    /*                                    ^                 */
      *iv_return = SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "BUILTIN_RID_REMOTE_DESKTOP_USERS", 32)) {
    /*                                    ^                 */
#ifdef BUILTIN_RID_REMOTE_DESKTOP_USERS
      *iv_return = BUILTIN_RID_REMOTE_DESKTOP_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT", 32)) {
    /*                                    ^                 */
      *iv_return = SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_33 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_CERT_SERV_DCOM_ACCESS BUILTIN_RID_DISTRIBUTED_COM_USERS
     BUILTIN_RID_INCOMING_FOREST_TRUST SEC_ACE_FLAG_NO_PROPAGATE_INHERIT
     SEC_ACE_TYPE_ACCESS_DENIED_OBJECT */
  /* Offset 29 gives the best switch position.  */
  switch (name[29]) {
  case 'C':
    if (memEQ(name, "BUILTIN_RID_CERT_SERV_DCOM_ACCESS", 33)) {
    /*                                            ^          */
#ifdef BUILTIN_RID_CERT_SERV_DCOM_ACCESS
      *iv_return = BUILTIN_RID_CERT_SERV_DCOM_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SEC_ACE_FLAG_NO_PROPAGATE_INHERIT", 33)) {
    /*                                            ^          */
#ifdef SEC_ACE_FLAG_NO_PROPAGATE_INHERIT
      *iv_return = SEC_ACE_FLAG_NO_PROPAGATE_INHERIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'J':
    if (memEQ(name, "SEC_ACE_TYPE_ACCESS_DENIED_OBJECT", 33)) {
    /*                                            ^          */
      *iv_return = SEC_ACE_TYPE_ACCESS_DENIED_OBJECT;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "BUILTIN_RID_INCOMING_FOREST_TRUST", 33)) {
    /*                                            ^          */
#ifdef BUILTIN_RID_INCOMING_FOREST_TRUST
      *iv_return = BUILTIN_RID_INCOMING_FOREST_TRUST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "BUILTIN_RID_DISTRIBUTED_COM_USERS", 33)) {
    /*                                            ^          */
#ifdef BUILTIN_RID_DISTRIBUTED_COM_USERS
      *iv_return = BUILTIN_RID_DISTRIBUTED_COM_USERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_34 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     BUILTIN_RID_NETWORK_CONF_OPERATORS DOMAIN_RID_ENTERPRISE_READONLY_DCS
     LSA_POLICY_MODE_REMOTE_INTERACTIVE SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'I':
    if (memEQ(name, "DOMAIN_RID_ENTERPRISE_READONLY_DCS", 34)) {
    /*                                 ^                      */
#ifdef DOMAIN_RID_ENTERPRISE_READONLY_DCS
      *iv_return = DOMAIN_RID_ENTERPRISE_READONLY_DCS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "BUILTIN_RID_NETWORK_CONF_OPERATORS", 34)) {
    /*                                 ^                      */
#ifdef BUILTIN_RID_NETWORK_CONF_OPERATORS
      *iv_return = BUILTIN_RID_NETWORK_CONF_OPERATORS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "LSA_POLICY_MODE_REMOTE_INTERACTIVE", 34)) {
    /*                                 ^                      */
#ifdef LSA_POLICY_MODE_REMOTE_INTERACTIVE
      *iv_return = LSA_POLICY_MODE_REMOTE_INTERACTIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT", 34)) {
    /*                                 ^                      */
      *iv_return = SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(BUILTIN_RID_ACCOUNT_OPERATORS BUILTIN_RID_ADMINISTRATORS
	       BUILTIN_RID_AUTH_ACCESS BUILTIN_RID_BACKUP_OPERATORS
	       BUILTIN_RID_CERT_SERV_DCOM_ACCESS BUILTIN_RID_CRYPTO_OPERATORS
	       BUILTIN_RID_DISTRIBUTED_COM_USERS BUILTIN_RID_EVENT_LOG_READERS
	       BUILTIN_RID_GUESTS BUILTIN_RID_INCOMING_FOREST_TRUST
	       BUILTIN_RID_NETWORK_CONF_OPERATORS BUILTIN_RID_PERFLOG_USERS
	       BUILTIN_RID_PERFMON_USERS BUILTIN_RID_POWER_USERS
	       BUILTIN_RID_PRE_2K_ACCESS BUILTIN_RID_PRINT_OPERATORS
	       BUILTIN_RID_RAS_SERVERS BUILTIN_RID_REMOTE_DESKTOP_USERS
	       BUILTIN_RID_REPLICATOR BUILTIN_RID_SERVER_OPERATORS
	       BUILTIN_RID_TS_LICENSE_SERVERS BUILTIN_RID_USERS
	       DOMAIN_RID_ADMINISTRATOR DOMAIN_RID_ADMINS
	       DOMAIN_RID_CERT_ADMINS DOMAIN_RID_DCS DOMAIN_RID_DOMAIN_MEMBERS
	       DOMAIN_RID_ENTERPRISE_ADMINS DOMAIN_RID_ENTERPRISE_READONLY_DCS
	       DOMAIN_RID_GUEST DOMAIN_RID_GUESTS DOMAIN_RID_KRBTGT
	       DOMAIN_RID_LOGON DOMAIN_RID_POLICY_ADMINS DOMAIN_RID_RAS_SERVERS
	       DOMAIN_RID_READONLY_DCS DOMAIN_RID_RODC_ALLOW
	       DOMAIN_RID_RODC_DENY DOMAIN_RID_SCHEMA_ADMINS DOMAIN_RID_USERS
	       KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
	       KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96 KERB_ENCTYPE_DES_CBC_CRC
	       KERB_ENCTYPE_DES_CBC_MD5 KERB_ENCTYPE_RC4_HMAC_MD5
	       LSA_POLICY_MODE_ALL LSA_POLICY_MODE_ALL_NT4
	       LSA_POLICY_MODE_BATCH LSA_POLICY_MODE_DENY_BATCH
	       LSA_POLICY_MODE_DENY_INTERACTIVE LSA_POLICY_MODE_DENY_NETWORK
	       LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE
	       LSA_POLICY_MODE_DENY_SERVICE LSA_POLICY_MODE_INTERACTIVE
	       LSA_POLICY_MODE_NETWORK LSA_POLICY_MODE_PROXY
	       LSA_POLICY_MODE_REMOTE_INTERACTIVE LSA_POLICY_MODE_SERVICE
	       NT4_ACL_REVISION SD_REVISION SECINFO_DACL SECINFO_GROUP
	       SECINFO_LABEL SECINFO_OWNER SECINFO_PROTECTED_DACL
	       SECINFO_PROTECTED_SACL SECINFO_SACL SECINFO_UNPROTECTED_DACL
	       SECINFO_UNPROTECTED_SACL SEC_ACE_FLAG_CONTAINER_INHERIT
	       SEC_ACE_FLAG_FAILED_ACCESS SEC_ACE_FLAG_INHERITED_ACE
	       SEC_ACE_FLAG_INHERIT_ONLY SEC_ACE_FLAG_NO_PROPAGATE_INHERIT
	       SEC_ACE_FLAG_OBJECT_INHERIT SEC_ACE_FLAG_SUCCESSFUL_ACCESS
	       SEC_ACE_FLAG_VALID_INHERIT SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT
	       SEC_ACE_OBJECT_TYPE_PRESENT SEC_ADS_CONTROL_ACCESS
	       SEC_ADS_CREATE_CHILD SEC_ADS_DELETE_CHILD SEC_ADS_DELETE_TREE
	       SEC_ADS_GENERIC_ALL SEC_ADS_GENERIC_ALL_DS
	       SEC_ADS_GENERIC_EXECUTE SEC_ADS_GENERIC_READ
	       SEC_ADS_GENERIC_WRITE SEC_ADS_LIST SEC_ADS_LIST_OBJECT
	       SEC_ADS_READ_PROP SEC_ADS_SELF_WRITE SEC_ADS_WRITE_PROP
	       SEC_DACL_AUTO_INHERIT SEC_DEFAULT_DESCRIPTOR
	       SEC_DESC_DACL_AUTO_INHERITED SEC_DESC_DACL_AUTO_INHERIT_REQ
	       SEC_DESC_DACL_DEFAULTED SEC_DESC_DACL_PRESENT
	       SEC_DESC_DACL_PROTECTED SEC_DESC_DACL_TRUSTED
	       SEC_DESC_GROUP_DEFAULTED SEC_DESC_OWNER_DEFAULTED
	       SEC_DESC_RM_CONTROL_VALID SEC_DESC_SACL_AUTO_INHERITED
	       SEC_DESC_SACL_AUTO_INHERIT_REQ SEC_DESC_SACL_DEFAULTED
	       SEC_DESC_SACL_PRESENT SEC_DESC_SACL_PROTECTED
	       SEC_DESC_SELF_RELATIVE SEC_DESC_SERVER_SECURITY SEC_DIR_ADD_FILE
	       SEC_DIR_ADD_SUBDIR SEC_DIR_DELETE_CHILD SEC_DIR_LIST
	       SEC_DIR_READ_ATTRIBUTE SEC_DIR_READ_EA SEC_DIR_TRAVERSE
	       SEC_DIR_WRITE_ATTRIBUTE SEC_DIR_WRITE_EA SEC_FILE_ALL
	       SEC_FILE_APPEND_DATA SEC_FILE_EXECUTE SEC_FILE_READ_ATTRIBUTE
	       SEC_FILE_READ_DATA SEC_FILE_READ_EA SEC_FILE_WRITE_ATTRIBUTE
	       SEC_FILE_WRITE_DATA SEC_FILE_WRITE_EA SEC_FLAG_MAXIMUM_ALLOWED
	       SEC_FLAG_SYSTEM_SECURITY SEC_GENERIC_ALL SEC_GENERIC_EXECUTE
	       SEC_GENERIC_READ SEC_GENERIC_WRITE SEC_GROUP_FROM_PARENT
	       SEC_MASK_FLAGS SEC_MASK_GENERIC SEC_MASK_INVALID
	       SEC_MASK_SPECIFIC SEC_MASK_STANDARD SEC_OWNER_FROM_PARENT
	       SEC_PRIV_ADD_USERS SEC_PRIV_ADD_USERS_BIT SEC_PRIV_BACKUP
	       SEC_PRIV_BACKUP_BIT SEC_PRIV_CHANGE_NOTIFY
	       SEC_PRIV_CHANGE_NOTIFY_BIT SEC_PRIV_CREATE_GLOBAL
	       SEC_PRIV_CREATE_GLOBAL_BIT SEC_PRIV_CREATE_PAGEFILE
	       SEC_PRIV_CREATE_PAGEFILE_BIT SEC_PRIV_DEBUG SEC_PRIV_DEBUG_BIT
	       SEC_PRIV_DISK_OPERATOR SEC_PRIV_DISK_OPERATOR_BIT
	       SEC_PRIV_ENABLE_DELEGATION SEC_PRIV_ENABLE_DELEGATION_BIT
	       SEC_PRIV_IMPERSONATE SEC_PRIV_IMPERSONATE_BIT
	       SEC_PRIV_INCREASE_BASE_PRIORITY
	       SEC_PRIV_INCREASE_BASE_PRIORITY_BIT SEC_PRIV_INCREASE_QUOTA
	       SEC_PRIV_INCREASE_QUOTA_BIT SEC_PRIV_INVALID
	       SEC_PRIV_LOAD_DRIVER SEC_PRIV_LOAD_DRIVER_BIT
	       SEC_PRIV_MACHINE_ACCOUNT SEC_PRIV_MACHINE_ACCOUNT_BIT
	       SEC_PRIV_MANAGE_VOLUME SEC_PRIV_MANAGE_VOLUME_BIT
	       SEC_PRIV_PRINT_OPERATOR SEC_PRIV_PRINT_OPERATOR_BIT
	       SEC_PRIV_PROFILE_SINGLE_PROCESS
	       SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT SEC_PRIV_REMOTE_SHUTDOWN
	       SEC_PRIV_REMOTE_SHUTDOWN_BIT SEC_PRIV_RESTORE
	       SEC_PRIV_RESTORE_BIT SEC_PRIV_SECURITY SEC_PRIV_SECURITY_BIT
	       SEC_PRIV_SHUTDOWN SEC_PRIV_SHUTDOWN_BIT SEC_PRIV_SYSTEMTIME
	       SEC_PRIV_SYSTEMTIME_BIT SEC_PRIV_SYSTEM_ENVIRONMENT
	       SEC_PRIV_SYSTEM_ENVIRONMENT_BIT SEC_PRIV_SYSTEM_PROFILE
	       SEC_PRIV_SYSTEM_PROFILE_BIT SEC_PRIV_TAKE_OWNERSHIP
	       SEC_PRIV_TAKE_OWNERSHIP_BIT SEC_PRIV_UNDOCK SEC_PRIV_UNDOCK_BIT
	       SEC_REG_CREATE_LINK SEC_REG_CREATE_SUBKEY SEC_REG_ENUM_SUBKEYS
	       SEC_REG_NOTIFY SEC_REG_QUERY_VALUE SEC_REG_SET_VALUE
	       SEC_RIGHTS_DIR_ALL SEC_RIGHTS_DIR_EXECUTE SEC_RIGHTS_DIR_READ
	       SEC_RIGHTS_DIR_WRITE SEC_RIGHTS_FILE_ALL SEC_RIGHTS_FILE_EXECUTE
	       SEC_RIGHTS_FILE_READ SEC_RIGHTS_FILE_WRITE
	       SEC_RIGHTS_PRIV_BACKUP SEC_RIGHTS_PRIV_RESTORE
	       SEC_SACL_AUTO_INHERIT SEC_STD_ALL SEC_STD_DELETE
	       SEC_STD_READ_CONTROL SEC_STD_REQUIRED SEC_STD_SYNCHRONIZE
	       SEC_STD_WRITE_DAC SEC_STD_WRITE_OWNER STANDARD_RIGHTS_ALL_ACCESS
	       STANDARD_RIGHTS_EXECUTE_ACCESS STANDARD_RIGHTS_MODIFY_ACCESS
	       STANDARD_RIGHTS_READ_ACCESS STANDARD_RIGHTS_REQUIRED_ACCESS
	       STANDARD_RIGHTS_WRITE_ACCESS),
            {name=>"SECURITY_ACL_REVISION_ADS", type=>"IV", macro=>"1"},
            {name=>"SECURITY_ACL_REVISION_NT4", type=>"IV", macro=>"1"},
            {name=>"SECURITY_DESCRIPTOR_REVISION_1", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_ACCESS_ALLOWED", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_ACCESS_DENIED", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_ACCESS_DENIED_OBJECT", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_ALLOWED_COMPOUND", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_SYSTEM_ALARM", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_SYSTEM_AUDIT", type=>"IV", macro=>"1"},
            {name=>"SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT", type=>"IV", macro=>"1"});

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Samba::Security::Descriptor", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Samba::Security::Descriptor", $types);
__END__
   */

  switch (len) {
  case 11:
    /* Names all of length 11.  */
    /* SD_REVISION SEC_STD_ALL */
    /* Offset 1 gives the best switch position.  */
    switch (name[1]) {
    case 'D':
      if (memEQ(name, "SD_REVISION", 11)) {
      /*                ^                */
#ifdef SD_REVISION
        *iv_return = SD_REVISION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'E':
      if (memEQ(name, "SEC_STD_ALL", 11)) {
      /*                ^                */
#ifdef SEC_STD_ALL
        *iv_return = SEC_STD_ALL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 12:
    return constant_12 (aTHX_ name, iv_return);
    break;
  case 13:
    return constant_13 (aTHX_ name, iv_return);
    break;
  case 14:
    return constant_14 (aTHX_ name, iv_return);
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 16:
    return constant_16 (aTHX_ name, iv_return);
    break;
  case 17:
    return constant_17 (aTHX_ name, iv_return);
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    return constant_20 (aTHX_ name, iv_return);
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    return constant_26 (aTHX_ name, iv_return);
    break;
  case 27:
    return constant_27 (aTHX_ name, iv_return);
    break;
  case 28:
    return constant_28 (aTHX_ name, iv_return);
    break;
  case 29:
    return constant_29 (aTHX_ name, iv_return);
    break;
  case 30:
    return constant_30 (aTHX_ name, iv_return);
    break;
  case 31:
    return constant_31 (aTHX_ name, iv_return);
    break;
  case 32:
    return constant_32 (aTHX_ name, iv_return);
    break;
  case 33:
    return constant_33 (aTHX_ name, iv_return);
    break;
  case 34:
    return constant_34 (aTHX_ name, iv_return);
    break;
  case 35:
    /* Names all of length 35.  */
    /* SEC_PRIV_INCREASE_BASE_PRIORITY_BIT SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT
       */
    /* Offset 29 gives the best switch position.  */
    switch (name[29]) {
    case 'S':
      if (memEQ(name, "SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT", 35)) {
      /*                                            ^            */
#ifdef SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT
        *iv_return = SEC_PRIV_PROFILE_SINGLE_PROCESS_BIT;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "SEC_PRIV_INCREASE_BASE_PRIORITY_BIT", 35)) {
      /*                                            ^            */
#ifdef SEC_PRIV_INCREASE_BASE_PRIORITY_BIT
        *iv_return = SEC_PRIV_INCREASE_BASE_PRIORITY_BIT;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 36:
    /* Names all of length 36.  */
    /* KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
       KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96 */
    /* Offset 16 gives the best switch position.  */
    switch (name[16]) {
    case '1':
      if (memEQ(name, "KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96", 36)) {
      /*                               ^                          */
#ifdef KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
        *iv_return = KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case '2':
      if (memEQ(name, "KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96", 36)) {
      /*                               ^                          */
#ifdef KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96
        *iv_return = KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 37:
    if (memEQ(name, "SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT", 37)) {
#ifdef SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT
      *iv_return = SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 39:
    if (memEQ(name, "LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE", 39)) {
#ifdef LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE
      *iv_return = LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

