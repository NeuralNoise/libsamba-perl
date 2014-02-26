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
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     FILE_ATTRIBUTE_DEVICE FILE_ATTRIBUTE_HIDDEN FILE_ATTRIBUTE_NORMAL
     FILE_ATTRIBUTE_SPARSE FILE_ATTRIBUTE_SYSTEM FILE_ATTRIBUTE_VOLUME
     NTCREATEX_DISP_CREATE */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'A':
    if (memEQ(name, "NTCREATEX_DISP_CREATE", 21)) {
    /*                                 ^         */
#ifdef NTCREATEX_DISP_CREATE
      *iv_return = NTCREATEX_DISP_CREATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "FILE_ATTRIBUTE_HIDDEN", 21)) {
    /*                                 ^         */
#ifdef FILE_ATTRIBUTE_HIDDEN
      *iv_return = FILE_ATTRIBUTE_HIDDEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "FILE_ATTRIBUTE_DEVICE", 21)) {
    /*                                 ^         */
#ifdef FILE_ATTRIBUTE_DEVICE
      *iv_return = FILE_ATTRIBUTE_DEVICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "FILE_ATTRIBUTE_NORMAL", 21)) {
    /*                                 ^         */
#ifdef FILE_ATTRIBUTE_NORMAL
      *iv_return = FILE_ATTRIBUTE_NORMAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "FILE_ATTRIBUTE_SPARSE", 21)) {
    /*                                 ^         */
#ifdef FILE_ATTRIBUTE_SPARSE
      *iv_return = FILE_ATTRIBUTE_SPARSE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "FILE_ATTRIBUTE_SYSTEM", 21)) {
    /*                                 ^         */
#ifdef FILE_ATTRIBUTE_SYSTEM
      *iv_return = FILE_ATTRIBUTE_SYSTEM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "FILE_ATTRIBUTE_VOLUME", 21)) {
    /*                                 ^         */
#ifdef FILE_ATTRIBUTE_VOLUME
      *iv_return = FILE_ATTRIBUTE_VOLUME;
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
     FILE_ATTRIBUTE_ARCHIVE FILE_ATTRIBUTE_OFFLINE NTCREATEX_DISP_OPEN_IF */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case 'C':
    if (memEQ(name, "FILE_ATTRIBUTE_ARCHIVE", 22)) {
    /*                                ^           */
#ifdef FILE_ATTRIBUTE_ARCHIVE
      *iv_return = FILE_ATTRIBUTE_ARCHIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "NTCREATEX_DISP_OPEN_IF", 22)) {
    /*                                ^           */
#ifdef NTCREATEX_DISP_OPEN_IF
      *iv_return = NTCREATEX_DISP_OPEN_IF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "FILE_ATTRIBUTE_OFFLINE", 22)) {
    /*                                ^           */
#ifdef FILE_ATTRIBUTE_OFFLINE
      *iv_return = FILE_ATTRIBUTE_OFFLINE;
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
     FILE_ATTRIBUTE_DIRECTORY FILE_ATTRIBUTE_ENCRYPTED FILE_ATTRIBUTE_TEMPORARY
     NTCREATEX_DISP_OVERWRITE NTCREATEX_DISP_SUPERSEDE */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case 'C':
    if (memEQ(name, "FILE_ATTRIBUTE_ENCRYPTED", 24)) {
    /*                                ^             */
#ifdef FILE_ATTRIBUTE_ENCRYPTED
      *iv_return = FILE_ATTRIBUTE_ENCRYPTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "NTCREATEX_DISP_OVERWRITE", 24)) {
    /*                                ^             */
#ifdef NTCREATEX_DISP_OVERWRITE
      *iv_return = NTCREATEX_DISP_OVERWRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "FILE_ATTRIBUTE_TEMPORARY", 24)) {
    /*                                ^             */
#ifdef FILE_ATTRIBUTE_TEMPORARY
      *iv_return = FILE_ATTRIBUTE_TEMPORARY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "NTCREATEX_DISP_SUPERSEDE", 24)) {
    /*                                ^             */
#ifdef NTCREATEX_DISP_SUPERSEDE
      *iv_return = NTCREATEX_DISP_SUPERSEDE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "FILE_ATTRIBUTE_DIRECTORY", 24)) {
    /*                                ^             */
#ifdef FILE_ATTRIBUTE_DIRECTORY
      *iv_return = FILE_ATTRIBUTE_DIRECTORY;
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
     NTCREATEX_DISP_OVERWRITE_IF NTCREATEX_OPTIONS_DIRECTORY
     NTCREATEX_OPTIONS_NO_RECALL NTCREATEX_SHARE_ACCESS_MASK
     NTCREATEX_SHARE_ACCESS_NONE NTCREATEX_SHARE_ACCESS_READ */
  /* Offset 23 gives the best switch position.  */
  switch (name[23]) {
  case 'C':
    if (memEQ(name, "NTCREATEX_OPTIONS_NO_RECALL", 27)) {
    /*                                      ^          */
#ifdef NTCREATEX_OPTIONS_NO_RECALL
      *iv_return = NTCREATEX_OPTIONS_NO_RECALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "NTCREATEX_DISP_OVERWRITE_IF", 27)) {
    /*                                      ^          */
#ifdef NTCREATEX_DISP_OVERWRITE_IF
      *iv_return = NTCREATEX_DISP_OVERWRITE_IF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "NTCREATEX_SHARE_ACCESS_MASK", 27)) {
    /*                                      ^          */
#ifdef NTCREATEX_SHARE_ACCESS_MASK
      *iv_return = NTCREATEX_SHARE_ACCESS_MASK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "NTCREATEX_SHARE_ACCESS_NONE", 27)) {
    /*                                      ^          */
#ifdef NTCREATEX_SHARE_ACCESS_NONE
      *iv_return = NTCREATEX_SHARE_ACCESS_NONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "NTCREATEX_SHARE_ACCESS_READ", 27)) {
    /*                                      ^          */
#ifdef NTCREATEX_SHARE_ACCESS_READ
      *iv_return = NTCREATEX_SHARE_ACCESS_READ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "NTCREATEX_OPTIONS_DIRECTORY", 27)) {
    /*                                      ^          */
#ifdef NTCREATEX_OPTIONS_DIRECTORY
      *iv_return = NTCREATEX_OPTIONS_DIRECTORY;
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
constant_28 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     FILE_ATTRIBUTE_REPARSE_POINT NTCREATEX_OPTIONS_SYNC_ALERT
     NTCREATEX_SHARE_ACCESS_WRITE */
  /* Offset 24 gives the best switch position.  */
  switch (name[24]) {
  case 'L':
    if (memEQ(name, "NTCREATEX_OPTIONS_SYNC_ALERT", 28)) {
    /*                                       ^          */
#ifdef NTCREATEX_OPTIONS_SYNC_ALERT
      *iv_return = NTCREATEX_OPTIONS_SYNC_ALERT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "FILE_ATTRIBUTE_REPARSE_POINT", 28)) {
    /*                                       ^          */
#ifdef FILE_ATTRIBUTE_REPARSE_POINT
      *iv_return = FILE_ATTRIBUTE_REPARSE_POINT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "NTCREATEX_SHARE_ACCESS_WRITE", 28)) {
    /*                                       ^          */
#ifdef NTCREATEX_SHARE_ACCESS_WRITE
      *iv_return = NTCREATEX_SHARE_ACCESS_WRITE;
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
     NTCREATEX_OPTIONS_BACKUP_INTENT NTCREATEX_OPTIONS_RANDOM_ACCESS
     NTCREATEX_OPTIONS_REPARSE_POINT NTCREATEX_OPTIONS_WRITE_THROUGH */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'C':
    if (memEQ(name, "NTCREATEX_OPTIONS_BACKUP_INTENT", 31)) {
    /*                                   ^                 */
#ifdef NTCREATEX_OPTIONS_BACKUP_INTENT
      *iv_return = NTCREATEX_OPTIONS_BACKUP_INTENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "NTCREATEX_OPTIONS_WRITE_THROUGH", 31)) {
    /*                                   ^                 */
#ifdef NTCREATEX_OPTIONS_WRITE_THROUGH
      *iv_return = NTCREATEX_OPTIONS_WRITE_THROUGH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "NTCREATEX_OPTIONS_RANDOM_ACCESS", 31)) {
    /*                                   ^                 */
#ifdef NTCREATEX_OPTIONS_RANDOM_ACCESS
      *iv_return = NTCREATEX_OPTIONS_RANDOM_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "NTCREATEX_OPTIONS_REPARSE_POINT", 31)) {
    /*                                   ^                 */
#ifdef NTCREATEX_OPTIONS_REPARSE_POINT
      *iv_return = NTCREATEX_OPTIONS_REPARSE_POINT;
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
constant_33 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     NTCREATEX_OPTIONS_DELETE_ON_CLOSE NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE
     NTCREATEX_OPTIONS_OPEN_BY_FILE_ID NTCREATEX_OPTIONS_SEQUENTIAL_ONLY
     NTCREATEX_OPTIONS_TREE_CONNECTION */
  /* Offset 31 gives the best switch position.  */
  switch (name[31]) {
  case 'G':
    if (memEQ(name, "NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE", 33)) {
    /*                                              ^        */
#ifdef NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE
      *iv_return = NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "NTCREATEX_OPTIONS_OPEN_BY_FILE_ID", 33)) {
    /*                                              ^        */
#ifdef NTCREATEX_OPTIONS_OPEN_BY_FILE_ID
      *iv_return = NTCREATEX_OPTIONS_OPEN_BY_FILE_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "NTCREATEX_OPTIONS_SEQUENTIAL_ONLY", 33)) {
    /*                                              ^        */
#ifdef NTCREATEX_OPTIONS_SEQUENTIAL_ONLY
      *iv_return = NTCREATEX_OPTIONS_SEQUENTIAL_ONLY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "NTCREATEX_OPTIONS_TREE_CONNECTION", 33)) {
    /*                                              ^        */
#ifdef NTCREATEX_OPTIONS_TREE_CONNECTION
      *iv_return = NTCREATEX_OPTIONS_TREE_CONNECTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "NTCREATEX_OPTIONS_DELETE_ON_CLOSE", 33)) {
    /*                                              ^        */
#ifdef NTCREATEX_OPTIONS_DELETE_ON_CLOSE
      *iv_return = NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
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
constant_36 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     NTCREATEX_OPTIONS_INVALID_PARAM_MASK NTCREATEX_OPTIONS_NON_DIRECTORY_FILE
     NTCREATEX_OPTIONS_NOT_SUPPORTED_MASK */
  /* Offset 28 gives the best switch position.  */
  switch (name[28]) {
  case 'O':
    if (memEQ(name, "NTCREATEX_OPTIONS_NON_DIRECTORY_FILE", 36)) {
    /*                                           ^              */
#ifdef NTCREATEX_OPTIONS_NON_DIRECTORY_FILE
      *iv_return = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "NTCREATEX_OPTIONS_INVALID_PARAM_MASK", 36)) {
    /*                                           ^              */
#ifdef NTCREATEX_OPTIONS_INVALID_PARAM_MASK
      *iv_return = NTCREATEX_OPTIONS_INVALID_PARAM_MASK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "NTCREATEX_OPTIONS_NOT_SUPPORTED_MASK", 36)) {
    /*                                           ^              */
#ifdef NTCREATEX_OPTIONS_NOT_SUPPORTED_MASK
      *iv_return = NTCREATEX_OPTIONS_NOT_SUPPORTED_MASK;
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
my @names = (qw(FILE_ATTRIBUTE_ALL_MASK FILE_ATTRIBUTE_ARCHIVE
	       FILE_ATTRIBUTE_COMPRESSED FILE_ATTRIBUTE_DEVICE
	       FILE_ATTRIBUTE_DIRECTORY FILE_ATTRIBUTE_ENCRYPTED
	       FILE_ATTRIBUTE_HIDDEN FILE_ATTRIBUTE_NONINDEXED
	       FILE_ATTRIBUTE_NORMAL FILE_ATTRIBUTE_OFFLINE
	       FILE_ATTRIBUTE_READONLY FILE_ATTRIBUTE_REPARSE_POINT
	       FILE_ATTRIBUTE_SPARSE FILE_ATTRIBUTE_SYSTEM
	       FILE_ATTRIBUTE_TEMPORARY FILE_ATTRIBUTE_VOLUME
	       NTCREATEX_DISP_CREATE NTCREATEX_DISP_OPEN NTCREATEX_DISP_OPEN_IF
	       NTCREATEX_DISP_OVERWRITE NTCREATEX_DISP_OVERWRITE_IF
	       NTCREATEX_DISP_SUPERSEDE NTCREATEX_OPTIONS_ASYNC_ALERT
	       NTCREATEX_OPTIONS_BACKUP_INTENT
	       NTCREATEX_OPTIONS_COMPLETE_IF_OPLOCKED
	       NTCREATEX_OPTIONS_DELETE_ON_CLOSE NTCREATEX_OPTIONS_DIRECTORY
	       NTCREATEX_OPTIONS_FREE_SPACE_QUERY
	       NTCREATEX_OPTIONS_INVALID_PARAM_MASK
	       NTCREATEX_OPTIONS_MUST_IGNORE_MASK
	       NTCREATEX_OPTIONS_NON_DIRECTORY_FILE
	       NTCREATEX_OPTIONS_NOT_SUPPORTED_MASK
	       NTCREATEX_OPTIONS_NO_COMPRESSION
	       NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE
	       NTCREATEX_OPTIONS_NO_INTERMEDIATE_BUFFERING
	       NTCREATEX_OPTIONS_NO_RECALL NTCREATEX_OPTIONS_OPEN_BY_FILE_ID
	       NTCREATEX_OPTIONS_OPEN_FOR_RECOVERY NTCREATEX_OPTIONS_OPFILTER
	       NTCREATEX_OPTIONS_RANDOM_ACCESS NTCREATEX_OPTIONS_REPARSE_POINT
	       NTCREATEX_OPTIONS_SEQUENTIAL_ONLY NTCREATEX_OPTIONS_SYNC_ALERT
	       NTCREATEX_OPTIONS_TREE_CONNECTION
	       NTCREATEX_OPTIONS_WRITE_THROUGH NTCREATEX_SHARE_ACCESS_DELETE
	       NTCREATEX_SHARE_ACCESS_MASK NTCREATEX_SHARE_ACCESS_NONE
	       NTCREATEX_SHARE_ACCESS_READ NTCREATEX_SHARE_ACCESS_WRITE));

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Samba::Smb", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Samba::Smb", $types);
__END__
   */

  switch (len) {
  case 19:
    if (memEQ(name, "NTCREATEX_DISP_OPEN", 19)) {
#ifdef NTCREATEX_DISP_OPEN
      *iv_return = NTCREATEX_DISP_OPEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    /* Names all of length 23.  */
    /* FILE_ATTRIBUTE_ALL_MASK FILE_ATTRIBUTE_READONLY */
    /* Offset 19 gives the best switch position.  */
    switch (name[19]) {
    case 'M':
      if (memEQ(name, "FILE_ATTRIBUTE_ALL_MASK", 23)) {
      /*                                  ^          */
#ifdef FILE_ATTRIBUTE_ALL_MASK
        *iv_return = FILE_ATTRIBUTE_ALL_MASK;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'O':
      if (memEQ(name, "FILE_ATTRIBUTE_READONLY", 23)) {
      /*                                  ^          */
#ifdef FILE_ATTRIBUTE_READONLY
        *iv_return = FILE_ATTRIBUTE_READONLY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    /* Names all of length 25.  */
    /* FILE_ATTRIBUTE_COMPRESSED FILE_ATTRIBUTE_NONINDEXED */
    /* Offset 17 gives the best switch position.  */
    switch (name[17]) {
    case 'M':
      if (memEQ(name, "FILE_ATTRIBUTE_COMPRESSED", 25)) {
      /*                                ^              */
#ifdef FILE_ATTRIBUTE_COMPRESSED
        *iv_return = FILE_ATTRIBUTE_COMPRESSED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'N':
      if (memEQ(name, "FILE_ATTRIBUTE_NONINDEXED", 25)) {
      /*                                ^              */
#ifdef FILE_ATTRIBUTE_NONINDEXED
        *iv_return = FILE_ATTRIBUTE_NONINDEXED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 26:
    if (memEQ(name, "NTCREATEX_OPTIONS_OPFILTER", 26)) {
#ifdef NTCREATEX_OPTIONS_OPFILTER
      *iv_return = NTCREATEX_OPTIONS_OPFILTER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 27:
    return constant_27 (aTHX_ name, iv_return);
    break;
  case 28:
    return constant_28 (aTHX_ name, iv_return);
    break;
  case 29:
    /* Names all of length 29.  */
    /* NTCREATEX_OPTIONS_ASYNC_ALERT NTCREATEX_SHARE_ACCESS_DELETE */
    /* Offset 18 gives the best switch position.  */
    switch (name[18]) {
    case 'A':
      if (memEQ(name, "NTCREATEX_OPTIONS_ASYNC_ALERT", 29)) {
      /*                                 ^                 */
#ifdef NTCREATEX_OPTIONS_ASYNC_ALERT
        *iv_return = NTCREATEX_OPTIONS_ASYNC_ALERT;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'C':
      if (memEQ(name, "NTCREATEX_SHARE_ACCESS_DELETE", 29)) {
      /*                                 ^                 */
#ifdef NTCREATEX_SHARE_ACCESS_DELETE
        *iv_return = NTCREATEX_SHARE_ACCESS_DELETE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 31:
    return constant_31 (aTHX_ name, iv_return);
    break;
  case 32:
    if (memEQ(name, "NTCREATEX_OPTIONS_NO_COMPRESSION", 32)) {
#ifdef NTCREATEX_OPTIONS_NO_COMPRESSION
      *iv_return = NTCREATEX_OPTIONS_NO_COMPRESSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 33:
    return constant_33 (aTHX_ name, iv_return);
    break;
  case 34:
    /* Names all of length 34.  */
    /* NTCREATEX_OPTIONS_FREE_SPACE_QUERY NTCREATEX_OPTIONS_MUST_IGNORE_MASK */
    /* Offset 32 gives the best switch position.  */
    switch (name[32]) {
    case 'R':
      if (memEQ(name, "NTCREATEX_OPTIONS_FREE_SPACE_QUERY", 34)) {
      /*                                               ^        */
#ifdef NTCREATEX_OPTIONS_FREE_SPACE_QUERY
        *iv_return = NTCREATEX_OPTIONS_FREE_SPACE_QUERY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'S':
      if (memEQ(name, "NTCREATEX_OPTIONS_MUST_IGNORE_MASK", 34)) {
      /*                                               ^        */
#ifdef NTCREATEX_OPTIONS_MUST_IGNORE_MASK
        *iv_return = NTCREATEX_OPTIONS_MUST_IGNORE_MASK;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 35:
    if (memEQ(name, "NTCREATEX_OPTIONS_OPEN_FOR_RECOVERY", 35)) {
#ifdef NTCREATEX_OPTIONS_OPEN_FOR_RECOVERY
      *iv_return = NTCREATEX_OPTIONS_OPEN_FOR_RECOVERY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 36:
    return constant_36 (aTHX_ name, iv_return);
    break;
  case 38:
    if (memEQ(name, "NTCREATEX_OPTIONS_COMPLETE_IF_OPLOCKED", 38)) {
#ifdef NTCREATEX_OPTIONS_COMPLETE_IF_OPLOCKED
      *iv_return = NTCREATEX_OPTIONS_COMPLETE_IF_OPLOCKED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 43:
    if (memEQ(name, "NTCREATEX_OPTIONS_NO_INTERMEDIATE_BUFFERING", 43)) {
#ifdef NTCREATEX_OPTIONS_NO_INTERMEDIATE_BUFFERING
      *iv_return = NTCREATEX_OPTIONS_NO_INTERMEDIATE_BUFFERING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

