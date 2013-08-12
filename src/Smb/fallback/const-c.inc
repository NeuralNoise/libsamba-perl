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
constant_8 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DENY_ALL DENY_DOS DENY_FCB */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'A':
    if (memEQ(name, "DENY_ALL", 8)) {
    /*                    ^        */
#ifdef DENY_ALL
      *iv_return = DENY_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "DENY_DOS", 8)) {
    /*                    ^        */
#ifdef DENY_DOS
      *iv_return = DENY_DOS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "DENY_FCB", 8)) {
    /*                    ^        */
#ifdef DENY_FCB
      *iv_return = DENY_FCB;
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
     FILE_ATTRIBUTE_DEVICE FILE_ATTRIBUTE_HIDDEN FILE_ATTRIBUTE_NORMAL
     FILE_ATTRIBUTE_SPARSE FILE_ATTRIBUTE_SYSTEM FILE_ATTRIBUTE_VOLUME */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
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
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     FILE_ATTRIBUTE_DIRECTORY FILE_ATTRIBUTE_ENCRYPTED FILE_ATTRIBUTE_TEMPORARY
     */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'P':
    if (memEQ(name, "FILE_ATTRIBUTE_ENCRYPTED", 24)) {
    /*                                   ^          */
#ifdef FILE_ATTRIBUTE_ENCRYPTED
      *iv_return = FILE_ATTRIBUTE_ENCRYPTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "FILE_ATTRIBUTE_TEMPORARY", 24)) {
    /*                                   ^          */
#ifdef FILE_ATTRIBUTE_TEMPORARY
      *iv_return = FILE_ATTRIBUTE_TEMPORARY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "FILE_ATTRIBUTE_DIRECTORY", 24)) {
    /*                                   ^          */
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
my @names = (qw(DENY_ALL DENY_DOS DENY_FCB DENY_NONE DENY_READ DENY_WRITE
	       DOS_OPEN_FCB DOS_OPEN_RDONLY DOS_OPEN_RDWR DOS_OPEN_WRONLY
	       FILE_ATTRIBUTE_ALL_MASK FILE_ATTRIBUTE_ARCHIVE
	       FILE_ATTRIBUTE_COMPRESSED FILE_ATTRIBUTE_DEVICE
	       FILE_ATTRIBUTE_DIRECTORY FILE_ATTRIBUTE_ENCRYPTED
	       FILE_ATTRIBUTE_HIDDEN FILE_ATTRIBUTE_NONINDEXED
	       FILE_ATTRIBUTE_NORMAL FILE_ATTRIBUTE_OFFLINE
	       FILE_ATTRIBUTE_READONLY FILE_ATTRIBUTE_REPARSE_POINT
	       FILE_ATTRIBUTE_SPARSE FILE_ATTRIBUTE_SYSTEM
	       FILE_ATTRIBUTE_TEMPORARY FILE_ATTRIBUTE_VOLUME));

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Samba::Smb", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Samba::Smb", $types);
__END__
   */

  switch (len) {
  case 8:
    return constant_8 (aTHX_ name, iv_return);
    break;
  case 9:
    /* Names all of length 9.  */
    /* DENY_NONE DENY_READ */
    /* Offset 8 gives the best switch position.  */
    switch (name[8]) {
    case 'D':
      if (memEQ(name, "DENY_REA", 8)) {
      /*                       D     */
#ifdef DENY_READ
        *iv_return = DENY_READ;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'E':
      if (memEQ(name, "DENY_NON", 8)) {
      /*                       E     */
#ifdef DENY_NONE
        *iv_return = DENY_NONE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 10:
    if (memEQ(name, "DENY_WRITE", 10)) {
#ifdef DENY_WRITE
      *iv_return = DENY_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 12:
    if (memEQ(name, "DOS_OPEN_FCB", 12)) {
#ifdef DOS_OPEN_FCB
      *iv_return = DOS_OPEN_FCB;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 13:
    if (memEQ(name, "DOS_OPEN_RDWR", 13)) {
#ifdef DOS_OPEN_RDWR
      *iv_return = DOS_OPEN_RDWR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 15:
    /* Names all of length 15.  */
    /* DOS_OPEN_RDONLY DOS_OPEN_WRONLY */
    /* Offset 9 gives the best switch position.  */
    switch (name[9]) {
    case 'R':
      if (memEQ(name, "DOS_OPEN_RDONLY", 15)) {
      /*                        ^            */
#ifdef DOS_OPEN_RDONLY
        *iv_return = DOS_OPEN_RDONLY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'W':
      if (memEQ(name, "DOS_OPEN_WRONLY", 15)) {
      /*                        ^            */
#ifdef DOS_OPEN_WRONLY
        *iv_return = DOS_OPEN_WRONLY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    /* Names all of length 22.  */
    /* FILE_ATTRIBUTE_ARCHIVE FILE_ATTRIBUTE_OFFLINE */
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
  case 28:
    if (memEQ(name, "FILE_ATTRIBUTE_REPARSE_POINT", 28)) {
#ifdef FILE_ATTRIBUTE_REPARSE_POINT
      *iv_return = FILE_ATTRIBUTE_REPARSE_POINT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

