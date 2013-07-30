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
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CRED_AUTO_USE_KERBEROS CRED_DONT_USE_KERBEROS CRED_MUST_USE_KERBEROS */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'N':
    if (memEQ(name, "CRED_DONT_USE_KERBEROS", 22)) {
    /*                      ^                     */
      *iv_return = CRED_DONT_USE_KERBEROS;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "CRED_MUST_USE_KERBEROS", 22)) {
    /*                      ^                     */
      *iv_return = CRED_MUST_USE_KERBEROS;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "CRED_AUTO_USE_KERBEROS", 22)) {
    /*                      ^                     */
      *iv_return = CRED_AUTO_USE_KERBEROS;
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
my @names = (qw(),
            {name=>"CRED_AUTO_KRB_FORWARDABLE", type=>"IV", macro=>"1"},
            {name=>"CRED_AUTO_USE_KERBEROS", type=>"IV", macro=>"1"},
            {name=>"CRED_DONT_USE_KERBEROS", type=>"IV", macro=>"1"},
            {name=>"CRED_FORCE_KRB_FORWARDABLE", type=>"IV", macro=>"1"},
            {name=>"CRED_MUST_USE_KERBEROS", type=>"IV", macro=>"1"},
            {name=>"CRED_NO_KRB_FORWARDABLE", type=>"IV", macro=>"1"});

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Samba::Credentials", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Samba::Credentials", $types);
__END__
   */

  switch (len) {
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    if (memEQ(name, "CRED_NO_KRB_FORWARDABLE", 23)) {
      *iv_return = CRED_NO_KRB_FORWARDABLE;
      return PERL_constant_ISIV;
    }
    break;
  case 25:
    if (memEQ(name, "CRED_AUTO_KRB_FORWARDABLE", 25)) {
      *iv_return = CRED_AUTO_KRB_FORWARDABLE;
      return PERL_constant_ISIV;
    }
    break;
  case 26:
    if (memEQ(name, "CRED_FORCE_KRB_FORWARDABLE", 26)) {
      *iv_return = CRED_FORCE_KRB_FORWARDABLE;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

