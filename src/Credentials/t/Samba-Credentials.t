# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Samba-Credentials.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 11;
BEGIN { use_ok('Samba::LoadParm') };
BEGIN { use_ok('Samba::Credentials') };

#########################

my $fail = 0;
foreach my $constname (qw(
	CRED_MUST_USE_KERBEROS CRED_DONT_USE_KERBEROS CRED_AUTO_USE_KERBEROS
	CRED_AUTO_KRB_FORWARDABLE CRED_FORCE_KRB_FORWARDABLE
    CRED_NO_KRB_FORWARDABLE)) {
    next if (eval "my \$a = $constname; 1");
    if ($@ =~ /^Your vendor has not defined Samba::Credentials macro $constname/) {
        print "# pass: $@";
    } else {
        print "# fail: $@";
        $fail = 1;
    }
}
ok( $fail == 0 , 'Constants' );


my $lp = new Samba::LoadParm();
isa_ok($lp, "LoadParmPtr");
ok($lp->load_default() == 1, "Load default smb.conf");

my $creds = new Samba::Credentials($lp);
isa_ok($creds, "CredentialsPtr");

ok($creds->kerberos_state(CRED_AUTO_USE_KERBEROS) == CRED_AUTO_USE_KERBEROS, "Set AUTO kerberos state");
ok($creds->kerberos_state(CRED_MUST_USE_KERBEROS) == CRED_MUST_USE_KERBEROS, "Set MUST kerberos state");
ok($creds->kerberos_state(CRED_DONT_USE_KERBEROS) == CRED_DONT_USE_KERBEROS, "Set DONT kerberos state");

ok((not defined $creds->username()) == 1, "Get undefiend username");
$creds->guess();
ok(defined $creds->username(), "Get username");
