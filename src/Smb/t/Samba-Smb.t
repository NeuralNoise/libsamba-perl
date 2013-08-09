# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Samba-Smb.t'

#########################

# change 'tests => 2' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 12;
BEGIN { use_ok('Samba::LoadParm') };
BEGIN { use_ok('Samba::Credentials') };
BEGIN { use_ok('Samba::Smb') };


my $fail = 0;
foreach my $constname (qw(
	DENY_DOS
    DENY_ALL
    DENY_WRITE
    DENY_READ
    DENY_NONE
    DENY_FCB
    DOS_OPEN_RDONLY
    DOS_OPEN_WRONLY
    DOS_OPEN_RDWR
    DOS_OPEN_FCB)) {
  next if (eval "my \$a = $constname; 1");
  if ($@ =~ /^Your vendor has not defined Samba::Smb macro $constname/) {
    print "# pass: $@";
  } else {
    print "# fail: $@";
    $fail = 1;
  }

}

ok( $fail == 0 , 'Constants' );

#########################

my $lp = new Samba::LoadParm();
isa_ok($lp, 'LoadParmPtr');
ok($lp->load_default() == 1, "load default smb.conf");

my $creds = new Samba::Credentials($lp);
isa_ok($creds, 'CredentialsPtr');
ok($creds->guess() == 1, "Guess credentials");
ok($creds->username('administrator') eq 'administrator', "Set username");
ok($creds->password('Zentyal1234') eq 'Zentyal1234', "Set password");

my $target = "sefirot.kernevil.lan";
my $service = "sysvol";
my $smb = new Samba::Smb($lp, $creds, $target, $service);
isa_ok($smb, 'SmbPtr');
ok(defined $smb, "Connect");
