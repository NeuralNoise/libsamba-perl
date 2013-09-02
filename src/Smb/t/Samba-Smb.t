# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Samba-Smb.t'

#########################

use strict;
use warnings;

use Test::More tests => 17;
use Fcntl;

BEGIN { use_ok('Samba::LoadParm') };
BEGIN { use_ok('Samba::Credentials') };
BEGIN { use_ok('Samba::Smb') };

my $fail = 0;
foreach my $constname (qw(
    FILE_ATTRIBUTE_READONLY
    FILE_ATTRIBUTE_HIDDEN
    FILE_ATTRIBUTE_SYSTEM
    FILE_ATTRIBUTE_VOLUME
    FILE_ATTRIBUTE_DIRECTORY
    FILE_ATTRIBUTE_ARCHIVE
    FILE_ATTRIBUTE_DEVICE
    FILE_ATTRIBUTE_NORMAL
    FILE_ATTRIBUTE_TEMPORARY
    FILE_ATTRIBUTE_SPARSE
    FILE_ATTRIBUTE_REPARSE_POINT
    FILE_ATTRIBUTE_COMPRESSED
    FILE_ATTRIBUTE_OFFLINE
    FILE_ATTRIBUTE_NONINDEXED
    FILE_ATTRIBUTE_ENCRYPTED
    FILE_ATTRIBUTE_ALL_MASK
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
isa_ok($lp, 'Samba::LoadParm');
ok($lp->load_default() == 1, "load default smb.conf");

my $creds = new Samba::Credentials($lp);
isa_ok($creds, 'Samba::Credentials');
ok($creds->guess() == 1, "Guess credentials");
ok($creds->username('administrator') eq 'administrator', "Set username");
ok($creds->password('Zentyal1234') eq 'Zentyal1234', "Set password");

my $smb = new Samba::Smb($lp, $creds);
isa_ok($smb, 'Samba::Smb');
ok(defined $smb, "Create");

my $target = `hostname --fqdn`;
chomp $target;
my $service = "sysvol";
ok($smb->connect($target, $service) == 1, "connect");

my $listAttributes = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN |
                     FILE_ATTRIBUTE_DIRECTORY;
my $list = $smb->list("/", mask => "*", attributes => $listAttributes,
                      recursive => 0);
ok(defined $list, "list");

my $fd = $smb->open("/kernevil.lan/Policies/{6AC1786C-016F-11D2-945F-00C04FB984F9}/GPT.INI", O_RDONLY, DENY_NONE);
ok($fd > 0, "open");

my $fileAttr = $smb->getattr($fd);
ok(defined $fileAttr, "getattr");

my $closeRet = $smb->close($fd);
ok($closeRet == 1, "close");

# TODO Write tests for:
# chkpath
# mkdir
# rmdir
# deltree
# rename
# unlink
# write
# set_sd
