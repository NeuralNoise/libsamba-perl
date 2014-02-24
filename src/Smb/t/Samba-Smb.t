# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Samba-Smb.t'

#########################

use strict;
use warnings;

use Test::More tests => 18;
use Fcntl;

BEGIN { use_ok('Samba::LoadParm') };
BEGIN { use_ok('Samba::Credentials') };
BEGIN { use_ok('Samba::Smb') };

use Samba::Smb qw( :all );
use Samba::Security::Descriptor;

my $fail = 0;
foreach my $constname (qw(
    NTCREATEX_SHARE_ACCESS_NONE
    NTCREATEX_SHARE_ACCESS_READ
    NTCREATEX_SHARE_ACCESS_WRITE
    NTCREATEX_SHARE_ACCESS_DELETE
    NTCREATEX_SHARE_ACCESS_MASK

    NTCREATEX_DISP_SUPERSEDE
    NTCREATEX_DISP_OPEN
    NTCREATEX_DISP_CREATE
    NTCREATEX_DISP_OPEN_IF
    NTCREATEX_DISP_OVERWRITE
    NTCREATEX_DISP_OVERWRITE_IF

    NTCREATEX_OPTIONS_DIRECTORY
    NTCREATEX_OPTIONS_WRITE_THROUGH
    NTCREATEX_OPTIONS_SEQUENTIAL_ONLY
    NTCREATEX_OPTIONS_NO_INTERMEDIATE_BUFFERING
    NTCREATEX_OPTIONS_SYNC_ALERT
    NTCREATEX_OPTIONS_ASYNC_ALERT
    NTCREATEX_OPTIONS_NON_DIRECTORY_FILE
    NTCREATEX_OPTIONS_TREE_CONNECTION
    NTCREATEX_OPTIONS_COMPLETE_IF_OPLOCKED
    NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE
    NTCREATEX_OPTIONS_OPEN_FOR_RECOVERY
    NTCREATEX_OPTIONS_RANDOM_ACCESS
    NTCREATEX_OPTIONS_DELETE_ON_CLOSE
    NTCREATEX_OPTIONS_OPEN_BY_FILE_ID
    NTCREATEX_OPTIONS_BACKUP_INTENT
    NTCREATEX_OPTIONS_NO_COMPRESSION
    NTCREATEX_OPTIONS_OPFILTER
    NTCREATEX_OPTIONS_REPARSE_POINT
    NTCREATEX_OPTIONS_NO_RECALL
    NTCREATEX_OPTIONS_FREE_SPACE_QUERY
    NTCREATEX_OPTIONS_MUST_IGNORE_MASK
    NTCREATEX_OPTIONS_NOT_SUPPORTED_MASK
    NTCREATEX_OPTIONS_INVALID_PARAM_MASK

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
    )) {
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
ok($creds->password('foo') eq 'foo', "Set password");

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

my $path = "/kernevil.lan/Policies/{6AC1786C-016F-11D2-945F-00C04FB984F9}/GPT.INI";
my $fileAttr = $smb->getattr($path);
ok(defined $fileAttr, "getattr");

my $openParams = {
    access_mask => SEC_RIGHTS_FILE_ALL,
    create_options => NTCREATEX_OPTIONS_NON_DIRECTORY_FILE,
    file_attr => FILE_ATTRIBUTE_NORMAL,
    share_access => NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE,
    open_disposition => NTCREATEX_DISP_OPEN_IF,
};
my $fd = $smb->open($path, $openParams);
ok($fd > 0, "open");

$fileAttr = $smb->getattrE($fd);
ok(defined $fileAttr, "getattrE");

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
