# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Samba-Security-AccessControlEntry.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 3;
BEGIN { use_ok('Samba::Security::Descriptor') };
BEGIN { use_ok('Samba::Security::AccessControlEntry') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $sid = 'S-1-5-21-3292774351-1174609048-3382345406-500';
my $type = SEC_ACE_TYPE_ACCESS_ALLOWED;
my $mask = 0x001f01ff;
my $flags = SEC_ACE_FLAG_OBJECT_INHERIT;

my $ace = new Samba::Security::AccessControlEntry($sid, $type, $mask, $flags);
isa_ok($ace, 'Samba::Security::AccessControlEntry');
