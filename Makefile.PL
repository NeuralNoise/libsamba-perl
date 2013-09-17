use 5.014002;

use strict;
use warnings;

use ExtUtils::MakeMaker;
use Getopt::Long qw(GetOptions);

our $samba_prefix = '/opt/samba4';
GetOptions('samba-prefix=s' => \$samba_prefix);

WriteMakefile(
    NAME => 'Samba',
    DIR => ['src/LoadParm',
            'src/Credentials',
            'src/Smb',
            'src/Security/Descriptor',
            'src/Security/AccessControlEntry',
           ],
);
