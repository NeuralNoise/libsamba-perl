use 5.014002;
use ExtUtils::MakeMaker;

our $samba_prefix;

WriteMakefile(
    NAME              => 'Samba::Smb',
    DISTNAME          => 'Samba-Smb',
    VERSION_FROM      => 'lib/Samba/Smb.pm',
    ABSTRACT_FROM     => 'lib/Samba/Smb.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    LIBS              => ["-L$samba_prefix/lib -L/opt/samba4/lib/private -lsmbclient-raw -ltalloc -ltevent -lsamba-hostconfig -lsamba-credentials -lgensec"],
    DEFINE            => '',
    INC               => "-I../../include -I. -I$samba_prefix/include",
    OBJECT            => 'Smb.o',
    INST_LIB          => '../../blib/lib',
    INST_ARCHLIB      => '../../blib/arch',
);
