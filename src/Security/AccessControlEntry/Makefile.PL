use 5.014002;
use ExtUtils::MakeMaker;

our $samba_prefix;

WriteMakefile(
    NAME              => 'Samba::Security::AccessControlEntry',
    DISTNAME          => 'Samba-Security-AccessControlEntry',
    VERSION_FROM      => 'lib/Samba/Security/AccessControlEntry.pm',
    ABSTRACT_FROM     => 'lib/Samba/Security/AccessControlEntry.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    LIBS              => ["-L$samba_prefix/lib -ltalloc -lsamba-security"],
    DEFINE            => '',
    INC               => "-I../../../include -I. -I$samba_prefix/include",
    OBJECT            => 'AccessControlEntry.o',
    INST_LIB          => '../../../blib/lib',
    INST_ARCHLIB      => '../../../blib/arch',
);
