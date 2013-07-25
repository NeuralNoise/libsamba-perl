use 5.014002;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Samba::Credentials',
    DISTNAME          => 'Samba-Credentials',
    VERSION_FROM      => 'lib/Samba/Credentials.pm',
    ABSTRACT_FROM     => 'lib/Samba/Credentials.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    LIBS              => ['-L/usr/local/samba/lib -ltalloc -lsamba-hostconfig -lsamba-credentials -lgensec'],
    DEFINE            => '',
    INC               => '-I../../include -I. -I/usr/local/samba/include',
    OBJECT            => 'Credentials.o',
    INST_LIB          => '../../blib/lib',
    INST_ARCHLIB      => '../../blib/arch',
);
