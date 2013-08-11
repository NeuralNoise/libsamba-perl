use 5.014002;
use ExtUtils::MakeMaker;

our $samba_prefix;

WriteMakefile(
    NAME              => 'Samba::LoadParm',
    DISTNAME          => 'Samba-LoadParm',
    VERSION_FROM      => 'lib/Samba/LoadParm.pm',
    ABSTRACT_FROM     => 'lib/Samba/LoadParm.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    LIBS              => ["-L$samba_prefix/lib -ltalloc -lsamba-hostconfig"],
    DEFINE            => '',
    INC               => "-I../../include -I. -I$samba_prefix/include -I/usr/lib/perl5/XS/Object/Magic/Install",
    OBJECT            => 'LoadParm.o',
    INST_LIB          => '../../blib/lib',
    INST_ARCHLIB      => '../../blib/arch',
);
