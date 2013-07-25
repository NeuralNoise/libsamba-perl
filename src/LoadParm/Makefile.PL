use 5.014002;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Samba::LoadParm',
    DISTNAME          => 'Samba-LoadParm',
    VERSION_FROM      => 'lib/Samba/LoadParm.pm',
    ABSTRACT_FROM     => 'lib/Samba/LoadParm.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    LIBS              => ['-L/usr/local/samba/lib -ltalloc -lsamba-hostconfig'],
    DEFINE            => '',
    INC               => '-I../../include -I. -I/usr/local/samba/include',
    OBJECT            => 'LoadParm.o',
    INST_LIB          => '../../blib/lib',
    INST_ARCHLIB      => '../../blib/arch',
);
