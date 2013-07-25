use 5.014002;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => 'Samba',
    DIR => ['src/LoadParm', 'src/Credentials', 'src/Smb'],
);
