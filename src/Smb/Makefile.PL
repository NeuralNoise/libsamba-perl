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
    LIBS              => ["-L$samba_prefix/lib -L/opt/samba4/lib/private -lsmbclient-raw -ltalloc -ltevent -lsamba-hostconfig -lsamba-credentials -lgensec -ldcerpc"],
    DEFINE            => '',
    INC               => "-I../../include -I. -I$samba_prefix/include",
    OBJECT            => 'Smb.o',
    INST_LIB          => '../../blib/lib',
    INST_ARCHLIB      => '../../blib/arch',
);
if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw(
    DENY_DOS
    DENY_ALL
    DENY_WRITE
    DENY_READ
    DENY_NONE
    DENY_FCB
    DOS_OPEN_RDONLY
    DOS_OPEN_WRONLY
    DOS_OPEN_RDWR
    DOS_OPEN_FCB));
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'Samba::Smb',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );
} else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
