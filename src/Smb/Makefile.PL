use 5.014002;
use ExtUtils::MakeMaker;

our $samba_prefix;

my $pkg_config_cflags = `PKG_CONFIG_PATH=$samba_prefix/lib/pkgconfig pkg-config talloc tevent samba-hostconfig samba-credentials gensec dcerpc errors smbclient-raw --cflags`;
my $pkg_config_ldflags = `PKG_CONFIG_PATH=$samba_prefix/lib/pkgconfig pkg-config talloc tevent samba-hostconfig samba-credentials gensec dcerpc errors smbclient-raw --libs`;
chomp $pkg_config_cflags;
chomp $pkg_config_ldflags;

my $ccflags = $Config{ccflags};
$ccflags .= " $pkg_config_ldflags $pkg_config_cflags -Wimplicit-function-declaration";

my $ldflags = " $pkg_config_ldflags";

WriteMakefile(
    NAME              => 'Samba::Smb',
    DISTNAME          => 'Samba-Smb',
    VERSION_FROM      => 'lib/Samba/Smb.pm',
    ABSTRACT_FROM     => 'lib/Samba/Smb.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    CCFLAGS           => $ccflags,
    LIBS              => ["-L$samba_prefix/lib $ldflags"],
    DEFINE            => '',
    INC               => "-I../../include -I. -I/usr/lib/perl5/XS/Object/Magic/Install",
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
  ));
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
