use 5.014002;
use ExtUtils::MakeMaker;

our $samba_prefix;

my $pkg_config_cflags = `PKG_CONFIG_PATH=$samba_prefix/lib/pkgconfig pkg-config talloc samba-security --cflags`;
my $pkg_config_ldflags = `PKG_CONFIG_PATH=$samba_prefix/lib/pkgconfig pkg-config talloc samba-security --libs`;
chomp $pkg_config_cflags;
chomp $pkg_config_ldflags;

my $ccflags = $Config{ccflags};
$ccflags .= " $pkg_config_ldflags $pkg_config_cflags -Wimplicit-function-declaration";

my $ldflags = " $pkg_config_ldflags";

WriteMakefile(
    NAME              => 'Samba::Security::AccessControlEntry',
    DISTNAME          => 'Samba-Security-AccessControlEntry',
    VERSION_FROM      => 'lib/Samba/Security/AccessControlEntry.pm',
    ABSTRACT_FROM     => 'lib/Samba/Security/AccessControlEntry.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    CCFLAGS           => $ccflags,
    LIBS              => ["-L$samba_prefix/lib $ldflags"],
    DEFINE            => '',
    INC               => "-I../../../include -I. -I$samba_prefix/include -I/usr/lib/perl5/XS/Object/Magic/Install",
    OBJECT            => 'AccessControlEntry.o',
    INST_LIB          => '../../../blib/lib',
    INST_ARCHLIB      => '../../../blib/arch',
);
