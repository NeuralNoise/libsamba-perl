use 5.014002;
use ExtUtils::MakeMaker;

our $samba_prefix;

WriteMakefile(
    NAME              => 'Samba::Credentials',
    DISTNAME          => 'Samba-Credentials',
    VERSION_FROM      => 'lib/Samba/Credentials.pm',
    ABSTRACT_FROM     => 'lib/Samba/Credentials.pm',
    AUTHOR            => 'Samuel Cabrero <scabrero@zentyal.com>',
    PREREQ_PM         => {},
    LIBS              => ["-L$samba_prefix/lib -ltalloc -lsamba-hostconfig -lsamba-credentials -lgensec"],
    DEFINE            => '',
    INC               => "-I../../include -I. -I$samba_prefix/include -I/usr/lib/perl5/XS/Object/Magic/Install",
    OBJECT            => 'Credentials.o',
    INST_LIB          => '../../blib/lib',
    INST_ARCHLIB      => '../../blib/arch',
);
if  (eval {require ExtUtils::Constant; 1}) {
# If you edit these definitions to change the constants used by this module,
# you will need to use the generated const-c.inc and const-xs.inc
# files to replace their "fallback" counterparts before distributing your
# changes.
    my @names = ({name=>"CRED_AUTO_KRB_FORWARDABLE", macro=>"1"},
                 {name=>"CRED_FORCE_KRB_FORWARDABLE", macro=>"1"},
                 {name=>"CRED_NO_KRB_FORWARDABLE", macro=>"1"},
                 {name=>"CRED_AUTO_USE_KERBEROS", macro=>"1"},
                 {name=>"CRED_DONT_USE_KERBEROS", macro=>"1"},
                 {name=>"CRED_MUST_USE_KERBEROS", macro=>"1"});
    ExtUtils::Constant::WriteConstants(
            NAME         => 'Samba::Credentials',
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
