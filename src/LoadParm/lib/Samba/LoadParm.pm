package Samba::LoadParm;

use 5.014002;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Samba::LoadParm ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(

) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

our $VERSION = '0.01';

my %functions = (
    default_path    => \&_default_path,
    setup_dir       => \&_setup_dir,
    modules_dir     => \&_modules_dir,
    bin_dir         => \&_bin_dir,
    sbin_dir        => \&_sbin_dir,
    private_path    => \&_private_path,
    server_role     => \&_server_role,
    load            => \&_load,
    load_default    => \&_load_default,
    is_myname       => \&_is_myname,
    is_mydomain     => \&_is_mydomain,
);

sub AUTOLOAD
{
    my $self = shift;

    our $AUTOLOAD;

    my $attr = $AUTOLOAD;
    $attr =~ s/.*:://;
    return unless $attr =~ /[^A-Z]/;
    print STDERR "$attr\n";

    die "Method undef ->$attr()\n" unless defined($functions{$attr});
    return $functions{$attr}->($self->{context}, @_);
}

require XSLoader;
XSLoader::load('Samba::LoadParm', $VERSION);

# Preloaded methods go here.

sub new
{
    my ($class, %params) = @_;

    my $self = {};
    bless ($self, $class);

    $self->{context} = _init();

    return $self;
}

sub DESTROY
{
    my ($self) = @_;
    _destroy($self->{context});
}

1;
__END__

=head1 NAME

Samba::LoadParm - Extension for parsing and writting Samba configuration files

=head1 SYNOPSIS

  use Samba::LoadParm;

  my $lp = new Samba::LoadParm();
  $lp->load_default();

=head1 DESCRIPTION

  This module implements an object interface

=over

=item new

  Instantiate object.

=item load_default

  Load default smb.conf file. Returns 1 on success.

=item load filename

  Load specified file. Returns 1 on success.

=item is_myname name

  Check whether the specified name matches one of our netbios names.

=item is_mydomain name

  Check whether the specified name matches our domain name.

=item private_path name

  Returns an absolute path to a file in the Samba private directory.

=item server_role

  Get the server role.

=item default_path

  Returns the default smb.conf path.

=item setup_dir

  Returns the compiled in location for provision tempates.

=item modules_dir

  Returns the compiled in location of modules.

=item bin_dir

  Returns the compiled in BINDIR.

=item sbin_dir

  Returns the compiled in SBINDIR.

=back

=head1 EXPORT

None by default.

=head1 SEE ALSO

Samba::Credentials
Samba::Smb
Samba::Security::Descriptor

=head1 AUTHOR

Samuel Cabrero, E<lt>scabrero@zentyal.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Zentyal S.L.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

=cut
