package Samba::Credentials;

use 5.014002;
use strict;
use warnings;
use Carp;
use XS::Object::Magic;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Samba::Credentials ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	CRED_AUTO_KRB_FORWARDABLE
	CRED_FORCE_KRB_FORWARDABLE
	CRED_NO_KRB_FORWARDABLE
	CRED_AUTO_USE_KERBEROS
	CRED_DONT_USE_KERBEROS
	CRED_MUST_USE_KERBEROS
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	CRED_AUTO_KRB_FORWARDABLE
	CRED_FORCE_KRB_FORWARDABLE
	CRED_NO_KRB_FORWARDABLE
	CRED_AUTO_USE_KERBEROS
	CRED_DONT_USE_KERBEROS
	CRED_MUST_USE_KERBEROS
);

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Samba::Credentials::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Samba::Credentials', $VERSION);

# Preloaded methods go here.

sub new
{
    my $class = shift;
    my $lp = shift;

    unless (defined $lp and $lp->isa('Samba::LoadParm')) {
        die "Missing constructor argument 'Samba::LoadParm'";
    }

    my $self = {};
    bless ($self, $class);

    $self->init($lp);

    return $self;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Samba::Credentials - Extension for Samba credentials management

=head1 SYNOPSIS

  use Samba::Credentials;
  use Samba::LoadParm;

  my $lp = new Samba::LoadParm();
  $lp->load_default();

  my $creds = new Samba::Credentials($lp);
  $creds->username("foo");
  $creds->password("bar");
  $creds->guess();

=head1 DESCRIPTION

  This module implements an object interface

=over

=back

=head2 EXPORT

None by default.

=head2 Exportable constants

  CRED_AUTO_KRB_FORWARDABLE
  CRED_AUTO_USE_KERBEROS
  CRED_DONT_USE_KERBEROS
  CRED_FORCE_KRB_FORWARDABLE
  CRED_MUST_USE_KERBEROS
  CRED_NO_KRB_FORWARDABLE

=head1 SEE ALSO

  Samba::LoadParm

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
