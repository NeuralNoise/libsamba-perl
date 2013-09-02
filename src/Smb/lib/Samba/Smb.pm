package Samba::Smb;

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

# This allows declaration	use Samba::Smb ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
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
    DENY_DOS
    DENY_ALL
    DENY_WRITE
    DENY_READ
    DENY_NONE
    DENY_FCB
    DOS_OPEN_RDONLY
    DOS_OPEN_WRONLY
    DOS_OPEN_RDWR
    DOS_OPEN_FCB
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
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
    DENY_DOS
    DENY_ALL
    DENY_WRITE
    DENY_READ
    DENY_NONE
    DENY_FCB
    DOS_OPEN_RDONLY
    DOS_OPEN_WRONLY
    DOS_OPEN_RDWR
    DOS_OPEN_FCB
);

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Samba::Smb::constant not defined" if $constname eq 'constant';
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
XSLoader::load('Samba::Smb', $VERSION);

# Preloaded methods go here.

sub new
{
    my $class = shift;
    my $lp = shift;
    my $creds = shift;

    my $self = {};
    bless ($self, $class);

    $self->init($lp, $creds);

    return $self;
}

sub list
{
    my ($self, $base, %opt_args) = @_;

    my $mask = '*';

    my ($error1, $val1) = constant('FILE_ATTRIBUTE_SYSTEM');
    croak ($error1) if $error1;
    my ($error2, $val2) = constant('FILE_ATTRIBUTE_DIRECTORY');
    croak ($error2) if $error2;
    my ($error3, $val3) = constant('FILE_ATTRIBUTE_ARCHIVE');
    croak ($error3) if $error3;

    my $attrs = ($val1 | $val2 | $val3);
    my $recursive = 0;

    unless (defined $base and length $base) {
        croak "Base directory not defined.";
    }

    if (exists $opt_args{mask}) {
        $mask = delete $opt_args{mask};
    }
    if (exists $opt_args{attributes}) {
        $attrs = delete $opt_args{attributes};
    }
    if (exists $opt_args{recursive}) {
        $recursive = delete $opt_args{recursive};
    }

    return $self->_list($base, $mask, $attrs, $recursive);
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 NAME

Samba::Smb - Perl bindings for libsmbclient-raw

=head1 SYNOPSIS

  use Samba::Smb;

  my $smb = new Samba::Smb($lp, $creds, $target, $service);

=head1 DESCRIPTION

  This module implements an object interface

=head2 EXPORT

None by default.

=head2 Exportable constants

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
  DENY_DOS
  DENY_ALL
  DENY_WRITE
  DENY_READ
  DENY_NONE
  DENY_FCB
  DOS_OPEN_RDONLY
  DOS_OPEN_WRONLY
  DOS_OPEN_RDWR
  DOS_OPEN_FCB

=head1 SEE ALSO

    Samba::LoadParm
    Samba::Credentials

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
