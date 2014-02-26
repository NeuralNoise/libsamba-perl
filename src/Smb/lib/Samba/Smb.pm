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
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

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

=head1 DESCRIPTION

=over

=item C<new>

=item C<connect>

=item C<case_sensitive>

=item C<open (PATH, ARGS)>

 This function can be used to create and open a new file, to open an existing
 file, to open and truncate an existing file to zero length, to create a
 directory, or to create a connection to a named pipe.

=over

=item PATH

 The file path relative to share root.

=item ARGS

 Optional hash reference containing arguments for the SMB_COM_NT_CREATE_ANDX
 command. This hash may contain the following keys.

=over

=item access_mask

=item create_options

=item file_attr

=item share_access

=item open_disposition

=back

=back

=item C<close>

=item C<chkpath>

=item C<mkdir>

=item C<rmdir>

=item C<deltree>

=item C<rename>

=item C<unlink>

=item C<write>

=item C<read>

=item C<get_sd>

=item C<set_sd>

=item C<getattrE>

=item C<getattr>

=back

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
