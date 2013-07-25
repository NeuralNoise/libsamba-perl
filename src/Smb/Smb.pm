package Samba::Smb;

use strict;
use warnings;

require XSLoader;

our $VERSION = '0.01';

XSLoader::load('Samba::Smb', $VERSION);

sub new
{
  my ($class, %params) = @_;

  my $self = {};
  bless ($self, $class);

  my $hostname = $params{hostname};
  my $service = $params{service};
  $self->{context} = _smb_new($hostname, $service);

  return $self;
}

1;
