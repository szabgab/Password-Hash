package Password::Hash::SHA1;
use strict;
use warnings;

use Digest::SHA qw(sha1_hex);

sub make_password {
	my ($class, $password, $salt) = @_;

	return sha1_hex("$salt$password");
}

1;


