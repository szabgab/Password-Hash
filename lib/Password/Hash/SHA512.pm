package Password::Hash::SHA512;
use strict;
use warnings;

use Digest::SHA qw(sha512_hex);

sub make_password {
	my ($class, $password, $salt) = @_;

	return sha512_hex("$salt$password");
}

1;



