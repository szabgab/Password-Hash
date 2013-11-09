package Password::Hash::MD5;
use strict;
use warnings;

use Digest::MD5 qw(md5_hex);

# Digets:MD5 says the returned string will be 32 bytes long

sub make_password {
	my ($class, $password, $salt) = @_;

	return md5_hex("$salt$password");
}

1;

