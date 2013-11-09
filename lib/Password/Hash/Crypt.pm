package Password::Hash::Crypt;
use strict;
use warnings;

sub make_password {
	my ($class, $password, $salt) = @_;

	return crypt($password, $salt);
}

1;

