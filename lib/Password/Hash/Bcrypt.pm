package Password::Hash::Bcrypt;
use strict;
use warnings;

use Digest::Bcrypt;

sub make_password {
	my ($class, $password, $salt) = @_;

	my $db = Digest::Bcrypt->new;
	$db->salt($salt);
	$db->cost(1);
	$db->add($password);

	return $db->hexdigest;
}

1;




