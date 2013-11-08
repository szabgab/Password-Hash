package Password::Hash::Crypt;

sub make_password {
	my ($class, $password, $salt);

	return crypt($password, $salt);
}

sub method { 1 }

1;

