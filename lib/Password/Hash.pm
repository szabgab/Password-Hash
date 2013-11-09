package Password::Hash;
use Moo;
use MooX::late;

my $API = 1;

has methods => (
	is      => 'rw',
	isa     => 'ArrayRef',
	default => sub { [
		'Crypt',
	]});

has iteration => (
	is      => 'rw',
	isa     => 'Int', #Positive Int?
	default => 1,
);

has generated_salt_length => (
	is      => 'rw',
	isa     => 'Int', #Positive Int?
	default => 4,
);

# maximum number of bytes for the clear-text password to avoid DDOS attacks:
# https://www.djangoproject.com/weblog/2013/sep/15/security/
has max_password_length => (
	is      => 'rw',
	isa     => 'Int', #Positive Int?
	default => 128,
);

sub make_password {
	my ($self, $password, %args) = @_;

	die 'Password too long' if length $password > $self->max_password_length;

	my $method = $self->methods->[0] or die "No method";
	my $module = _load($method);

	$args{salt}      //= $self->_generate_salt;
	$args{iteration} //= $self->iteration;

	foreach (1 .. $args{iteration}) {
		$password = $module->make_password($password, $args{salt});
	}
	return sprintf '%s$%s$%s$%s$%s', $API, $method, $args{iteration}, $args{salt}, $password;
}

sub check_password {
	my ($self, $password, $encoded) = @_;

	die 'Password too long' if length $password > $self->max_password_length;

	my ($api, $method, $iteration, $salt, $code) = split /\$/, $encoded;
	die if $api ne $API;
	die if not defined $code; # TODO more checks

	my $module = _load($method);

	my $result = $self->make_password($password, 
		iteration => $iteration,
		salt      => $salt,
	);

	return $encoded eq $result ? 1 : 0;
}

sub _load {
	my ($method) = @_;
	my $module = "Password::Hash::$method";
	eval "use $module";
	die "Unhandled method '$method' $@" if $@;
	return $module;
}


sub _generate_salt {
	my ($self) = @_;

	my @chars = ('a'..'z', 'A'..'Z', 0..9);
	my $salt = '';
	for (1 .. $self->generated_salt_length) {
		$salt .= $chars[ rand @chars ];
	}

	return $salt;
}

=head1 NAME

Password::Hash - Easy and secure storing of encrypted passwords

=head1 SYNOPSIS

Given a clear-text password convert it to an encrypted (hashed) string:

    use Password::Hash;
    my $ph = Password::Hash->new;
    my $hashed_pw = $ph->make_password('some secret'); # 1$1$abc$abM.kUMZnioHA

Given a clear-text password and a hashed string returns true if hashing the clear-text
password will lead to the same hash we passed:

    use Password::Hash;
    if ( $ph->check_password('some secret', $hashed_pw) ) {
        # the password matches
	}

=head1 DESCRIPTION

The string returned by C<make_password> has the following format:

    <api>$<algorithm>$<iterations>$<salt>$<hash>

Where 

C<api> is the internal api version of this module. It specifies the format of the strings.

C<algorithm> is one of the avaliable hahsing algorithms, (e.g. Crypt, MD5, sha1, sha256 etc).

C<iteration> is the number of times the encryption is called. It helps making the hashing be more computationally expensive.

C<salt> is a string added to the original password to reduce the possibility of rainbow attack.

C<hash> the actual hash from the one-way hashing algorithm.


=head SEE ALSO

L<Authen::Passphrase>, L<Crypt::Password::Util>, L<Crypt::Password::StretchedHash::HashInfo>

L<https://docs.djangoproject.com/en/1.5/topics/auth/passwords/>

L<http://www.pal-blog.de/entwicklung/perl/when-slower-is-better-secure-your-passwords.html>

=head1 COPYRIGHT

=encoding utf8

Copyright (c) 2013 Szabó, Gábor (http://szabgab.com/)

All right reserved. This program is free software; you can redistribute it
and/or modify it under the same terms as Perl 5.10 itself.

=cut

1;

