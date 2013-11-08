package Password::Hash;
use Moo;
use MooX::late;

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

has salt_length => (
	is      => 'rw',
	isa     => 'Int', #Positive Int?
	default => 4,
);

sub make_password {
	my ($self, $password, %args) = @_;
	my $method = $self->methods->[0] or die "No method";
	my $module = "Password::Hash::$method";
	eval "use $module";
	$args{salt}      //= 'abc';
	$args{iteration} //= $self->iteration;

	foreach (1 .. $args{iteration}) {
		$password = $module->make_password($password, $args{salt});
	}
	return sprintf '%s$%s$%s$%s', $module->method_id, $args{iteration}, $args{salt}, $password;
}

sub check_password {
	my ($self, $password, $encoded) = @_;

	my ($method_id, $iteration, $salt, $code) = split /\$/, $encoded;
	my $method;
	foreach my $m (@{ $self->methods }) {
		my $module = "Password::Hash::$m";
		eval "use $module";
		my $m_id = $module->method_id;
		if ($method_id == $m_id) {
			$method = $m;
			last;
		}
	}
	die "Unhandled method" if not $method;

	my $result = $self->make_password($password, 
		iteration => $iteration,
		salt      => $salt,
	);

	return $encoded eq $result ? 1 : 0;
}





1;

