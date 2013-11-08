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
	my ($self, $password) = @_;
	my $method = $self->methods->[0] or die "No method";
	my $module = "Password::Hash::$method";
	eval "use $module";
	my $salt = 'abc';

	foreach (1 .. $self->iteration) {
		$password = $module->make_password($password, $salt);
	}
	return sprintf '%s$%s$%s$%s', $module->method, $self->iteration, $salt, $password;
}

1;

