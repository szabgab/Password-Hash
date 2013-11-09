use strict;
use warnings;

use Test::More;

my $N = 1;

my @cases = (
	{
		methods => [qw(Crypt MD5)],
	},
	{
		methods => [qw(MD5 Crypt)],
	},
	{
		methods => [qw(SHA1)],
	},
	{
		methods => [qw(SHA512)],
	},
	{
		methods => [qw(Bcrypt)],
		generated_salt_length => 16,
	},
);

plan tests => 1 + 2 * $N * @cases;

use Password::Hash;

subtest 'default' => sub {
	my $ph = Password::Hash->new;
	isa_ok $ph, 'Password::Hash';

	my $hashed_pw = $ph->make_password('hello world');
	#diag $hashed_pw;
	ok $ph->check_password('hello world', $hashed_pw), 'pw matches';
	ok !$ph->check_password('Hello world', $hashed_pw), 'wrong pw does not match';
};

foreach my $c (@cases) {
	my $ph = Password::Hash->new(%$c);

	foreach (1 .. $N) {
		my $pw = 'hello world';
		my $hashed_pw = $ph->make_password($pw);
		my ($api, $method, $iteration, $salt, $hash) = split /\$/, $hashed_pw;
		is $method, $c->{methods}[0], "method is $c->{methods}[0]";
		#diag $hashed_pw;
		ok $ph->check_password($pw, $hashed_pw), "pw matches $c->{methods}[0]";
	}
}


