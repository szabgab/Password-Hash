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
);

plan tests => 3 + $N * @cases;

use Password::Hash;
my $ph = Password::Hash->new;
isa_ok $ph, 'Password::Hash';

my $hashed_pw = $ph->make_password('hello world');
#diag $hashed_pw;
ok $ph->check_password('hello world', $hashed_pw), 'pw matches';
ok !$ph->check_password('Hello world', $hashed_pw), 'wrong pw does not match';

foreach my $c (@cases) {
	my $p = Password::Hash->new(%$c);

	foreach (1 .. $N) {
		my $pw = 'hello world';
		my $hashed_pw = $ph->make_password($pw);
		ok $ph->check_password($pw, $hashed_pw), "pw matches $c->{methods}[0]";
	}
}


