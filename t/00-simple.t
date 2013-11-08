use strict;
use warnings;

use Test::More;

plan tests => 3;

use Password::Hash;
my $ph = Password::Hash->new;
isa_ok $ph, 'Password::Hash';

my $pw = $ph->make_password('hello world');
#diag $pw;
ok $ph->check_password('hello world', $pw), 'pw matches';
ok !$ph->check_password('Hello world', $pw), 'wrong pw does not match';

