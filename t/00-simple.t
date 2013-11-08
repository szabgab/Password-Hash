use strict;
use warnings;

use Test::More;

plan tests => 1;

use Password::Hash;
my $ph = Password::Hash->new;
isa_ok $ph, 'Password::Hash';

