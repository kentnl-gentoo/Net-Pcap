#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More;
BEGIN {
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => 14
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$err) = ('','','');


# Testing error messages
SKIP: {
    skip "Test::Exception not available", 4 unless $has_test_exception;

    # open_live() errors
    throws_ok(sub {
        Net::Pcap::open_live()
    }, '/^Usage: Net::Pcap::open_live\(device, snaplen, promisc, to_ms, err\)/', 
       "calling open_live() with no argument");

    throws_ok(sub {
        Net::Pcap::open_live(0, 0, 0, 0, undef)
    }, '/^arg5 not a reference/', 
       "calling open_live() with no reference for arg5");

    # close() errors
    throws_ok(sub {
        Net::Pcap::close()
    }, '/^Usage: Net::Pcap::close\(p\)/', 
       "calling close() with no argument");

    throws_ok(sub {
        Net::Pcap::close(undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling close() with incorrect argument type");

}

# Find a device
$dev = Net::Pcap::lookupdev(\$err);

# Testing open_live()
eval { $pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err) };
is(   $@,   '', "open_live()" );
is(   $err, '', " - \$err must be null: $err" ); $err = '';
ok( defined $pcap, " - \$pcap is defined" );
isa_ok( $pcap, 'SCALAR', " - \$pcap" );
isa_ok( $pcap, 'pcap_tPtr', " - \$pcap" );

# Testing close()
eval { Net::Pcap::close($pcap) };
is(   $@,   '', "close()" );
is(   $err, '', " - \$err must be null: $err" ); $err = '';

# Testing open_live() with fake device name
eval { $pcap = Net::Pcap::open_live('this is not a device', 1024, 1, 0, \$err) };
is(   $@,   '', "open_live()" );
like( $err, '/^ioctl: (?:No such device)/', " - \$err must be set: $err" ); $err = '';
is( $pcap, undef, " - \$pcap isn't defined" );

