#!/usr/bin/perl -T
use strict;
use Test::More;
BEGIN { plan tests => 5 }
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($pcap,$datalink) = ('',0);  # datalink == DLT_NULL => no link-layer encapsulation

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 1 unless $has_test_exception;

    # open_dead() errors
    throws_ok(sub {
        Net::Pcap::open_dead()
    }, '/^Usage: Net::Pcap::open_dead\(linktype, snaplen\)/',
       "calling open_dead() with no argument");
}

# Testing open_dead()
eval { $pcap = Net::Pcap::open_dead($datalink, 1024) };
is( $@, '', "open_dead()" );
ok( defined $pcap, " - \$pcap is defined" );
isa_ok( $pcap, 'SCALAR', " - \$pcap" );
isa_ok( $pcap, 'pcap_tPtr', " - \$pcap" );
