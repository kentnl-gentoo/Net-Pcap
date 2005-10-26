#!/usr/bin/perl -T
use strict;
use Test::More;
use lib 't';
use Utils;
my @sizes;  # snapshot sizes
BEGIN {
    @sizes = (128, 512, 1024, 2048, 4096, 8192, int(10000*rand), int(10000*rand), int(10000*rand), int(10000*rand));

    if(is_allowed_to_use_pcap()) {
        plan tests => @sizes * 2 + 2
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$snapshot,$err) = ('','','','');

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # snapshot() errors
    throws_ok(sub {
        Net::Pcap::snapshot()
    }, '/^Usage: Net::Pcap::snapshot\(p\)/', 
       "calling snapshot() with no argument");

    throws_ok(sub {
        Net::Pcap::snapshot(0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling snapshot() with incorrect argument type");
}

# Find a device
$dev = Net::Pcap::lookupdev(\$err);

for my $size (@sizes) {
    # Open the device
    $pcap = Net::Pcap::open_live($dev, $size, 1, 0, \$err);

    # Testing snapshot()
    $snapshot = 0;
    eval { $snapshot = Net::Pcap::snapshot($pcap) };
    is( $@, '', "snapshot()" );
    is( $snapshot, $size, " - snapshot has the expected size" );
    Net::Pcap::close($pcap);
}

