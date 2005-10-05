#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More ;#skip_all => "this script is sloooooooooow";
my $total;  # number of packets to process
BEGIN {
    $total = 3;
    use lib 't';
    require 'CheckAuth.pl';

    if(is_allowed_to_use_pcap()) {
        plan tests => $total * 16 + 4
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$net,$mask,$filter,$err) = ('','','','','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 3 unless $has_test_exception;

    # next() errors
    throws_ok(sub {
        Net::Pcap::next()
    }, '/^Usage: Net::Pcap::next\(p, h\)/', 
       "calling next() with no argument");

    throws_ok(sub {
        Net::Pcap::next(0, 0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling next() with incorrect argument type for arg1");

    throws_ok(sub {
        Net::Pcap::next($pcap, 0)
    }, '/^arg2 not a hash ref/', 
       "calling next() with incorrect argument type for arg2");

}

# Compile and set a filter
Net::Pcap::compile($pcap, \$filter, "ip", 0, $mask);
Net::Pcap::setfilter($pcap, $filter);

# Test next()
my $count = 0;
for (1..$total) {
    my($packet, %header);
    eval { $packet = Net::Pcap::next($pcap, \%header) };
    is( $@, '', "next()" );
    
    for my $field (qw(len caplen tv_sec tv_usec)) {
        ok( exists $header{$field}, " - field '$field' is present" );
        ok( defined $header{$field}, " - field '$field' is defined" );
        like( $header{$field}, '/^\d+$/', " - field '$field' is a number" );
    }

    ok( $header{caplen} <= $header{len}, " - coherency check: packet length (caplen <= len)" );

    ok( defined $packet, " - packet is defined" );
    is( length $packet, $header{caplen}, " - packet has the advertised size" );

    $count++;
}

is( $count, $total, "all packets processed" );

Net::Pcap::close($pcap);
