#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More skip_all => "this script hangs for unknown reason";
my $total;  # number of packets to process
BEGIN {
    $total = 5;
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => $total * 15 + 3
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$net,$mask,$filter,$err) = ('','','','','','');

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # next() errors
    throws_ok(sub {
        Net::Pcap::next()
    }, '/^Usage: Net::Pcap::next\(p, h\)/', 
       "calling next() with no argument");

    throws_ok(sub {
        Net::Pcap::next(undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling next() with incorrect argument type");

}

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Compile and set a filter
Net::Pcap::compile($pcap, \$filter, "ip", 0, $mask);
Net::Pcap::setfilter($pcap, $filter);

# Test next()
my $count = 0;
for $count (1..$total) {
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
}

is( $count, $total, "all packets processed" );


sub dotquad {
    my($na, $nb, $nc, $nd);
    my($net) = @_ ;
    $na = $net >> 24 & 255 ;
    $nb = $net >> 16 & 255 ;
    $nc = $net >>  8 & 255 ;
    $nd = $net & 255 ;
    return "$na.$nb.$nc.$nd"
}

