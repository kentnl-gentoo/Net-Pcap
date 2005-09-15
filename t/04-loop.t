#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More;
my $total;  # number of packets to process
BEGIN {
    $total = 10;
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => $total * 19 + 5
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$err) = ('','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # loop() errors
    throws_ok(sub {
        Net::Pcap::loop()
    }, '/^Usage: Net::Pcap::loop\(p, cnt, callback, user\)/', 
       "calling loop() with no argument");

    throws_ok(sub {
        Net::Pcap::loop(undef, 0, 0, 0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling loop() with incorrect argument type");

}

# Testing loop()
my $user_text = "Net::Pcap test suite";
my $count = 0;

sub process_packet {
    my($user_data, $header, $packet) = @_;

    pass( "process_packet() callback" );
    is( $user_data, $user_text, " - user data is the expected text" );
    ok( defined $header,        " - header is defined" );
    isa_ok( $header, 'HASH',    " - header" );

    for my $field (qw(len caplen tv_sec tv_usec)) {
        ok( exists $header->{$field}, "    - field '$field' is present" );
        ok( defined $header->{$field}, "    - field '$field' is defined" );
        like( $header->{$field}, '/^\d+$/', "    - field '$field' is a number" );
    }

    ok( $header->{caplen} <= $header->{len}, "    - coherency check: packet length (caplen <= len)" );

    ok( defined $packet,        " - packet is defined" );
    is( length $packet, $header->{caplen}, " - packet has the advertised size" );

    $count++;
}

my $retval = 0;
eval { $retval = Net::Pcap::loop($pcap, $total, \&process_packet, $user_text) };
is(   $@,   '', "loop()" );
is( $count, $total, "all packets processed" );
is( $retval, 0, "checking return value" );

Net::Pcap::close($pcap);

