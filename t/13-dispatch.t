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
        plan tests => 1 * 11 + 5
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$dumper,$dump_file,$err) = ('','','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # dispatch() errors
    throws_ok(sub {
        Net::Pcap::dispatch()
    }, '/^Usage: Net::Pcap::dispatch\(p, cnt, callback, user\)/', 
       "calling dispatch() with no argument");

    throws_ok(sub {
        Net::Pcap::dispatch(undef, undef, undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling dispatch() with incorrect argument type");

}

my $user_text = "Net::Pcap test suite";
my $count = 0;

sub process_packet {
    my($user_data, $header, $packet) = @_;
    my %stats = ();

    eval { Net::Pcap::stats($pcap, \%stats) };
    is(   $@,   '', "stats()" );
    is( keys %stats, 3, " - %stats has 3 elements" );

    for my $field (qw(ps_recv ps_drop ps_ifdrop)) {
        ok( exists $stats{$field}, "    - field '$field' is present" );
        ok( defined $stats{$field}, "    - field '$field' is defined" );
        like( $stats{$field}, '/^\d+$/', "    - field '$field' is a number" );
    }

    $count++;
}

my $retval = 0;
eval { $retval = Net::Pcap::dispatch($pcap, 10, \&process_packet, $user_text) };
is(   $@,   '', "dispatch()" );
is( $count, 1, "one packet processed" );
is( $retval, $count, "checking return value" );

Net::Pcap::close($pcap);

