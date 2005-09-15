#!/usr/bin/perl -T
use strict;
use File::Spec;
use Socket;
use Test::More;
BEGIN { plan tests => 8 }
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$datalink,$err) = ('','','','');

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 1 unless $has_test_exception;

    # datalink() errors
    throws_ok(sub {
        Net::Pcap::datalink()
    }, '/^Usage: Net::Pcap::datalink\(p\)/', 
       "calling datalink() with no argument");

    throws_ok(sub {
        Net::Pcap::datalink(undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling datalink() with incorrect argument type");
}

SKIP: {
    my $proto = getprotobyname('icmp');
    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
    } else {
        skip "must be run as root", 3
    }

    # Find a device and open it
    $dev = Net::Pcap::lookupdev(\$err);
    $pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);
    isa_ok( $pcap, 'pcap_tPtr', "\$pcap" );

    # Testing datalink()
    $datalink = '';
    eval { $datalink = Net::Pcap::datalink($pcap) };
    is( $@, '', "datalink() on a live connection" );
    like( $datalink , '/^\d+$/', " - datalink is an integer" );

    Net::Pcap::close($pcap);
}

# Open a sample dump
$pcap = Net::Pcap::open_offline(File::Spec->catfile(qw(t samples ping-ietf-20pk-be.dmp)), \$err);
isa_ok( $pcap, 'pcap_tPtr', "\$pcap" );

# Testing datalink()
$datalink = '';
eval { $datalink = Net::Pcap::datalink($pcap) };
is( $@, '', "datalink() on a dump file" );
like( $datalink , '/^\d+$/', " - datalink is an integer" );

Net::Pcap::close($pcap);
