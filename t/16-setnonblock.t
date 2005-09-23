#!/usr/bin/perl -T
use strict;
use File::Spec;
use Socket;
use Test::More;
BEGIN { plan tests => 21 }
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$r,$err) = ('','','','');

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 4 unless $has_test_exception;

    # setnonblock() errors
    throws_ok(sub {
        Net::Pcap::setnonblock()
    }, '/^Usage: Net::Pcap::setnonblock\(p\, nb, err\)/', 
       "calling setnonblock() with no argument");

    throws_ok(sub {
        Net::Pcap::setnonblock(undef, undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling setnonblock() with incorrect argument type");

    # getnonblock() errors
    throws_ok(sub {
        Net::Pcap::getnonblock()
    }, '/^Usage: Net::Pcap::getnonblock\(p\, err\)/', 
       "calling getnonblock() with no argument");

    throws_ok(sub {
        Net::Pcap::getnonblock(undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling getnonblock() with incorrect argument type");
}

SKIP: {
    my $proto = getprotobyname('icmp');
    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
    } else {
        skip "must be run as root", 13
    }

    # Find a device and open it
    $dev = Net::Pcap::lookupdev(\$err);
    $pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);
    isa_ok( $pcap, 'pcap_tPtr', "\$pcap" );

    for my $state (0, 1) {
        # Testing setnonblock()
        eval { $r = Net::Pcap::setnonblock($pcap, $state, \$err) };
        is( $@,   '', "setnonblock() state=$state" );
        is( $err, '', " - err must be null" );
        is( $r,    0, " - should return zero" );

        # Testing getnonblock()
        eval { $r = Net::Pcap::getnonblock($pcap, \$err) };
        is( $@,     '', "getnonblock()" );
        is( $err,   '', " - err must be null" );
        is( $r, $state, " - state must be $state" );
    }

    Net::Pcap::close($pcap);
}

# Open a sample dump
$pcap = Net::Pcap::open_offline(File::Spec->catfile(qw(t samples ping-ietf-20pk-be.dmp)), \$err);
isa_ok( $pcap, 'pcap_tPtr', "\$pcap" );

# Testing getnonblock()
eval { $r = Net::Pcap::getnonblock($pcap, \$err) };
is( $@,   '', "getnonblock()" );
is( $err, '', " - err must be null" );
is( $r,    0, " - state must be 0 for savefile" );

Net::Pcap::close($pcap);
