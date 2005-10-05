#!/usr/bin/perl -T
use strict;
use File::Spec;
use Socket;
use Test::More;
BEGIN { plan tests => 23 }
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
        Net::Pcap::setnonblock(0, 0, 0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling setnonblock() with incorrect argument type");

    # getnonblock() errors
    throws_ok(sub {
        Net::Pcap::getnonblock()
    }, '/^Usage: Net::Pcap::getnonblock\(p\, err\)/', 
       "calling getnonblock() with no argument");

    throws_ok(sub {
        Net::Pcap::getnonblock(0, 0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling getnonblock() with incorrect argument type");
}

SKIP: {
    use lib 't';
    require 'CheckAuth.pl';

    unless(is_allowed_to_use_pcap()) {
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

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    throws_ok(sub {
        Net::Pcap::setnonblock($pcap, 0, 0)
    }, '/^arg3 not a reference/', 
       "calling setnonblock() with incorrect argument type for arg3");

    throws_ok(sub {
        Net::Pcap::getnonblock($pcap, 0)
    }, '/^arg2 not a reference/', 
       "calling getnonblock() with incorrect argument type for arg2");
}

# Testing getnonblock()
eval { $r = Net::Pcap::getnonblock($pcap, \$err) };
is( $@,   '', "getnonblock()" );
is( $err, '', " - err must be null" );
is( $r,    0, " - state must be 0 for savefile" );

Net::Pcap::close($pcap);
