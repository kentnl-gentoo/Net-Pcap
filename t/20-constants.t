#!/usr/bin/perl -T
use strict;
use Test::More;
my @names;
BEGIN {
    if(open(MACROS, 'macros.all')) {
        @names = map {chomp;$_} <MACROS>;
        close(MACROS);
        plan tests => @names + 3;
    } else {
        plan skip_all => "can't read 'macros.all': $!"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 1 unless $has_test_exception;

    # constant() errors
    throws_ok(sub {
        Net::Pcap::constant()
    }, '/^Usage: Net::Pcap::constant\(sv\)/',
       "calling constant() with no argument");
}

# Testing constant()
like( Net::Pcap::constant('This'), 
    '/^This is not a valid pcap macro/', 
    "calling constant() with a non existing name" );

like( Net::Pcap::constant('NOSUCHNAME'), 
    '/^NOSUCHNAME is not a valid pcap macro/', 
    "calling constant() with a non existing name" );

# Testing all macros
if(@names) {
    for my $name (@names) {
        like( Net::Pcap::constant($name), 
              '/^(?:\d+|Your vendor has not defined pcap macro '.$name.', used)$/', 
              "checking that $name is a number (".Net::Pcap::constant($name).")" );
    }
}

