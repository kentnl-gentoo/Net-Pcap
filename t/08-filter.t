#!/usr/bin/perl -T
use strict;
use Test::More;
use Net::Pcap;
use lib 't';
use Utils;

plan skip_all => "must be run as root" unless is_allowed_to_use_pcap();
plan skip_all => "no network device available" unless find_network_device();
plan tests => 22;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$net,$mask,$pcap,$filter,$res,$err) = ('','','','','','','');

# Find a device and open it
$dev = find_network_device();
$res = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 10 unless $has_test_exception;

    # compile() errors
    throws_ok(sub {
        Net::Pcap::compile()
    }, '/^Usage: Net::Pcap::compile\(p, fp, str, optimize, mask\)/', 
       "calling compile() with no argument");

    throws_ok(sub {
        Net::Pcap::compile(0, 0, 0, 0, 0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling compile() with incorrect argument type for arg1");

    throws_ok(sub {
        Net::Pcap::compile($pcap, 0, 0, 0, 0)
    }, '/^arg2 not a reference/', 
       "calling compile() with incorrect argument type for arg2");

    # geterr() errors
    throws_ok(sub {
        Net::Pcap::geterr()
    }, '/^Usage: Net::Pcap::geterr\(p\)/', 
       "calling compile() with no argument");

    throws_ok(sub {
        Net::Pcap::geterr(0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling geterr() with incorrect argument type for arg1");

    # setfilter() errors
    throws_ok(sub {
        Net::Pcap::setfilter()
    }, '/^Usage: Net::Pcap::setfilter\(p, fp\)/', 
       "calling setfilter() with no argument");

    throws_ok(sub {
        Net::Pcap::setfilter(0, 0)
    }, '/^p is not of type pcap_tPtr/', 
       "calling setfilter() with incorrect argument type for arg1");

    throws_ok(sub {
        Net::Pcap::setfilter($pcap, 0)
    }, '/^fp is not of type struct bpf_programPtr/', 
       "calling setfilter() with incorrect argument type for arg2");

    # freecode() errors
    throws_ok(sub {
        Net::Pcap::freecode()
    }, '/^Usage: Net::Pcap::freecode\(fp\)/', 
       "calling freecode() with no argument");

    throws_ok(sub {
        Net::Pcap::freecode(0)
    }, '/^fp is not of type struct bpf_programPtr/', 
       "calling freecode() with incorrect argument type for arg1");

}

# Testing compile()
eval { $res = Net::Pcap::compile($pcap, \$filter, "tcp", 0, $mask) };
is(   $@,   '', "compile()" );
is(   $res,  0, " - result must be null: $res" );
ok( defined $filter, " - \$filter is defined" );
isa_ok( $filter, 'SCALAR', " - \$filter" );
isa_ok( $filter, 'struct bpf_programPtr', " - \$filter" );

# Testing geterr()
eval { $err = Net::Pcap::geterr($pcap) };
is(   $@,   '', "geterr()" );
if($res == 0) {
    is(   $err, '', " - \$err should be null" )
} else {
    isnt(   $err, '', " - \$err should not be null" )
}

# Testing setfilter()
eval { $res = Net::Pcap::setfilter($pcap, $filter) };
is(   $@,   '', "setfilter()" );
is(   $res,  0, " - result should be null: $res" );

# Testing freecode()
eval { Net::Pcap::freecode($filter) };
is(   $@,   '', "freecode()" );

# Testing geterr()
eval { $err = Net::Pcap::geterr($pcap) };
is(   $@,   '', "geterr()" );
if($res == 0) {
    is(   $err, '', " - \$err should be null" )
} else {
    isnt(   $err, '', " - \$err should not be null" )
}

Net::Pcap::close($pcap);
