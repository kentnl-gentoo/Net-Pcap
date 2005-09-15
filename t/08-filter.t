#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More;
BEGIN {
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => 19
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$net,$mask,$pcap,$filter,$res,$err) = ('','','','','','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
$res = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 8 unless $has_test_exception;

    # compile() errors
    throws_ok(sub {
        Net::Pcap::compile()
    }, '/^Usage: Net::Pcap::compile\(p, fp, str, optimize, mask\)/', 
       "calling compile() with no argument");

    throws_ok(sub {
        Net::Pcap::compile(undef, undef, undef, undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling compile() with incorrect argument type for arg1");

    throws_ok(sub {
        Net::Pcap::compile($pcap, undef, undef, undef, undef)
    }, '/^arg2 not a reference/', 
       "calling compile() with incorrect argument type for arg2");

    # geterr() errors
    throws_ok(sub {
        Net::Pcap::geterr()
    }, '/^Usage: Net::Pcap::geterr\(p\)/', 
       "calling compile() with no argument");

    throws_ok(sub {
        Net::Pcap::geterr(undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling geterr() with incorrect argument type for arg1");

    # setfilter() errors
    throws_ok(sub {
        Net::Pcap::setfilter()
    }, '/^Usage: Net::Pcap::setfilter\(p, fp\)/', 
       "calling setfilter() with no argument");

    throws_ok(sub {
        Net::Pcap::setfilter(undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling setfilter() with incorrect argument type for arg1");

    throws_ok(sub {
        Net::Pcap::setfilter($pcap, undef)
    }, '/^fp is not of type struct bpf_programPtr/', 
       "calling setfilter() with incorrect argument type for arg2");

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

# Testing geterr()
eval { $err = Net::Pcap::geterr($pcap) };
is(   $@,   '', "geterr()" );
if($res == 0) {
    is(   $err, '', " - \$err should be null" )
} else {
    isnt(   $err, '', " - \$err should not be null" )
}

Net::Pcap::close($pcap);
