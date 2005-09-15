#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More;
BEGIN {
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => 10
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

my($dev,$net,$mask,$pcap,$filter,$res,$err) = ('','','','','','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
$res = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);


# Testing compile() with an invalid filter
eval { $res = Net::Pcap::compile($pcap, \$filter, "this is not a filter", 0, $mask) };
is(   $@,   '', "compile()" );
is(   $res, -1, " - result must not be null: $res" );
eval { $err = Net::Pcap::geterr($pcap) };
is(   $@,   '', "geterr()" );
is(   $err, 'syntax error', " - \$err must not be null" );

# Testing compile() with a valid filter
eval { $res = Net::Pcap::compile($pcap, \$filter, "tcp", 0, $mask) };
is(   $@,   '', "compile()" );
is(   $res,  0, " - result must be null: $res" );
eval { $err = Net::Pcap::geterr($pcap) };
is(   $@,   '', "geterr()" );
TODO: { local $TODO = "BUG: error string not reset";
is(   $err, '', " - \$err must be null" );
}

# Testing strerror()
eval { $err = Net::Pcap::strerror(1) };
is(   $@,   '', "strerror()" );
isnt( $err, '', " - \$err must not be null" );
