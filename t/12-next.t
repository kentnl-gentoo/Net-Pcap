#!/usr/bin/perl
#
# Test next function
#
# $Id: 12-next.t,v 1.5 1999/03/15 06:33:32 tpot Exp $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..1\n");

# Must run as root

if ($UID != 0) {
    print("not ok\n");
    exit;
}

my($dev, $pcap_t, $err, $net, $mask, $result, $filter);

#
# Test loop on open_live interface
#

$dev = Net::Pcap::lookupdev(\$err);
$result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 1, \$err);

# From test.pl, Net-Pcap-0.01.tar.gz

sub dotquad {
    my($na, $nb, $nc, $nd);
    my ( $net ) = @_ ;
    $na=$net >> 24 & 255 ;
    $nb=$net >> 16 & 255 ;
    $nc=$net >>  8 & 255 ;
    $nd=$net & 255 ;
    return ( "$na.$nb.$nc.$nd") ;
}

print ("net is ", dotquad($net), " mask is ", dotquad($mask), "\n");

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("not ok\n");
    exit;
}

$result = Net::Pcap::compile($pcap_t, \$filter, "ip", 0, $mask);

if ($result == -1) {
    print("Net::Pcap::compile returned ", Net::Pcap::geterr($pcap_t), "\n");
    print("not ok\n");
    exit;
}

$result = Net::Pcap::setfilter($pcap_t, $filter);

if ($result == -1) {
    print("Net::Pcap::setfilter returned ", Net::Pcap::geterr($pcap_t), "\n");
    print("not ok\n");
    exit;
}

for my $count (1..10) {
    my($pkt, %hdr);

    while (!($pkt = Net::Pcap::next($pcap_t, \%hdr))) {
	print("no pkt received (but that's OK)\n");
    }

    if (!defined(%hdr) or !defined($pkt)) {
	print("Bad args passed to callback\n");
	print("header is not defined\n"), if (!defined(%hdr));
	print("packet is not defined\n"), if (!defined($pkt));
	print("not ok\n");
	exit;
    }

    print("$count: received packet of len $hdr{len}\n");
}

Net::Pcap::close($pcap_t);

print("ok\n");
