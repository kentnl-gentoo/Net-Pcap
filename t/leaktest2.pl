#!/usr/bin/perl
#
# Test for memory leaks in lookup functions
#
# $Id: leaktest2.pl,v 1.2 1999/03/14 03:14:10 tpot Exp $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

my($dev, $net, $mask, $err, $result);

while(1) {
    $dev = Net::Pcap::lookupdev(\$err);
    $result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
}
