#!/usr/bin/perl -T
use strict;
use Test::More;
BEGIN { plan tests => 2 }
use Net::Pcap;

# Testing lib_version()
my $version = '';
eval { $version = Net::Pcap::lib_version() };
is( $@, '', "lib_version()" );
if ($^O eq 'MSWin32' or $^O eq 'cygwin') {
    like( $version, '/^WinPcap version \d\.\d+/', " - checking version string ($version)" );
} else {
    like( $version, '/^libpcap version \d\.\d+\.\d+$/', " - checking version string ($version)" );
}
