#!/usr/bin/perl -T
use strict;
use Test::More;
BEGIN { plan tests => 2 }
use Net::Pcap;

# Testing lib_version()
my $version = '';
eval { $version = Net::Pcap::lib_version() };
is( $@, '', "lib_version()" );
like( $version, '/^libpcap version \d\.\d+\.\d+$/', " - checking version string ($version)" );
