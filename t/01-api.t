#!/usr/bin/perl -T
use strict;
use Test::More;
BEGIN { plan tests => 36 }
use Net::Pcap;

# check that the following functions are available
can_ok( 'Net::Pcap', 'Net::Pcap::lookupdev' );
can_ok( 'Net::Pcap', 'Net::Pcap::findalldevs' );
can_ok( 'Net::Pcap', 'Net::Pcap::lookupnet' );
can_ok( 'Net::Pcap', 'Net::Pcap::open_live' );
can_ok( 'Net::Pcap', 'Net::Pcap::open_dead' );
can_ok( 'Net::Pcap', 'Net::Pcap::setnonblock' );
can_ok( 'Net::Pcap', 'Net::Pcap::getnonblock' );
can_ok( 'Net::Pcap', 'Net::Pcap::loop' );
can_ok( 'Net::Pcap', 'Net::Pcap::open_offline' );
can_ok( 'Net::Pcap', 'Net::Pcap::close' );
can_ok( 'Net::Pcap', 'Net::Pcap::dispatch' );
can_ok( 'Net::Pcap', 'Net::Pcap::next' );
can_ok( 'Net::Pcap', 'Net::Pcap::compile' );
can_ok( 'Net::Pcap', 'Net::Pcap::freecode' );
can_ok( 'Net::Pcap', 'Net::Pcap::setfilter' );
can_ok( 'Net::Pcap', 'Net::Pcap::dump_open' );
can_ok( 'Net::Pcap', 'Net::Pcap::dump' );
can_ok( 'Net::Pcap', 'Net::Pcap::dump_flush' );
can_ok( 'Net::Pcap', 'Net::Pcap::dump_file' );
can_ok( 'Net::Pcap', 'Net::Pcap::dump_close' );
can_ok( 'Net::Pcap', 'Net::Pcap::datalink' );
can_ok( 'Net::Pcap', 'Net::Pcap::set_datalink' );
can_ok( 'Net::Pcap', 'Net::Pcap::datalink_name_to_val' );
can_ok( 'Net::Pcap', 'Net::Pcap::datalink_val_to_name' );
can_ok( 'Net::Pcap', 'Net::Pcap::datalink_val_to_description' );
can_ok( 'Net::Pcap', 'Net::Pcap::snapshot' );
can_ok( 'Net::Pcap', 'Net::Pcap::is_swapped' );
can_ok( 'Net::Pcap', 'Net::Pcap::major_version' );
can_ok( 'Net::Pcap', 'Net::Pcap::minor_version' );
can_ok( 'Net::Pcap', 'Net::Pcap::lib_version' );
can_ok( 'Net::Pcap', 'Net::Pcap::stats' );
can_ok( 'Net::Pcap', 'Net::Pcap::file' );
can_ok( 'Net::Pcap', 'Net::Pcap::fileno' );
can_ok( 'Net::Pcap', 'Net::Pcap::geterr' );
can_ok( 'Net::Pcap', 'Net::Pcap::strerror' );
can_ok( 'Net::Pcap', 'Net::Pcap::perror' );
