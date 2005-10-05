#!/usr/bin/perl -T
use strict;
use Test::More;
BEGIN { plan tests => 36 }
use Net::Pcap;

# check that the following functions are available
ok( defined &Net::Pcap::lookupdev       , "Net::Pcap::lookupdev() exists" );
ok( defined &Net::Pcap::findalldevs     , "Net::Pcap::findalldevs() exists" );
ok( defined &Net::Pcap::lookupnet       , "Net::Pcap::lookupnet() exists" );
ok( defined &Net::Pcap::open_live       , "Net::Pcap::open_live() exists" );
ok( defined &Net::Pcap::open_dead       , "Net::Pcap::open_dead() exists" );
ok( defined &Net::Pcap::setnonblock     , "Net::Pcap::setnonblock() exists" );
ok( defined &Net::Pcap::getnonblock     , "Net::Pcap::getnonblock() exists" );
ok( defined &Net::Pcap::loop            , "Net::Pcap::loop() exists" );
ok( defined &Net::Pcap::open_offline    , "Net::Pcap::open_offline() exists" );
ok( defined &Net::Pcap::close           , "Net::Pcap::close() exists" );
ok( defined &Net::Pcap::dispatch        , "Net::Pcap::dispatch() exists" );
ok( defined &Net::Pcap::next            , "Net::Pcap::next() exists" );
ok( defined &Net::Pcap::compile         , "Net::Pcap::compile() exists" );
ok( defined &Net::Pcap::freecode        , "Net::Pcap::freecode() exists" );
ok( defined &Net::Pcap::setfilter       , "Net::Pcap::setfilter() exists" );
ok( defined &Net::Pcap::dump_open       , "Net::Pcap::dump_open() exists" );
ok( defined &Net::Pcap::dump            , "Net::Pcap::dump() exists" );
ok( defined &Net::Pcap::dump_flush      , "Net::Pcap::dump_flush() exists" );
ok( defined &Net::Pcap::dump_file       , "Net::Pcap::dump_file() exists" );
ok( defined &Net::Pcap::dump_close      , "Net::Pcap::dump_close() exists" );
ok( defined &Net::Pcap::datalink        , "Net::Pcap::datalink() exists" );
ok( defined &Net::Pcap::set_datalink    , "Net::Pcap::set_datalink() exists" );
ok( defined &Net::Pcap::datalink_name_to_val        , "Net::Pcap::datalink_name_to_val() exists" );
ok( defined &Net::Pcap::datalink_val_to_name        , "Net::Pcap::datalink_val_to_name() exists" );
ok( defined &Net::Pcap::datalink_val_to_description , "Net::Pcap::datalink_val_to_description() exists" );
ok( defined &Net::Pcap::snapshot        , "Net::Pcap::snapshot() exists" );
ok( defined &Net::Pcap::is_swapped      , "Net::Pcap::is_swapped() exists" );
ok( defined &Net::Pcap::major_version   , "Net::Pcap::major_version() exists" );
ok( defined &Net::Pcap::minor_version   , "Net::Pcap::minor_version() exists" );
ok( defined &Net::Pcap::lib_version     , "Net::Pcap::lib_version() exists" );
ok( defined &Net::Pcap::stats           , "Net::Pcap::stats() exists" );
ok( defined &Net::Pcap::file            , "Net::Pcap::file() exists" );
ok( defined &Net::Pcap::fileno          , "Net::Pcap::fileno() exists" );
ok( defined &Net::Pcap::geterr          , "Net::Pcap::geterr() exists" );
ok( defined &Net::Pcap::strerror        , "Net::Pcap::strerror() exists" );
ok( defined &Net::Pcap::perror          , "Net::Pcap::perror() exists" );
