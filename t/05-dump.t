#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More;
my $total;  # number of packets to process
BEGIN {
    $total = 10;
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => $total * 20 + 8
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$dumper,$dump_file,$err) = ('','','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # dump_open() errors
    throws_ok(sub {
        Net::Pcap::dump_open()
    }, '/^Usage: Net::Pcap::dump_open\(p, fname\)/', 
       "calling dump_open() with no argument");

    throws_ok(sub {
        Net::Pcap::dump_open(undef, undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling dump_open() with incorrect argument type");

}

# Testing dump_open()
eval q{ use File::Temp qw(:mktemp); $dump_file = mktemp('pcap-XXXXXX') };
$dump_file ||= "pcap-$$.dmp";
my $user_text = "Net::Pcap test suite";
my $count = 0;
my $size = 0;

eval { $dumper = Net::Pcap::dump_open($pcap, $dump_file) };
is(   $@,   '', "dump_open()" );
ok( defined $dumper, " - dumper is defined" );

sub process_packet {
    my($user_data, $header, $packet) = @_;

    pass( "process_packet() callback" );
    is( $user_data, $user_text, " - user data is the expected text" );
    ok( defined $header,        " - header is defined" );
    isa_ok( $header, 'HASH',    " - header" );

    for my $field (qw(len caplen tv_sec tv_usec)) {
        ok( exists $header->{$field}, "    - field '$field' is present" );
        ok( defined $header->{$field}, "    - field '$field' is defined" );
        like( $header->{$field}, '/^\d+$/', "    - field '$field' is a number" );
    }

    ok( $header->{caplen} <= $header->{len}, "    - caplen <= len" );

    ok( defined $packet,        " - packet is defined" );
    is( length $packet, $header->{caplen}, " - packet has the advertised size" );

    eval { Net::Pcap::dump($dumper, $header, $packet) };
    is(   $@,   '', "dump()");

    $size += $header->{caplen};
    $count++;
}

Net::Pcap::loop($pcap, $total, \&process_packet, $user_text);
is( $count, $total, "all packets processed" );

eval { Net::Pcap::dump_close($dumper) };
is(   $@,   '', "dump_close()" );
ok( -f $dump_file, "dump file created" );
ok( -s $dump_file >= $size, "dump file size" );

Net::Pcap::close($pcap);
unlink($dump_file);

