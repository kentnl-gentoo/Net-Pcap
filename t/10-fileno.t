#!/usr/bin/perl -T
use strict;
use File::Spec;
use Socket;
use Test::More;
BEGIN { plan tests => 16 }
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$filehandle,$fileno,$err) = ('','','','','');

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # file() errors
    throws_ok(sub {
        Net::Pcap::file()
    }, '/^Usage: Net::Pcap::file\(p\)/', 
       "calling file() with no argument");

    throws_ok(sub {
        Net::Pcap::file(undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling file() with incorrect argument type");

    # fileno() errors
    throws_ok(sub {
        Net::Pcap::fileno()
    }, '/^Usage: Net::Pcap::fileno\(p\)/', 
       "calling fileno() with no argument");

    throws_ok(sub {
        Net::Pcap::fileno(undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling fileno() with incorrect argument type");
}

SKIP: {
    my $proto = getprotobyname('icmp');
    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
    } else {
        skip "must be run as root", 6
    }

    # Find a device and open it
    $dev = Net::Pcap::lookupdev(\$err);
    $pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);
    isa_ok( $pcap, 'pcap_tPtr', "\$pcap" );

    # Testing file()
    eval { $filehandle = Net::Pcap::file($pcap) };
    is( $@, '', "file() on a live connection" );
    TODO: {
        local $TODO = "file() currently seems to always return undef";
        $filehandle = undef;
        ok( defined $filehandle, " - returned filehandle must be defined" );
        isa_ok( $filehandle, 'GLOB', " - \$filehandle" );
    }

    # Testing fileno()
    $fileno = undef;
    eval { $fileno = Net::Pcap::fileno($pcap) };
    is( $@, '', "fileno() on a live connection" );
    like( $fileno, '/^\d+$/', " - fileno must be an integer" );

    Net::Pcap::close($pcap);
}

# Open a sample dump
$pcap = Net::Pcap::open_offline(File::Spec->catfile(qw(t samples ping-ietf-20pk-be.dmp)), \$err);
isa_ok( $pcap, 'pcap_tPtr', "\$pcap" );

# Testing file()
TODO: {
    todo_skip "file() on a dump file currently causes a segmentation fault", 3;
    eval { $filehandle = Net::Pcap::file($pcap) };
    is( $@, '', "file() on a dump file" );
    ok( defined $filehandle, " - returned filehandle must be defined" );
    isa_ok( $filehandle, 'GLOB', " - \$filehandle" );
}

# Testing fileno()
eval { $fileno = Net::Pcap::fileno($pcap) };
is( $@, '', "fileno() on a dump file" );
like( $fileno, '/^\d+$/', " - fileno must be an integer" );

Net::Pcap::close($pcap);

