#!/usr/bin/perl -T
use strict;
use Test::More;
BEGIN { plan tests => 22 }
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$net,$mask,$result,$err) = ('','','','','');
my @devs = ();
my $ip_regexp = '/^[12]?\d+\.[12]?\d+\.[12]?\d+\.[12]?\d+$/';


# Testing error messages
SKIP: {
    skip "Test::Exception not available", 8 unless $has_test_exception;

    # lookupdev() errors
    throws_ok(sub {
        Net::Pcap::lookupdev()
    }, '/^Usage: Net::Pcap::lookupdev\(err\)/', 
       "calling lookupdev() with no argument");

    throws_ok(sub {
        Net::Pcap::lookupdev(undef)
    }, '/^arg1 not a hash ref/', 
       "calling lookupdev() with incorrect argument type");

    # findalldevs() errors
    throws_ok(sub {
        Net::Pcap::findalldevs()
    }, '/^Usage: Net::Pcap::findalldevs\(err\)/', 
       "calling findalldevs() with no argument");

    throws_ok(sub {
        Net::Pcap::findalldevs(undef)
    }, '/^arg1 not a reference/', 
       "calling findalldevs() with incorrect argument type");

    # lookupnet() errors
    throws_ok(sub {
        Net::Pcap::lookupnet()
    }, '/^Usage: Net::Pcap::lookupnet\(device, net, mask, err\)/', 
       "calling lookupnet() with no argument");

    throws_ok(sub {
        Net::Pcap::lookupnet('', undef, undef, undef)
    }, '/^arg2 not a reference/', 
       "calling lookupnet() with incorrect argument type for arg2");

    throws_ok(sub {
        Net::Pcap::lookupnet('', \$net, undef, undef)
    }, '/^arg3 not a reference/', 
       "calling lookupnet() with incorrect argument type for arg3");

    throws_ok(sub {
        Net::Pcap::lookupnet('', \$net, \$mask, undef)
    }, '/^arg4 not a reference/', 
       "calling lookupnet() with incorrect argument type for arg4");
}

# Testing lookupdev()
eval { $dev = Net::Pcap::lookupdev(\$err) };
is(   $@,   '', "lookupdev()" );
is(   $err, '', " - \$err must be null: $err" ); $err = '';
isnt( $dev, '', " - \$dev isn't null: '$dev'" );

# Testing findalldevs()
eval { @devs = Net::Pcap::findalldevs(\$err) };
is(   $@,   '', "findalldevs()" );
is(   $err, '', " - \$err must be null: $err" ); $err = '';
ok( @devs >= 1, " - at least one device must be present in the list returned by findalldevs()" );
my %devs = map { $_ => 1 } @devs;
is( $devs{$dev}, 1, " - '$dev' must be present in the list returned by findalldevs()" );

# Testing lookupnet()
eval { $result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err) };
is(   $@,    '', "lookupnet()" );
is(   $err,  '', " - \$err must be null: $err" ); $err = '';
is(  $result, 0, " - \$result must be null: $result" );
isnt( $net,  '', " - \$net isn't null: '$net' => ".dotquad($net) );
isnt( $mask, '', " - \$mask isn't null: '$mask' => ".dotquad($mask) );
like( dotquad($net),  $ip_regexp, " - does \$net look like an IP address ?" );
like( dotquad($mask), $ip_regexp, " - does \$mask look like an IP address ?" );


sub dotquad {
    my($na, $nb, $nc, $nd);
    my($net) = @_ ;
    $na = $net >> 24 & 255 ;
    $nb = $net >> 16 & 255 ;
    $nc = $net >>  8 & 255 ;
    $nd = $net & 255 ;
    return "$na.$nb.$nc.$nd"
}
