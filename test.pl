#!/usr/local/bin/perl
require 5.003 ;
require Net::Pcap ;

# All numbers in HEX

$ethertype_name{'0060'} = 'LOOP  ' ;
$ethertype_name{'0200'} = 'ECHO  ' ;
$ethertype_name{'0400'} = 'PUP   ' ;
$ethertype_name{'0500'} = 'SPRITE' ;
$ethertype_name{'0600'} = 'NS    ' ;
$ethertype_name{'0800'} = 'IP    ' ;
$ethertype_name{'0801'} = 'X75   ' ;
$ethertype_name{'0802'} = 'NBS   ' ;
$ethertype_name{'0803'} = 'ECMA  ' ;
$ethertype_name{'0804'} = 'CHAOS ' ;
$ethertype_name{'0805'} = 'X25   ' ;
$ethertype_name{'0806'} = 'ARP   ' ;
$ethertype_name{'1000'} = 'TRAIL ' ;
$ethertype_name{'6000'} = 'DEC   ' ;
$ethertype_name{'6001'} = 'DNA_DL' ; # MOPDL
$ethertype_name{'6002'} = 'DNA_RC' ; # MOPRC
$ethertype_name{'6003'} = 'DNA_RT' ; # Phase IV DECnet
$ethertype_name{'6004'} = 'LAT   ' ;
$ethertype_name{'6005'} = 'DIAG  ' ;
$ethertype_name{'6006'} = 'CUST  ' ;
$ethertype_name{'6007'} = 'SCA   ' ;
$ethertype_name{'8035'} = 'RARP  ' ;
$ethertype_name{'8038'} = 'LANBRG' ; # DEC LANBridge
$ethertype_name{'803C'} = 'DECDNS' ;
$ethertype_name{'803E'} = 'DECDTS' ;
$ethertype_name{'805B'} = 'VEXP  ' ;
$ethertype_name{'805C'} = 'VPROD ' ;
$ethertype_name{'809B'} = 'ATALK ' ;
$ethertype_name{'80F3'} = 'AARP  ' ;
$ethertype_name{'8137'} = 'IPX   ' ;
$ethertype_name{'86DD'} = 'IPV6  ' ; 
$ethertype_name{'9000'} = 'LBACK ' ; # MOP
$ethertype_name{'0A00' } = 'PUP   ' ; # Xerox IEEE802.3 PUP
$ethertype_name{'0A01' } = 'PUP-AT' ; # Xerox IEEE802.3 PUP Address Translation

# All numbers in HEX

$ip_type_name{'00'}='IP  ' ;
$ip_type_name{'01'}='ICMP' ;
$ip_type_name{'02'}='IGMP' ;
$ip_type_name{'03'}='GGP ' ;
$ip_type_name{'04'}='IPIP' ;
$ip_type_name{'06'}='TCP ' ;
$ip_type_name{'08'}='EGP ' ;
$ip_type_name{'09'}='IGRP' ;
$ip_type_name{'0C'}='PUP ' ; # 12
$ip_type_name{'11'}='UDP ' ; # 17
$ip_type_name{'16'}='IDP ' ; # 22 XNS IDP
$ip_type_name{'1D'}='TP  ' ; # 29
$ip_type_name{'2F'}='GRE ' ; # 47
$ip_type_name{'50'}='EON ' ; # 80
$ip_type_name{'59'}='OSPF' ; # 89
$ip_type_name{'FF'}='RAW ' ; # 255

$ethertype_pattern{'0800'}= '^(\w{18})(\w{2})(\w{4})(\w{8})(\w{8})(\w{4})(\w{4})(\w*)$' ;
$ethertype_format{'0800'}= ' " " . $ip_type_name{$2} . " " . &dotquad(hex($4)) . ":" . hex($6) . \' \' . &dotquad(hex($5)) . ":" . hex($7)' ;

$ethertype_pattern{'0806'}= '^(\w{16})(\w{12})(\w{8})(\w{12})(\w{8})(\w*)$' ;
$ethertype_format{'0806'}= ' $2 . " IS-AT " . &dotquad(hex($3)) . " " . $4 . " " . &dotquad(hex($5 )) ;' ;
#-----------------------------------------------------------------------
sub print_pkt
{
    my ( $arg , $pkt) = @_ ;
#    ($sec , $min, $hour , $mday, $mon, $year, $wday, $yday, $isdst )
#	= localtime($time_sec) ;
#    print "$hour:$min:$sec" ;
    my ( $ether_dst , $ether_src , $ether_type , $rest )
	= unpack ( 'H12 H12 H4 H*' , $pkt ) ;
    my ( $pattern , $format , $packet_txt ) ;
    if ( $pattern = $ethertype_pattern{$ether_type} )
    {
	$rest=~m/$pattern/ ;
	if ( $format = $ethertype_format{$ether_type} )
	{
	    $packet_txt = eval ( $format ) ;
	    die ( $@ ) unless $packet_txt ;
	}
	else
	{
	    $packet_txt = join ( ' ' , $rest=~m/$pattern/ ) ;
	}
    }
    else
    {
	$packet_txt = $rest ;
    }
    printf ( " %s->%s %s %s\n" , $ether_src , $ether_dst ,
	    ($ethertype_name{$ether_type}
	     ? $ethertype_name{$ether_type}
	     : $ether_type ),
	    $packet_txt ) ;
}
#-----------------------------------------------------------------------
sub dotquad {
    my ( $net ) = @_ ;
    $na=$net >> 24 & 255 ;
    $nb=$net >> 16 & 255 ;
    $nc=$net >>  8 & 255 ;
    $nd=$net & 255 ;
    return ( "$na.$nb.$nc.$nd") ;
}
#-----------------------------------------------------------------------
$pkt_cnt = 20 ;

$pcap_dev = Net::Pcap::lookupdev(\$errbuff) ;
die "errbuf: $errbuf" unless $pcap_dev;
$pcap_net = Net::Pcap::lookupnet( $pcap_dev , \$net , \$mask , \$errbuff) ;

print "opening $pcap_dev (" . &dotquad($net) . " " . &dotquad($mask) . ")\n" ;
$pcap_desc = Net::Pcap::open_live ( $pcap_dev , 100 , 1, 1000, \$errbuf ) ;
die "$errbuf" unless $pcap_desc;
Net::Pcap::compile ( $pcap_desc , \$bpf_prog, $ARGV[0] , 0 , $mask ) ;
Net::Pcap::setfilter ( $pcap_desc , $bpf_prog ) ;
Net::Pcap::loop ( $pcap_desc , $pkt_cnt , \&print_pkt , '' ) ;

exit ;
#-----------------------------------------------------------------------
