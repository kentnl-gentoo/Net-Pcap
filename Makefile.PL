#
# Makefile.PL for Net::Pcap
#
# $Id: Makefile.PL,v 1.3 1999/03/11 23:34:01 tpot Exp $
#

use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'         => 'Net::Pcap',
	'DISTNAME'     => 'Net-Pcap',
	'VERSION_FROM' => 'Pcap.pm',
	'LIBS'         => ['-lpcap'], 
	dist => {
		'COMPRESS' => "gzip -9f",
		'SUFFIX'   => "gz"
	}
);
