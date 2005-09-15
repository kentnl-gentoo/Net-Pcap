use strict;
use ExtUtils::MakeMaker;
eval "use ExtUtils::MakeMaker::Coverage";

WriteMakefile(
	'NAME'             => 'Net::Pcap',
    'AUTHOR'           => 'Sébastien Aperghis-Tramoni <sebastien@aperghis.net>',
	'DISTNAME'         => 'Net-Pcap',
	'VERSION_FROM'     => 'Pcap.pm',
	'ABSTRACT_FROM'    => 'Pcap.pm',
	'PL_FILES'         => {}, 
	'PREREQ_PM'        => {
        'Test::More' => '0.45', 
    },
	'LIBS'             => ['-lpcap'], 
	dist => { 'COMPRESS' => "gzip -9f", 'SUFFIX'   => "gz" }, 
	clean => { FILES => 'Net-P0f-*' }, 
);
