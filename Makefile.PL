use ExtUtils::MakeMaker;
require 5.003;
$Verbose++ if $ENV{USER} eq "k";

WriteMakefile(
	NAME       => "Net::Pcap",
	"dist"     => { SUFFIX   => ".gz", DIST_DEFAULT => 'all tardist',
			    COMPRESS => "gzip -9f" },
	VERSION => '0.01' , 
	CONFIGURE  => \&initialize
);



sub initialize {
    my %X=();
    my @libpcapdir = qw(/usr/local /usr);
    my ($libpcapdir,$basedir);

    for $libpcapdir (@libpcapdir) {
	if (-f "$libpcapdir/include/pcap.h") {
	    print "Assuming \"$libpcapdir/{lib,include}\" contain libpcap.a and pcap.h \n";
	    $basedir = $libpcapdir;
	    last;
	}
    }
    
    if ( ! $basedir )
    { 
	$basedir = $libpcapdir[0];
	$basedir=prompt("
Where is your libpcap installed? Please name the directory that contains
the subdirs lib and include.",$basedir) unless -f "$basedir/include/libpcap.h";
    }
    my $headerdir="$basedir/include";
    die "No pcap.h file found in $headerdir\n" unless -f "$headerdir/pcap.h";
    warn "No bpf.h file found in $headerdir\n" unless -f "$headerdir/net/bpf.h";
    my $libdir="$basedir/lib";
    
    @headerfiles = ("$headerdir/pcap.h" , "$headerdir/net/bpf.h" );
    $X{LIBS}     = "-L$libdir -lpcap";
    $X{INC}      = "-I$headerdir";
    $X{H}        = \@headerfiles;
    \%X;
}
