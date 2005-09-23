use strict;
use ExtUtils::MakeMaker;
eval "use ExtUtils::MakeMaker::Coverage";

die <<"REASON" unless have_library('pcap');
You appear to lack the pcap(3) library. \a

If it is installed in a non-standard location, please try setting the LIBS 
and INC values on the command line.

Or get the sources and install the pcap library from http://www.tcpdump.org/

If you install the pcap library using a system package, make sure to also 
install the -devel package, which contains the C headers needed to compile 
this module. 
REASON

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
	CCFLAGS            => '-Wall', 
	'LIBS'             => ['-lpcap'], 
	dist => { 'COMPRESS' => "gzip -9f", 'SUFFIX'   => "gz" }, 
	clean => { FILES => 'Net-P0f-*' }, 
);

if(eval {require ExtUtils::Constant; 1}) {
    # If you edit these definitions to change the constants used by this module,
    # you will need to use the generated const-c.inc and const-xs.inc
    # files to replace their "fallback" counterparts before distributing your
    # changes.
    my @names = (qw(BPF_A BPF_ABS BPF_ADD BPF_ALIGNMENT BPF_ALU BPF_AND BPF_B
        BPF_DIV BPF_H BPF_IMM BPF_IND BPF_JA BPF_JEQ BPF_JGE BPF_JGT
        BPF_JMP BPF_JSET BPF_K BPF_LD BPF_LDX BPF_LEN BPF_LSH
        BPF_MAJOR_VERSION BPF_MAXBUFSIZE BPF_MAXINSNS BPF_MEM
        BPF_MEMWORDS BPF_MINBUFSIZE BPF_MINOR_VERSION BPF_MISC BPF_MSH
        BPF_MUL BPF_NEG BPF_OR BPF_RELEASE BPF_RET BPF_RSH BPF_ST
        BPF_STX BPF_SUB BPF_TAX BPF_TXA BPF_W BPF_X DLT_AIRONET_HEADER
        DLT_APPLE_IP_OVER_IEEE1394 DLT_ARCNET DLT_ARCNET_LINUX
        DLT_ATM_CLIP DLT_ATM_RFC1483 DLT_AURORA DLT_AX25 DLT_CHAOS
        DLT_CHDLC DLT_CISCO_IOS DLT_C_HDLC DLT_DOCSIS DLT_ECONET
        DLT_EN10MB DLT_EN3MB DLT_ENC DLT_FDDI DLT_FRELAY DLT_HHDLC
        DLT_IBM_SN DLT_IBM_SP DLT_IEEE802 DLT_IEEE802_11
        DLT_IEEE802_11_RADIO DLT_IEEE802_11_RADIO_AVS DLT_IPFILTER
        DLT_IP_OVER_FC DLT_JUNIPER_ATM1 DLT_JUNIPER_ATM2
        DLT_JUNIPER_ES DLT_JUNIPER_GGSN DLT_JUNIPER_MFR
        DLT_JUNIPER_MLFR DLT_JUNIPER_MLPPP DLT_JUNIPER_MONITOR
        DLT_JUNIPER_SERVICES DLT_LINUX_IRDA DLT_LINUX_SLL DLT_LOOP
        DLT_LTALK DLT_NULL DLT_OLD_PFLOG DLT_PCI_EXP DLT_PFLOG
        DLT_PFSYNC DLT_PPP DLT_PPP_BSDOS DLT_PPP_ETHER DLT_PPP_SERIAL
        DLT_PRISM_HEADER DLT_PRONET DLT_RAW DLT_RIO DLT_SLIP
        DLT_SLIP_BSDOS DLT_SUNATM DLT_SYMANTEC_FIREWALL DLT_TZSP
        DLT_USER0 DLT_USER1 DLT_USER10 DLT_USER11 DLT_USER12
        DLT_USER13 DLT_USER14 DLT_USER15 DLT_USER2 DLT_USER3 DLT_USER4
        DLT_USER5 DLT_USER6 DLT_USER7 DLT_USER8 DLT_USER9 MODE_CAPT
        MODE_MON MODE_STAT PCAP_ERRBUF_SIZE PCAP_IF_LOOPBACK
        PCAP_VERSION_MAJOR PCAP_VERSION_MINOR));

    ExtUtils::Constant::WriteConstants(
            NAME         => 'pcap',
            NAMES        => \@names,
            DEFAULT_TYPE => 'IV',
            C_FILE       => 'const-c.inc',
            XS_FILE      => 'const-xs.inc',
    );

} else {
    use File::Copy;
    use File::Spec;
    foreach my $file ('const-c.inc', 'const-xs.inc') {
        my $fallback = File::Spec->catfile('fallback', $file);
        copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
    }
}


# The rest of the code, up to the end of this file, has been copied 
# from XML::LibXML::Common Makefile.PL

###################################################################
# Functions
#  - these should really be in MakeMaker... But &shrug;
###################################################################

use Config;
use Cwd;
use Symbol;
use File::Spec;

my($DEBUG,%config,$DEVNULL,$is_Win32);

BEGIN {
    $is_Win32 = ($^O =~ /Win32/);
    if ($is_Win32) {
        $DEVNULL = 'DEVNULL';
    } else {
        $DEVNULL = eval { File::Spec->devnull };
        if ($@) { $DEVNULL = '/dev/null' }
    }
}

sub rm_f {
    my @files = @_;
    my @realfiles;
    foreach (@files) {
        push @realfiles, glob($_);
    }
    if (@realfiles) {
        chmod(0777, @realfiles);
        unlink(@realfiles);
    }
}

sub rm_fr {
    my @files = @_;
    my @realfiles;
    foreach (@files) {
        push @realfiles, glob($_);
    }
    foreach my $file (@realfiles) {
        if (-d $file) {
            # warn("$file is a directory\n");
            rm_fr("$file/*");
            rm_fr("$file/.exists");
            rmdir($file) || die "Couldn't remove $file: $!";
        } else {
            # warn("removing $file\n");
            chmod(0777, $file);
            unlink($file);
        }
    }
}

sub xsystem {
    my $command = shift;
    if ($DEBUG) {
        print $command, "\n";
        if (system($command) != 0) {
            die "system call to '$command' failed";
        }
        return 1;
    }
    open(OLDOUT, ">&STDOUT");
    open(OLDERR, ">&STDERR");
    open(STDOUT, ">$DEVNULL");
    open(STDERR, ">$DEVNULL");
    my $retval = system($command);
    open(STDOUT, ">&OLDOUT");
    open(STDERR, ">&OLDERR");
    if ($retval != 0) {
        die "system call to '$command' failed";
    }
    return 1;
}

sub backtick {
    my $command = shift;
    if ($DEBUG) {
        print $command, "\n";
        my $results = `$command`;
        chomp $results;
        if ($? != 0) {
            die "backticks call to '$command' failed";
        }
        return $results;
    }
    open(OLDOUT, ">&STDOUT");
    open(OLDERR, ">&STDERR");
    open(STDOUT, ">$DEVNULL");
    open(STDERR, ">$DEVNULL");
    my $results = `$command`;
    my $retval = $?;
    open(STDOUT, ">&OLDOUT");
    open(STDERR, ">&OLDERR");
    if ($retval != 0) {
        die "backticks call to '$command' failed";
    }
    chomp $results;
    return $results;
}

sub try_link0 {
    my ($src, $opt) = @_;
    my $cfile = gensym();
    # local $config{LIBS};
    # $config{LIBS} .= $opt;
    unless (mkdir(".testlink", 0777)) {
        rm_fr(".testlink");
        mkdir(".testlink", 0777) || die "Cannot create .testlink dir: $!";
    }
    chdir(".testlink");
    open($cfile, ">Conftest.xs") || die "Cannot write to file Conftest.xs: $!";
print $cfile <<EOT;
#ifdef __cplusplus
extern "C" {
#endif
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#ifdef __cplusplus
}
#endif

EOT
    print $cfile $src;
    print $cfile <<EOT;

MODULE = Conftest          PACKAGE = Conftest

PROTOTYPES: DISABLE

EOT
    close($cfile);
    open($cfile, ">Conftest.pm") || die "Cannot write to file Conftest.pm: $!";
    print $cfile <<'EOT';
package Conftest;
$VERSION = 1.0;
require DynaLoader;
@ISA = ('DynaLoader');
bootstrap Conftest $VERSION;
1;
EOT
    close($cfile);
    open($cfile, ">Makefile.PL") || die "Cannot write to file Makefile.PL: $!";
    print $cfile <<'EOT';
use ExtUtils::MakeMaker;
my %config;
while($_ = shift @ARGV) {
    my ($k, $v) = split /=/, $_, 2;
    warn("$k = $v\n");
    $config{$k} = $v;
}
WriteMakefile(NAME => "Conftest", VERSION_FROM => "Conftest.pm", %config);
EOT
    close($cfile);
    open($cfile, ">test.pl") || die "Cannot write to file test.pl: $!";
    print $cfile <<EOT;
use Test; BEGIN { plan tests => 1; } END { ok(\$loaded) }
use Conftest; \$loaded++;
EOT
    close($cfile);
    my $quote = $is_Win32 ? '"' : "'";
    xsystem("$^X Makefile.PL " . join(' ', map { "${quote}$_=$config{$_}${quote}" } keys %config));
    xsystem("$Config{make} test ${quote}OTHERLDFLAGS=${opt}${quote}");
} # end try_link0

sub try_link {
    my $start_dir = cwd();
    my $result = eval {
        try_link0(@_);
    };
    warn $@ if $DEBUG && $@;
    chdir($start_dir);
    rm_fr(".testlink");
    return $result;
}

sub have_library {
    my ($lib, $func) = (@_, "blank");
    printf("checking for %s() in -l%s... ", $func, $lib) if $func ne "blank";
    printf("looking for -l%s... ", $lib) if $func eq "blank";

    my $result;
    if ($func) {
        my $libs = $is_Win32 ? " $lib.lib  " : "-l$lib";
#        my $libs = "-l$lib";
        if ($is_Win32) {
            $result = try_link(<<"SRC",undef );
#include <windows.h>
#include <winsock.h>
blank() { return 0; }
int t() { ${func}(); return 0; }
SRC
            unless ($result) {
                $result = try_link(<<"SRC", undef);
#include <windows.h>
#include <winsock.h>
blank() { return 0; }
int t() { void ((*p)()); p = (void ((*)()))${func}; return 0; }
SRC
            }
        }
        else {
            $result = try_link(<<"SRC", undef);
blank() { return 0; }
int t() { ${func}(); return 0; }
SRC
        }
    }

    unless ($result) {
        print "no\n";
        return 0;
    }

    if ($func ne "main") {
        $config{DEFINE} .= uc(" -Dhave_$func");
    }

    print "yes\n";
    return 1;
}
