#
# Pcap.pm
#
# An interface to the LBL pcap(3) library.  This module simply
# bootstraps the extensions defined in Pcap.xs
#
# Copyright (C) 2005 Sebastien Aperghis-Tramoni. All rights reserved.
# Copyright (C) 2003 Marco Carnut. All rights reserved. 
# Copyright (C) 1999-2000 Tim Potter. All rights reserved. 
# Copyright (C) 1998 Bo Adler. All rights reserved. 
# Copyright (C) 1997 Peter Lister. All rights reserved. 
# 
# This program is free software; you can redistribute it and/or modify 
# it under the same terms as Perl itself.
#
package Net::Pcap;
use strict;
require Exporter;
use AutoLoader;
use Carp;

{   no strict;
    $VERSION = '0.08';

    @ISA = qw(Exporter DynaLoader);

    %EXPORT_TAGS = (
        'bpf' => [qw(
            BPF_ALIGNMENT  BPF_MAJOR_VERSION  BPF_MAXBUFSIZE  BPF_MAXINSNS
            BPF_MEMWORDS  BPF_MINBUFSIZE  BPF_MINOR_VERSION  BPF_RELEASE
        )], 
        'datalink' => [qw(
            DLT_AIRONET_HEADER  DLT_APPLE_IP_OVER_IEEE1394  DLT_ARCNET
            DLT_ARCNET_LINUX  DLT_ATM_CLIP  DLT_ATM_RFC1483  DLT_AURORA  DLT_AX25
            DLT_CHAOS  DLT_CHDLC  DLT_CISCO_IOS  DLT_C_HDLC  DLT_DOCSIS  DLT_ECONET
            DLT_EN10MB  DLT_EN3MB  DLT_ENC  DLT_FDDI  DLT_FRELAY  DLT_HHDLC
            DLT_IBM_SN  DLT_IBM_SP  DLT_IEEE802  DLT_IEEE802_11  DLT_IEEE802_11_RADIO
            DLT_IEEE802_11_RADIO_AVS  DLT_IPFILTER  DLT_IP_OVER_FC  DLT_JUNIPER_ATM1
            DLT_JUNIPER_ATM2  DLT_JUNIPER_ES  DLT_JUNIPER_GGSN  DLT_JUNIPER_MFR
            DLT_JUNIPER_MLFR  DLT_JUNIPER_MLPPP  DLT_JUNIPER_MONITOR  DLT_JUNIPER_SERVICES
            DLT_LINUX_IRDA  DLT_LINUX_SLL  DLT_LOOP  DLT_LTALK  DLT_NULL  DLT_OLD_PFLOG
            DLT_PCI_EXP  DLT_PFLOG  DLT_PFSYNC  DLT_PPP  DLT_PPP_BSDOS  DLT_PPP_ETHER
            DLT_PPP_SERIAL  DLT_PRISM_HEADER  DLT_PRONET  DLT_RAW  DLT_RIO  DLT_SLIP
            DLT_SLIP_BSDOS  DLT_SUNATM  DLT_SYMANTEC_FIREWALL  DLT_TZSP  DLT_USER0
            DLT_USER1  DLT_USER2  DLT_USER3  DLT_USER4  DLT_USER5  DLT_USER6  DLT_USER7
            DLT_USER8  DLT_USER9  DLT_USER10  DLT_USER11  DLT_USER12  DLT_USER13
            DLT_USER14  DLT_USER15
        )], 
        pcap => [qw(
            MODE_CAPT  MODE_MON  MODE_STAT
            PCAP_ERRBUF_SIZE    PCAP_IF_LOOPBACK
            PCAP_VERSION_MAJOR  PCAP_VERSION_MINOR
        )], 
        functions => [qw(
            lookupdev  findalldevs
            open_live  open_dead  open_offline pcap_close
            dump_open  pcap_dump  dump_close  dump_file  dump_flush
            dispatch  pcap_next loop  breakloop
            datalink  set_datalink  datalink_name_to_val  
            datalink_val_to_name  datalink_val_to_description
            snapshot  pcap_file  pcap_fileno  get_selectable_fd
            is_swapped  major_version  minor_version
            geterr strerror perror
            lib_version
        )], 
    );
  
    @EXPORT = (
        @{$EXPORT_TAGS{pcap}}, 
        @{$EXPORT_TAGS{datalink}}, 
    );

    @EXPORT_OK = (
        @{$EXPORT_TAGS{functions}}, 
        @{$EXPORT_TAGS{bpf}}, 
    );

    eval {
        require XSLoader;
        XSLoader::load('Net::Pcap', $VERSION);
        1
    } or do {
        require DynaLoader;
        push @ISA, 'DynaLoader';
        bootstrap Net::Pcap $VERSION;
    };
}

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    no strict;
    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Net::Pcap::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }

    {   no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX    if ($] >= 5.00561) {
#XXX        *$AUTOLOAD = sub () { $val };
#XXX    } else {
	    *$AUTOLOAD = sub { $val };
#XXX    }
    }
    goto &$AUTOLOAD;
}


# Functions aliases
#*Net::Pcap::pcap_open   = \&Net::Pcap::open;
*Net::Pcap::pcap_close  = \&Net::Pcap::close;
*Net::Pcap::pcap_next   = \&Net::Pcap::next;
*Net::Pcap::pcap_dump   = \&Net::Pcap::dump;
*Net::Pcap::pcap_file   = \&Net::Pcap::file;
*Net::Pcap::pcap_fileno = \&Net::Pcap::fileno;


# Perl wrapper for DWIM
sub findalldevs {
    croak "Usage: Net::Pcap::findalldevs(devinfo, err)" unless @_ and @_ <= 2 and ref $_[0];
    
    # findalldevs(\$err), legacy from Marco Carnut 0.05
    my %devinfo = ();
    ( ref $_[0] eq 'SCALAR' and return Net::Pcap::findalldevs_xs(\%devinfo, $_[0]) ) 
        or croak "arg1 not a scalar ref"
        if @_ == 1;
    
    # findalldevs(\$err, \%devinfo), legacy from Jean-Louis Morel 0.04.02
    ref $_[0] eq 'SCALAR' and (
        ( ref $_[1] eq 'HASH' and return Net::Pcap::findalldevs_xs($_[1], $_[0]) )
        or croak "arg2 not a hash ref"
    );

    # findalldevs(\%devinfo, \$err), new, correct syntax, consistent with libpcap(3)
    ref $_[0] eq 'HASH' and (
        ( ref $_[1] eq 'SCALAR' and return Net::Pcap::findalldevs_xs($_[0], $_[1]) )
            or croak "arg2 not a scalar ref"
    );

    # if here, the function was called with incorrect arguments
    ref $_[0] ne 'HASH' and croak "arg1 not a hash ref";
}


1;

__END__

=head1 NAME

Net::Pcap - Interface to pcap(3) LBL packet capture library

=head1 VERSION

Version 0.08

=head1 SYNOPSIS

    use Net::Pcap;

    my $err = '';
    my $dev = Net::Pcap::lookupdev(\$err);  # find a device

    # open the device for live listening
    my $pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

    # loop over next 10 packets
    Net::Pcap::loop($pcap, 10, \&process_packet, "just for the demo");

    # close the device
    Net::Pcap::close($pcap);

    sub process_packet {
        my($user_data, $header, $packet) = @_;
        # do something ...
    }


=head1 DESCRIPTION

C<Net::Pcap> is a Perl binding to the LBL pcap(3) library.
The README for libpcap describes itself as:

  "a system-independent interface for user-level packet capture.
  libpcap provides a portable framework for low-level network
  monitoring.  Applications include network statistics collection,
  security monitoring, network debugging, etc."


=head1 EXPORTS

C<Net::Pcap> supports the following C<Exporter> tags: 

=over 4

=item *

C<:bpf> exports a few BPF related constants: 

    BPF_ALIGNMENT  BPF_MAJOR_VERSION  BPF_MAXBUFSIZE  BPF_MAXINSNS
    BPF_MEMWORDS  BPF_MINBUFSIZE  BPF_MINOR_VERSION  BPF_RELEASE

=item *

C<:datalink> exports the data link types macros: 

    DLT_AIRONET_HEADER  DLT_APPLE_IP_OVER_IEEE1394  DLT_ARCNET
    DLT_ARCNET_LINUX  DLT_ATM_CLIP  DLT_ATM_RFC1483  DLT_AURORA  DLT_AX25
    DLT_CHAOS  DLT_CHDLC  DLT_CISCO_IOS  DLT_C_HDLC  DLT_DOCSIS  DLT_ECONET
    DLT_EN10MB  DLT_EN3MB  DLT_ENC  DLT_FDDI  DLT_FRELAY  DLT_HHDLC
    DLT_IBM_SN  DLT_IBM_SP  DLT_IEEE802  DLT_IEEE802_11  DLT_IEEE802_11_RADIO
    DLT_IEEE802_11_RADIO_AVS  DLT_IPFILTER  DLT_IP_OVER_FC  DLT_JUNIPER_ATM1
    DLT_JUNIPER_ATM2  DLT_JUNIPER_ES  DLT_JUNIPER_GGSN  DLT_JUNIPER_MFR
    DLT_JUNIPER_MLFR  DLT_JUNIPER_MLPPP  DLT_JUNIPER_MONITOR  DLT_JUNIPER_SERVICES
    DLT_LINUX_IRDA  DLT_LINUX_SLL  DLT_LOOP  DLT_LTALK  DLT_NULL  DLT_OLD_PFLOG
    DLT_PCI_EXP  DLT_PFLOG  DLT_PFSYNC  DLT_PPP  DLT_PPP_BSDOS  DLT_PPP_ETHER
    DLT_PPP_SERIAL  DLT_PRISM_HEADER  DLT_PRONET  DLT_RAW  DLT_RIO  DLT_SLIP
    DLT_SLIP_BSDOS  DLT_SUNATM  DLT_SYMANTEC_FIREWALL  DLT_TZSP  DLT_USER0
    DLT_USER1  DLT_USER2  DLT_USER3  DLT_USER4  DLT_USER5  DLT_USER6  DLT_USER7
    DLT_USER8  DLT_USER9  DLT_USER10  DLT_USER11  DLT_USER12  DLT_USER13
    DLT_USER14  DLT_USER15

=item *

C<:pcap> exports a few C<pcap> constants: 

    MODE_CAPT  MODE_MON  MODE_STAT
    PCAP_ERRBUF_SIZE    PCAP_IF_LOOPBACK
    PCAP_VERSION_MAJOR  PCAP_VERSION_MINOR

=item *

C<:functions> exports the function names, so that you can write C<lookupdev()> 
instead of C<Net::Pcap::lookupdev()> for example. As some functions would have 
the same name as existing Perl functions, they have been prefixed by C<pcap_>. 
This is the case for C<open()>, C<close()>, C<next()>, C<dump()>, C<file()>, 
C<fileno()>. 

=back

The symbols from the C<datalink> and C<:pcap> tags are exported by default. 


=head1 FUNCTIONS

All functions defined by C<Net::Pcap> are direct mappings to the
libpcap functions.  Consult the pcap(3) documentation and source code
for more information.

Arguments that change a parameter, for example C<Net::Pcap::lookupdev()>,
are passed that parameter as a reference.  This is to retain
compatibility with previous versions of B<Net::Pcap>.

=head2 Lookup functions

=over 4

=item B<lookupdev(\$err)>

=item B<Net::Pcap::lookupdev(\$err)>

Returns the name of a network device that can be used with
C<Net::Pcap::open_live()> function.  On error, the C<$err> parameter 
is filled with an appropriate error message else it is undefined.

B<Example>

    $dev = Net::Pcap::lookupdev();


=item B<findalldevs(\%devinfo, \$err)>

=item B<Net::Pcap::findalldevs(\%devinfo, \$err)>

Returns a list of all network device names that can be used with
C<Net::Pcap::open_live()> function.  On error, the C<$err> parameter 
is filled with an appropriate error message else it is undefined.

B<Example>

    @devs = Net::Pcap::findalldevs(\%devinfo, \$err);
    for my $dev (@devs) {
        print "$dev : $devinfo{$dev}\n"
    }

B<Note:> For backward compatibility reasons, this function can also 
be called using the following signatures: 

    @devs = Net::Pcap::findalldevs(\$err);

    @devs = Net::Pcap::findalldevs(\$err, \%devinfo);

The first form was introduced by Marco Carnut in C<Net::Pcap> version 0.05 
and kept intact in versions 0.06 and 0.07. 
The second form was introduced by Jean-Louis Morel for the Windows only, 
ActivePerl port of C<Net::Pcap>, in versions 0.04.01 and 0.04.02. 

The new syntax has been introduced for consistency with the rest of the Perl 
API and the C API of C<libpcap(3)>, where C<$err> is always the last argument. 


=item B<lookupnet($dev, \$net, \$mask, \$err)>

=item B<Net::Pcap::lookupnet($dev, \$net, \$mask, \$err)>

Determine the network number and netmask for the device specified in
C<$dev>.  The function returns 0 on success and sets the C<$net> and
C<$mask> parameters with values.  On failure it returns -1 and the
C<$err> parameter is filled with an appropriate error message.

=back

=head2 Packet capture functions

=over 4

=item B<open_live($dev, $snaplen, $promisc, $to_ms, \$err)>

=item B<Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err)>

Returns a packet capture descriptor for looking at packets on the
network.  The C<$dev> parameter specifies which network interface to
capture packets from.  The C<$snaplen> and C<$promisc> parameters specify
the maximum number of bytes to capture from each packet, and whether
to put the interface into promiscuous mode, respectively.  The C<$to_ms>
parameter specifies a read timeout in milliseconds.  The packet descriptor 
will be undefined if an error occurs, and the C<$err> parameter will be 
set with an appropriate error message.

B<Example>

    $dev = Net::Pcap::lookupdev();
    $pcap = Net::Pcap::open_live($dev, 1024, 1, \$err)
        or die "Can't open device $dev: $err\n";


=item B<open_dead($linktype, $snaplen)>

=item B<Net::Pcap::open_dead($linktype, $snaplen)>

Creates and returns a new packet descriptor to use when calling the other 
functions in C<libpcap>. It is typically used when just using C<libpcap> 
for compiling BPF code. 

B<Example>

    $pcap = Net::Pcap::open_dead(0, 1024);


=item B<open_offline($filename, \$err)>

=item B<Net::Pcap::open_offline($filename, \$err)>

Return a packet capture descriptor to read from a previously created
"savefile".  The returned descriptor is undefined if there was an
error and in this case the C<$err> parameter will be filled.  Savefiles
are created using the C<Net::Pcap::dump_*> commands.

B<Example>

    $pcap = Net::Pcap::open_offline($dump, \$err)
        or die "Can't read '$dump': $err\n";


=item B<loop($pcap, $count, \&callback, $user_data)>

=item B<Net::Pcap::loop($pcap, $count, \&callback, $user_data)>

Read C<$cnt> packets from the packet capture descriptor C<$pcap> and call
the perl function C<&callback> with an argument of C<$user_data>.  
If C<$count> is negative, then the function loops forever or until an error 
occurs. Returns 0 if C<$count> is exhausted, -1 on error, and -2 if the 
loop terminated due to a call to pcap_breakloop() before any packets were 
processed. 

The callback function is also passed packet header information and
packet data like so:

    sub process_packet {
        my($user_data, $header, $packet) = @_;

        ...
    }

The header information is a reference to a hash containing the
following fields.

=over 4

=item * C<len>

The total length of the packet.

=item * C<caplen>

The actual captured length of the packet data.  This corresponds to
the snapshot length parameter passed to C<Net::Pcap::open_live()>.

=item * C<tv_sec>

Seconds value of the packet timestamp.

=item * C<tv_usec>

Microseconds value of the packet timestamp.

=back

B<Example>

    Net::Pcap::loop($pcap, 10, \&process_packet, "user data");

    sub process_packet {
        my($user_data, $header, $packet) = @_;
        # ...
    }


=item B<breakloop($pcap)>

=item B<Net::Pcap::breakloop($pcap)>

Sets a flag  that will force C<Net::Pcap::dispatch()> or C<Net::Pcap::loop()> 
to return rather than looping; they will return the number of packets that 
have been processed so far, or -2 if no packets have been processed so far. 

This routine is safe to use inside a signal handler on UNIX or a console 
control handler on Windows, as it merely sets a flag that is checked within 
the loop. 

Please see the section on C<pcap_breakloop()> in L<pcap(3)> for more 
information. 


=item B<pcap_close($pcap)>

=item B<Net::Pcap::close($pcap)>

Close the packet capture device associated with the descriptor C<$pcap>.


=item B<dispatch($pcap, $count, \&callback, $user_data)>

=item B<Net::Pcap::dispatch($pcap, $count, \&callback, $user_data)>

Collect C<$count> packets and process them with callback function
C<&callback>.  if C<$count> is -1, all packets currently buffered are
processed.  If C<$count> is 0, process all packets until an error occurs. 


=item B<pcap_next($pcap, \%header)>

=item B<Net::Pcap::next($pcap, \%header)>

Return the next available packet on the interface associated with
packet descriptor C<$pcap>.  Into the C<%header> hash is stored the received
packet header.  If not packet is available, the return value and
header is undefined.


=item B<compile($pcap, \$filter, $filter_str, $optimize, $netmask)>

=item B<Net::Pcap::compile($pcap, \$filter, $filter_str, $optimize, $netmask)>

Compile the filter string contained in C<$filter_str> and store it in
C<$filter>.  A description of the filter language can be found in the
libpcap source code, or the manual page for tcpdump(8) .  The filter
is optimized if the C<$optimize> variable is true.  The netmask of the 
network device must be specified in the C<$netmask> parameter.  The 
function returns 0 if the compilation was successful, or -1 if there 
was a problem.


=item B<setfilter($pcap, $filter)>

=item B<Net::Pcap::setfilter($pcap, $filter)>

Associate the compiled filter stored in C<$filter> with the packet
capture descriptor C<$pcap>.

=item B<Net::Pcap::freecode($filter)>

Used to free the allocated memory used by a compiled filter, as created 
by C<pcap_compile()>. 


=item B<setnonblock($pcap, $mode, \$err)>

=item B<Net::Pcap::setnonblock($pcap, $mode, \$err)>

Set the I<non-blocking> mode of a live capture descriptor, depending on the 
value of C<$mode> (zero to activate and non-zero to desactivate). It has no 
effect on offline descriptors. If there is an error, it returns -1 and sets 
C<$err>. 

In non-blocking mode, an attempt to read from the capture descriptor with 
C<pcap_dispatch()> will, if no packets are currently available to be read, 
return 0  immediately rather than blocking waiting for packets to arrive. 
C<pcap_loop()> and C<pcap_next()> will not work in non-blocking mode. 


=item B<getnonblock($pcap, \$err)>

=item B<Net::Pcap::getnonblock($pcap, \$err)>

Returns the I<non-blocking> state of the capture descriptor C<$pcap>. 
Always returns 0 on savefiles. If there is an error, it returns -1 and 
sets C<$err>. 

=back

=head2 Savefile commands

=over 4

=item B<dump_open($pcap, $filename)>

=item B<Net::Pcap::dump_open($pcap, $filename)>

Open a savefile for writing and return a descriptor for doing so.  If
C<$filename> is C<"-"> data is written to standard output.  On error, the
return value is undefined and C<Net::Pcap::geterr()> can be used to
retrieve the error text.


=item B<pcap_dump($dumper, \%header, $packet)>

=item B<Net::Pcap::dump($dumper, \%header, $packet)>

Dump the packet described by header C<%header> and packet data C<$packet> 
to the savefile associated with C<$dumper>.  The packet header has the
same format as that passed to the C<Net::Pcap::loop()> callback.


=item B<dump_file($dumper)>

=item B<Net::Pcap::dump_file($dumper)>

Returns the filehandle associated with a savefile opened with
C<Net::Pcap::dump_open()>.


=item B<dump_flush($dumper)>

=item B<Net::Pcap::dump_flush($dumper)>

Flushes the output buffer to the corresponding save file, so that any 
packets written with C<Net::Pcap::dump()> but not yet written to the save 
file will be written. Returns -1 on error, 0 on success.


=item B<dump_close($dumper)>

=item B<Net::Pcap::dump_close($dumper)>

Close the savefile associated with the descriptor C<$dumper>.

=back

=head2 Status functions

=over 4


=item B<datalink($pcap)>

=item B<Net::Pcap::datalink($pcap)>

Returns the link layer type associated with the given pcap descriptor.

B<Example>

    $linktype = Net::Pcap::datalink($pcap);


=item B<set_datalink($pcap, $linktype)>

=item B<Net::Pcap::set_datalink($pcap, $linktype)>

Sets the data link type of the given pcap descriptor to the type specified 
by C<$linktype>. Returns -1 on failure. 


=item B<datalink_name_to_val($name)>

=item B<Net::Pcap::datalink_name_to_val($name)>

Translates a data link type name, which is a C<DLT_> name with the C<DLT_> 
part removed, to the corresponding data link type value. The translation is 
case-insensitive. Returns -1 on failure. 

B<Example>

    $linktype = Net::Pcap::datalink_name_to_val('LTalk');  # returns DLT_LTALK


=item B<datalink_val_to_name($linktype)>

=item B<Net::Pcap::datalink_val_to_name($linktype)>

Translates a data link type value to the corresponding data link type name. 

B<Example>

    $name = Net::Pcap::datalink_val_to_name(DLT_LTALK);  # returns 'LTALK'


=item B<datalink_val_to_description($linktype)>

=item B<Net::Pcap::datalink_val_to_description($linktype)>

Translates a data link type value to a short description of that data link type.

B<Example>

    $descr = Net::Pcap::datalink_val_to_description(DLT_LTALK);  # returns 'Localtalk'


=item B<snapshot($pcap)>

=item B<Net::Pcap::snapshot($pcap)>

Returns the snapshot length (snaplen) specified in the call to
C<Net::Pcap::open_live()>.


=item B<is_swapped($pcap)>

=item B<Net::Pcap::is_swapped($pcap)>

This function returns true if the endianess of the currently open
savefile is different from the endianess of the machine.


=item B<major_version($pcap)>

=item B<Net::Pcap::major_version($pcap)>

Return the major version number of the pcap library used to write the
currently open savefile.


=item B<minor_version($pcap)>

=item B<Net::Pcap::minor_version($pcap)>

Return the minor version of the pcap library used to write the
currently open savefile.


=item B<stats($pcap, \%stats)>

=item B<Net::Pcap::stats($pcap, \%stats)>

Returns a hash containing information about the status of packet
capture device C<$pcap>.  The hash contains the following fields.

=over 4

=item * C<ps_recv>

The number of packets received by the packet capture software.

=item * C<ps_drop>

The number of packets dropped by the packet capture software.

=item * C<ps_ifdrop>

The number of packets dropped by the network interface.

=back


=item B<pcap_file($pcap)>

=item B<Net::Pcap::file($pcap)>

Returns the filehandle associated with a savefile opened with
C<Net::Pcap::open_offline()> or C<undef> if the device was opened 
with C<Net::pcap::open_live()>..


=item B<pcap_fileno($pcap)>

=item B<Net::Pcap::fileno($pcap)>

Returns the file number of the network device opened with
C<Net::Pcap::open_live()>.


=item B<get_selectable_fd($pcap)>

=item B<Net::Pcap::get_selectable_fdfileno($pcap)>

Returns, on Unix, a file descriptor number for a file descriptor on which 
one can do a C<select()> or C<poll()> to wait for it to be possible to read 
packets without blocking, if such a descriptor exists, or -1, if no such 
descriptor exists. Some network devices opened with C<Net::Pcap::open_live()> 
do not support C<select()> or C<poll()>, so -1 is returned for those devices.
See L<pcap(3)> for more details. 

=back

=head2 Error handling

=over 4

=item B<geterr($pcap)>

=item B<Net::Pcap::geterr($pcap)>

Returns an error message for the last error associated with the packet
capture device C<$pcap>.


=item B<strerror($errno)>

=item B<Net::Pcap::strerror($errno)>

Returns a string describing error number C<$errno>.


=item B<perror($pcap, $prefix)>

=item B<Net::Pcap::perror($pcap, $prefix)>

Prints the text of the last error associated with descriptor C<$pcap> on
standard error, prefixed by C<$prefix>.

=back

=head2 Information

=over 4

=item B<lib_version()>

=item B<Net::Pcap::lib_version()>

Returns the name and version of the C<pcap> library the module was linked 
against. 

=back


=head1 CONSTANTS

C<Net::Pcap> exports by default the names of several constants in order to 
ease the development of programs. See L</"EXPORTS"> for details about which 
constants are exported. 

Here are the descriptions of a few data link types. See L<pcap(3)> for a more 
complete description and semantics associated with each data link. 

=over 4

=item *

C<DLT_NULL> - BSD loopback encapsulation

=item *

C<DLT_EN10MB> - Ethernet (10Mb, 100Mb, 1000Mb, and up)

=item *

C<DLT_RAW> - raw IP

=item *

C<DLT_IEEE802> - IEEE 802.5 Token Ring

=item *

C<DLT_IEEE802_11> - IEEE 802.11 wireless LAN

=item *

C<DLT_FRELAY> - Frame Relay

=item *

C<DLT_FDDI> - FDDI

=item *

C<DLT_SLIP> - Serial Line IP

=item *

C<DLT_PPP> - PPP (Point-to-point Protocol)

=item *

C<DLT_PPP_SERIAL> - PPP over serial with HDLC encapsulation

=item *

C<DLT_PPP_ETHER> - PPP over Ethernet

=item *

C<DLT_IP_OVER_FC> - RFC  2625  IP-over-Fibre  Channel

=item *

C<DLT_AX25> - Amateur Radio AX.25

=item *

C<DLT_LINUX_IRDA> - Linux-IrDA

=item *

C<DLT_LTALK> - Apple  LocalTalk

=item *

C<DLT_APPLE_IP_OVER_IEEE1394> - Apple IP-over-IEEE 1394 (a.k.a. Firewire)

=back


=head1 DIAGNOSTICS

=over 4

=item arg%d not a scalar ref

=item arg%d not a hash ref

=item arg%d not a reference

B<(F)> These errors occur if you forgot to give a reference to a function 
which expect one or more of its arguments to be references.

=back


=head1 LIMITATIONS

The following limitations apply to this version of C<Net::Pcap>.

=over 

=item *

At present, only one callback function and user data scalar can be
current at any time as they are both stored in global variables.

=back


=head1 BUGS

Please report any bugs or feature requests to
C<bug-Net-Pcap@rt.cpan.org>, or through the web interface at
L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Pcap>.
I will be notified, and then you'll automatically be notified
of progress on your bug as I make changes.

Currently known bugs: 

=over 4

=item *

the C<ps_recv> field is not correctly set; see F<t/07-stats.t>; 
see L<http://rt.cpan.org/NoAuth/Bug.html?id=7371>

=item *

C<Net::Pcap::file()> seems to always returns C<undef> for live 
connection and causes segmentation fault for dump files; 
see F<t/10-fileno.t>

=item *

C<Net::Pcap::fileno()> is documented to return -1 when called 
on save file, but seems to always return an actual file number. 
See F<t/10-fileno.t>


=item *

C<Net::Pcap::dump_file()> seems to corrupt something somewhere, 
and makes scripts dump core. See F<t/05-dump.t>

=back


=head1 EXAMPLES

See the F<eg/> and F<t/> directories of the C<Net::Pcap> distribution 
for examples on using this module.


=head1 SEE ALSO

L<pcap(3)>, L<tcpdump(8)>

The source code for the C<pcap(3)> library is available from L<http://www.tcpdump.org/>

The source code and binary for the Win32 version of the pcap library, WinPcap, 
is available from L<http://www.winpcap.org/>


=head1 AUTHORS

Current maintainer is SE<eacute>bastien Aperghis-Tramoni (SAPER) 
E<lt>sebastien@aperghis.netE<gt> with the help of Jean-Louis Morel (JLMOREL) 
E<lt>jl_morel@bribes.orgE<gt> for WinPcap support. 

Previous authors & maintainers: 

=over 4

=item *

Marco Carnut (KCARNUT) E<lt>kiko@tempest.com.brE<gt>

=item *

Tim Potter (TIMPOTTER) E<lt>tpot@frungy.orgE<gt>

=item *

Bo Adler (BOADLER) E<lt>thumper@alumni.caltech.eduE<gt>

=item *

Peter Lister (PLISTER) E<lt>p.lister@cranfield.ac.ukE<gt>

=back


=head1 COPYRIGHT

Copyright (C) 2005 SE<eacute>bastien Aperghis-Tramoni. All rights reserved. 

Copyright (C) 2003 Marco Carnut. All rights reserved. 

Copyright (C) 1999-2000 Tim Potter. All rights reserved. 

Copyright (C) 1998 Bo Adler. All rights reserved. 

Copyright (C) 1997 Peter Lister. All rights reserved. 

This program is free software; you can redistribute it and/or modify 
it under the same terms as Perl itself.

=cut
