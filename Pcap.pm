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
require DynaLoader;
use AutoLoader;
use Carp;

{   no strict;
    $VERSION = '0.07';

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
    );
  
    @EXPORT = (
        @{$EXPORT_TAGS{pcap}}, 
        @{$EXPORT_TAGS{datalink}}, 
        @{$EXPORT_TAGS{bpf}}, 
    );

    bootstrap Net::Pcap $VERSION;
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

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

Net::Pcap - Interface to pcap(3) LBL packet capture library

=head1 VERSION

Version 0.07

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

=head1 FUNCTIONS

All functions defined by C<Net::Pcap> are direct mappings to the
libpcap functions.  Consult the pcap(3) documentation and source code
for more information.

Arguments that change a parameter, for example C<Net::Pcap::lookupdev()>,
are passed that parameter as a reference.  This is to retain
compatibility with previous versions of B<Net::Pcap>.

=head2 Lookup functions

=over 4

=item B<Net::Pcap::lookupdev(\$err)>

Returns the name of a network device that can be used with
B<Net::Pcap::open_live() function>.  On error, the C<$err> parameter 
is filled with an appropriate error message else it is undefined.

B<Example>

    $dev = Net::Pcap::lookupdev();

=item B<Net::Pcap::findalldevs(\$err)>

Returns a list of all network device names that can be used with
B<Net::Pcap::open_live() function>.  On error, the C<$err> parameter 
is filled with an appropriate error message else it is undefined.

B<Example>

    @devs = Net::Pcap::findalldevs(\$err);

=item B<Net::Pcap::lookupnet($dev, \$net, \$mask, \$err)>

Determine the network number and netmask for the device specified in
C<$dev>.  The function returns 0 on success and sets the C<$net> and
C<$mask> parameters with values.  On failure it returns -1 and the
C<$err> parameter is filled with an appropriate error message.

=back

=head2 Packet capture functions

=over 4

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

=item B<Net::Pcap::open_dead($linktype, $snaplen)>

Creates and returns a new packet descriptor to use when calling the other 
functions in C<libpcap>. It is typically used when just using C<libpcap> 
for compiling BPF code. 

B<Example>

    $pcap = Net::Pcap::open_dead(0, 1024);

=item B<Net::Pcap::open_offline($filename, \$err)>

Return a packet capture descriptor to read from a previously created
"savefile".  The returned descriptor is undefined if there was an
error and in this case the C<$err> parameter will be filled.  Savefiles
are created using the C<Net::Pcap::dump_*> commands.

B<Example>

    $pcap = Net::Pcap::open_offline($dump, \$err)
        or die "Can't read '$dump': $err\n";

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

=item B<Net::Pcap::breakloop($pcap)>

Sets a flag  that will force C<Net::Pcap::dispatch()> or C<Net::Pcap::loop()> 
to return rather than looping; they will return the number of packets that 
have been processed so far, or -2 if no packets have been processed so far. 

This routine is safe to use inside a signal handler on UNIX or a console 
control handler on Windows, as it merely sets a flag that is checked within 
the loop. 

Please see the section on C<pcap_breakloop()> in L<pcap(3)> for more 
information. 

=item B<Net::Pcap::close($pcap)>

Close the packet capture device associated with descriptor C<$pcap>.

=item B<Net::Pcap::dispatch($pcap, $count, \&callback, $user_data)>

Collect C<$count> packets and process them with callback function
C<&callback>.  if C<$count> is -1, all packets currently buffered are
processed.  If C<$count> is 0, process all packets until an error occurs. 

=item B<Net::Pcap::next($pcap, \%header)>

Return the next available packet on the interface associated with
packet descriptor C<$pcap>.  Into the C<%header> hash is stored the received
packet header.  If not packet is available, the return value and
header is undefined.

=item B<Net::Pcap::compile($pcap, \$filter, $filter_str, $optimize, $netmask)>

Compile the filter string contained in C<$filter_str> and store it in
C<$filter>.  A description of the filter language can be found in the
libpcap source code, or the manual page for tcpdump(8) .  The filter
is optimized if the C<$optimize> variable is true.  The netmask of the 
network device must be specified in the C<$netmask> parameter.  The 
function returns 0 if the compilation was successful, or -1 if there 
was a problem.

=item B<Net::Pcap::setfilter($pcap, $filter)>

Associate the compiled filter stored in C<$filter> with the packet
capture descriptor C<$pcap>.

=item B<Net::Pcap::setnonblock($pcap, $mode, \$err)>

Set the I<non-blocking> mode of a live capture descriptor, depending on the 
value of C<$mode> (zero to activate and non-zero to desactivate). It has no 
effect on offline descriptors. If there is an error, it returns -1 and sets 
C<$err>. 

In non-blocking mode, an attempt to read from the capture descriptor with 
C<pcap_dispatch()> will, if no packets are currently available to be read, 
return 0  immediately rather than blocking waiting for packets to arrive. 
C<pcap_loop()> and C<pcap_next()> will not work in non-blocking mode. 

=item B<Net::Pcap::getnonblock($pcap, \$err)>

Returns the I<non-blocking> state of the capture descriptor C<$pcap>. 
Always returns 0 on savefiles. If there is an error, it returns -1 and 
sets C<$err>. 

=back

=head2 Savefile commands

=over 4

=item B<Net::Pcap::dump_open($pcap, $filename)>

Open a savefile for writing and return a descriptor for doing so.  If
$filename is C<"-"> data is written to standard output.  On error, the
return value is undefined and C<Net::Pcap::geterr()> can be used to
retrieve the error text.

=item B<Net::Pcap::dump($pcap_dumper_t, \%header, $packet)>

Dump the packet described by header C<%header> and packet data C<$packet> 
to the savefile associated with C<$pcap_dumper_t>.  The packet header has the
same format as that passed to the C<Net::Pcap::loop()> callback.

=item B<Net::Pcap::dump_close($pcap_dumper_t)>

Close the savefile associated with descriptor C<$pcap_dumper_t>.

=back

=head2 Status functions

=over 4

=item B<Net::Pcap::datalink($pcap)>

Returns the link layer type associated with the given pcap descriptor.

B<Example>

    $linktype = Net::Pcap::datalink($pcap);

=item B<Net::Pcap::set_datalink($pcap, $linktype)>

Sets the data link type of the given pcap descriptor to the type specified 
by C<$linktype>. Returns -1 on failure. 

=item B<Net::Pcap::datalink_name_to_val($name)>

Translates a data link type name, which is a C<DLT_> name with the C<DLT_> 
part removed, to the corresponding data link type value. The translation is 
case-insensitive. Returns -1 on failure. 

B<Example>

    $linktype = Net::Pcap::datalink_name_to_val('LTalk');  # returns DLT_LTALK

=item B<Net::Pcap::datalink_val_to_name($linktype)>

Translates a data link type value to the corresponding data link type name. 

B<Example>

    $name = Net::Pcap::datalink_val_to_name(DLT_LTALK);  # returns 'LTALK'

=item B<Net::Pcap::datalink_val_to_description($linktype)>

Translates a data link type value to a short description of that data link type.

B<Example>

    $descr = Net::Pcap::datalink_val_to_description(DLT_LTALK);  # returns 'Localtalk'

=item B<Net::Pcap::snapshot($pcap)>

Returns the snapshot length (snaplen) specified in the call to
B<Net::Pcap::open_live()>.

=item B<Net::Pcap::is_swapped($pcap)>

This function returns true if the endianess of the currently open
savefile is different from the endianess of the machine.

=item B<Net::Pcap::major_version($pcap)>

Return the major version number of the pcap library used to write the
currently open savefile.

=item B<Net::Pcap::minor_version($pcap)>

Return the minor version of the pcap library used to write the
currently open savefile.

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

=item B<Net::Pcap::file($pcap)>

Return the filehandle associated with a savefile opened with
C<Net::Pcap::open_offline()>.

=item B<Net::Pcap::fileno($pcap)>

Return the file number of the network device opened with
C<Net::Pcap::open_live()>.

=back

=head2 Error handling

=over 4

=item B<Net::Pcap::geterr($pcap)>

Returns an error message for the last error associated with the packet
capture device C<$pcap>.

=item B<Net::Pcap::strerror($errno)>

Returns a string describing error number C<$errno>.

=item B<Net::Pcap::perror($pcap, $prefix)>

Prints the text of the last error associated with descriptor C<$pcap> on
standard error, prefixed by C<$prefix>.

=back

=head2 Information

=over 4

=item B<Net::Pcap::lib_version()>

Returns the name and version of the C<pcap> library the module was linked 
against. 

=back


=head1 DIAGNOSTICS

=over 4

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

the error string associated to a C<pcap_tPtr> is never reset, thus 
leading to potential false errors; see F<t/09-error.t>

=item *

C<Net::Pcap::file()> seems to always returns C<undef> for live 
connection and causes segmentation fault for dump files; 
see F<t/10-fileno.t>

=back


=head1 EXAMPLES

See the F<eg/> and F<t/> directories of the C<Net::Pcap> distribution 
for examples on using this module.


=head1 SEE ALSO

pcap(3), tcpdump(8)

The source code for libpcap is available from L<http://www.tcpdump.org/>


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
