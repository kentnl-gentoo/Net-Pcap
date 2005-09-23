#!/bin/sh
rm -f macros
egrep '#define +BPF_.+'  /usr/include/pcap*h | awk '{print $2}' | grep -v '(' | sort -u >>macros
egrep '#define +DLT_.+'  /usr/include/pcap*h | awk '{print $2}' | sort -u >>macros
egrep '#define +MODE_.+' /usr/include/pcap*h | awk '{print $2}' | sort -u >>macros
egrep '#define +PCAP_.+' /usr/include/pcap*h | awk '{print $2}' | sort -u >>macros
