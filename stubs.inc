/* Stubs for functions not available in libpcap */
#define FUNCTION_NOT_IMPLEMENTED_ERROR(func)  fputs(\
        "The function " #func "() is not available in your release of the pcap library.", stderr);

#ifndef pcap_lib_version
const char * pcap_lib_version(void);
const char * pcap_lib_version(void) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_lib_version)
    return "";
}
#endif

#ifndef pcap_findalldevs
int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf);
int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_findalldevs)
    return -1;
}
#endif

#ifndef pcap_breakloop
void pcap_breakloop(pcap_t * p);
void pcap_breakloop(pcap_t * p) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_breakloop)
}
#endif

#ifndef pcap_setnonblock
int pcap_setnonblock(pcap_t * p, int nonblock, char * errbuf);
int pcap_setnonblock(pcap_t * p, int nonblock, char * errbuf) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_setnonblock)
    return -1;
}
#endif

#ifndef pcap_getnonblock
int pcap_getnonblock(pcap_t * p, char * errbuf);
int pcap_getnonblock(pcap_t * p, char * errbuf) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_getnonblock)
    return -1;
}
#endif

#ifndef pcap_set_datalink
int pcap_set_datalink(pcap_t * p, int datalink);
int pcap_set_datalink(pcap_t * p, int datalink) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_set_datalink)
    return -1;
}
#endif

#ifndef pcap_datalink_name_to_val
int pcap_datalink_name_to_val(const char * name);
int pcap_datalink_name_to_val(const char * name) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_datalink_name_to_val)
    return -1;
}
#endif

#ifndef pcap_datalink_val_to_name
const char * pcap_datalink_val_to_name(int datalink);
const char * pcap_datalink_val_to_name(int datalink) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_datalink_val_to_name)
    return "";
}
#endif

#ifndef pcap_datalink_val_to_description
const char * pcap_datalink_val_to_description(int datalink);
const char * pcap_datalink_val_to_description(int datalink) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_datalink_val_to_description)
    return "";
}
#endif

