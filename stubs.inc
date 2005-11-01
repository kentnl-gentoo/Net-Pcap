/* Stubs for functions not available in libpcap */
#define FUNCTION_NOT_IMPLEMENTED_ERROR(func)  croak(\
        "The function " #func "() is not available in your release of the pcap library.");
#define FUNCTION_NOT_IMPLEMENTED_WARNING(func)  warn(\
        "The function " #func "() is not available in your release of the pcap library.");

#ifndef HAVE_PCAP_LIB_VERSION
#ifdef __GNUC__
#warning "the function pcap_lib_version() is not available, but will be emulated"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_lib_version() is not available, but will be emulated" )
#endif
const char * pcap_lib_version(void);
const char * pcap_lib_version(void) {
    return "libpcap version unknown (pre 0.8)";
}
#endif

#ifndef HAVE_PCAP_FINDALLDEVS
#ifdef __GNUC__
#warning "the function pcap_findalldevs() is not available, but will be emulated"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_findalldevs() is not available, but will be emulated" )
#endif
typedef struct pcap_if pcap_if_t;
struct pcap_if {
    struct pcap_if *next;
    char *name;     /* name to hand to "pcap_open_live()" */
    char *description;  /* textual description of interface, or NULL */
    struct pcap_addr *addresses;
    bpf_u_int32 flags;  /* PCAP_IF_ interface flags */
};

int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf);
int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf) {
    return 3;
}

void pcap_freealldevs(pcap_if_t * alldevsp);
void pcap_freealldevs(pcap_if_t * alldevsp) {
    return;
}
#endif

#ifndef HAVE_PCAP_BREAKLOOP
#ifdef __GNUC__
#warning "the function pcap_breakloop() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_breakloop() is not available" )
#endif
void pcap_breakloop(pcap_t * p);
void pcap_breakloop(pcap_t * p) {
    FUNCTION_NOT_IMPLEMENTED_WARNING(pcap_breakloop)
}
#endif

#ifndef HAVE_PCAP_SETNONBLOCK
#ifdef __GNUC__
#warning "the function pcap_setnonblock() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_setnonblock() is not available" )
#endif
int pcap_setnonblock(pcap_t * p, int nonblock, char * errbuf);
int pcap_setnonblock(pcap_t * p, int nonblock, char * errbuf) {
    FUNCTION_NOT_IMPLEMENTED_WARNING(pcap_setnonblock)
    return -1;
}
#endif

#ifndef HAVE_PCAP_GETNONBLOCK
#ifdef __GNUC__
#warning "the function pcap_getnonblock() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_getnonblock() is not available" )
#endif
int pcap_getnonblock(pcap_t * p, char * errbuf);
int pcap_getnonblock(pcap_t * p, char * errbuf) {
    FUNCTION_NOT_IMPLEMENTED_WARNING(pcap_getnonblock)
    return -1;
}
#endif

#ifndef HAVE_PCAP_DUMP_FILE
#ifdef __GNUC__
#warning "the function pcap_dump_file() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_dump_file() is not available" )
#endif
FILE *pcap_dump_file(pcap_dumper_t *p);
FILE *pcap_dump_file(pcap_dumper_t *p) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_dump_file)
    return NULL;
}
#endif

#ifndef HAVE_PCAP_DUMP_FLUSH
#ifdef __GNUC__
#warning "the function pcap_dump_flush() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_dump_flush() is not available" )
#endif
int pcap_dump_flush(pcap_dumper_t *p);
int pcap_dump_flush(pcap_dumper_t *p) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_dump_flush)
    return -1;
}
#endif

#ifndef HAVE_PCAP_SET_DATALINK
#ifdef __GNUC__
#warning "the function pcap_set_datalink() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_set_datalink() is not available" )
#endif
int pcap_set_datalink(pcap_t * p, int datalink);
int pcap_set_datalink(pcap_t * p, int datalink) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_set_datalink)
    return -1;
}
#endif

#ifndef HAVE_PCAP_DATALINK_NAME_TO_VAL
#ifdef __GNUC__
#warning "the function pcap_datalink_name_to_val() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_datalink_name_to_val() is not available" )
#endif
int pcap_datalink_name_to_val(const char * name);
int pcap_datalink_name_to_val(const char * name) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_datalink_name_to_val)
    return -1;
}
#endif

#ifndef HAVE_PCAP_DATALINK_VAL_TO_NAME
#ifdef __GNUC__
#warning "the function pcap_datalink_val_to_name() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_datalink_val_to_name() is not available" )
#endif
const char * pcap_datalink_val_to_name(int datalink);
const char * pcap_datalink_val_to_name(int datalink) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_datalink_val_to_name)
    return "";
}
#endif

#ifndef HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION
#ifdef __GNUC__
#warning "the function pcap_datalink_val_to_description() is not available"
#endif
#ifdef _MSC_VER
#pragma message( "Warning: the function pcap_datalink_val_to_description() is not available" )
#endif
const char * pcap_datalink_val_to_description(int datalink);
const char * pcap_datalink_val_to_description(int datalink) {
    FUNCTION_NOT_IMPLEMENTED_ERROR(pcap_datalink_val_to_description)
    return "";
}
#endif

