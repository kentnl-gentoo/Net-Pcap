/*
 * pcap.xs
 *
 * XS wrapper for LBL pcap(3) library.
 *
 * Copyright (c) 1999 Tim Potter. All rights reserved. This program is free 
 * software; you can redistribute it and/or modify it under the same terms 
 * as Perl itself.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#define  WINSOCK2_H_REQUESTED
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <pcap.h>
#include <pcap-bpf.h>

#include "const-c.inc"

#ifdef _WIN32
#define _WINPCAP
#include <Win32-Extensions.h>
#endif

#ifdef _WINPCAP
#include <remote-ext.h>
#endif

/* avoid space in the name of struct_bpf_programPtr class */
typedef struct bpf_program struct_bpf_program;

#ifdef __cplusplus
}
#endif


/* Wrapper for callback function */

SV *callback_fn;

void callback_wrapper(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
    SV *packet = newSVpv((u_char *)pkt, h->caplen);
    HV *hdr = newHV();
    SV *ref_hdr = newRV_inc((SV*)hdr);

    /* Push arguments onto stack */

    dSP;

    hv_store(hdr, "tv_sec", strlen("tv_sec"), newSViv(h->ts.tv_sec), 0);
    hv_store(hdr, "tv_usec", strlen("tv_usec"), newSViv(h->ts.tv_usec), 0);
    hv_store(hdr, "caplen", strlen("caplen"), newSViv(h->caplen), 0);
    hv_store(hdr, "len", strlen("len"), newSViv(h->len), 0);	

    PUSHMARK(sp);
    XPUSHs((SV*)user);
    XPUSHs(ref_hdr);
    XPUSHs(packet);
    PUTBACK;

    /* Call perl function */

    call_sv (callback_fn, G_DISCARD);

    /* Decrement refcount to temp SVs */

    SvREFCNT_dec(packet);
    SvREFCNT_dec(hdr);
    SvREFCNT_dec(ref_hdr);
}


MODULE = Net::Pcap	PACKAGE = Net::Pcap	 PREFIX = pcap_

INCLUDE: const-xs.inc

PROTOTYPES: DISABLE


char *
pcap_lookupdev(err)
	SV *err

	CODE:
		if (SvROK(err)) {
			char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
			SV *err_sv = SvRV(err);
			char *dev;

			dev = pcap_lookupdev(errbuf);

			if (!strcmp(dev,"\\")) {
				pcap_if_t *alldevs;
				if (pcap_findalldevs(&alldevs, errbuf) == -1) {
     					sv_setpv(err_sv, errbuf);
				} else {
					dev = alldevs->name;
				}
			} 
#ifdef _WIN32
			int length = lstrlenW((PWSTR)RETVAL) + 2;
			char *r = safemalloc(length);  /* Conversion from Unicode to ANSI */
			WideCharToMultiByte(CP_ACP, 0, (PWSTR)RETVAL, -1, r, length, NULL, NULL);	
			lstrcpyA(RETVAL, r);
			safefree(r);
#endif
			RETVAL = dev;

			if (RETVAL == NULL) {
				sv_setpv(err_sv, errbuf);
			} else {
				err_sv = &PL_sv_undef;
			}

			safefree(errbuf);
		} else
			croak("arg1 not a hash ref");

	OUTPUT:
		RETVAL
		err


int
pcap_lookupnet(device, net, mask, err)
	const char *device
	SV *net
	SV *mask
	SV *err

	CODE:
		if (SvROK(net) && SvROK(mask) && SvROK(err)) {
			char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
			unsigned int netp, maskp;
			SV *net_sv  = SvRV(net);
			SV *mask_sv = SvRV(mask);
			SV *err_sv  = SvRV(err);

			RETVAL = pcap_lookupnet(device, &netp, &maskp, errbuf);

			netp = ntohl(netp);
			maskp = ntohl(maskp);

			if (RETVAL != -1) {
				sv_setiv(net_sv, netp);
				sv_setiv(mask_sv, maskp);
				err_sv = &PL_sv_undef;
			} else {
				sv_setpv(err_sv, errbuf);
			}

			safefree(errbuf);

		} else {
			if (!SvROK(net )) croak("arg2 not a reference");
			if (!SvROK(mask)) croak("arg3 not a reference");
			if (!SvROK(err )) croak("arg4 not a reference");
		}

	OUTPUT:
		net
		mask
		err
		RETVAL


void
pcap_findalldevs(err)
	SV *err

	PPCODE:
		if (SvROK(err)) {
			pcap_if_t *alldevs;
			pcap_if_t *d;
			SV *err_sv = SvRV(err);
			char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
			if (pcap_findalldevs(&alldevs, errbuf) == -1) {
     				sv_setpv(err_sv, errbuf);
	   	        } else {
					for (d=alldevs; d; d=d->next) {
						XPUSHs(sv_2mortal(newSVpv(d->name, 0)));
				}
			}
		} else
			croak ("arg1 not a reference");


pcap_t *
pcap_open_live(device, snaplen, promisc, to_ms, err)
	const char *device
	int snaplen
	int promisc
	int to_ms
	SV *err;

	CODE:
		if (SvROK(err)) {
			char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
			SV *err_sv = SvRV(err);

			RETVAL = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);

			if (RETVAL == NULL) {
				sv_setpv(err_sv, errbuf);
			} else {
				err_sv = &PL_sv_undef;
			}

			safefree(errbuf);
		} else
			croak("arg5 not a reference");

	OUTPUT:
		err
		RETVAL


pcap_t *
pcap_open_dead(linktype, snaplen)
    int linktype
    int snaplen

    OUTPUT:
        RETVAL


pcap_t *
pcap_open_offline(fname, err)
	const char *fname
	SV *err

	CODE:
		if (SvROK(err)) {
			char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
			SV *err_sv = SvRV(err);

			RETVAL = pcap_open_offline(fname, errbuf);

			if (RETVAL == NULL) {
				sv_setpv(err_sv, errbuf);
			} else {
				err_sv = &PL_sv_undef;
			}

			safefree(errbuf);
		} else
			croak("arg2 not a reference");	

	OUTPUT:
		err
		RETVAL


pcap_dumper_t *
pcap_dump_open(p, fname)
	pcap_t *p
	const char *fname


int
pcap_setnonblock(p, nb, err)
	pcap_t *p
	int nb
	SV *err

	CODE:
		char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
		SV *err_sv = SvRV(err);

		RETVAL = pcap_setnonblock(p, nb, errbuf);

		if (RETVAL == -1) {
			sv_setpv(err_sv, errbuf);
		} else {
			err_sv = &PL_sv_undef;
		}

		safefree(errbuf);

	OUTPUT:
		err
		RETVAL


int
pcap_getnonblock(p, err)
  pcap_t *p
  SV *err

  CODE:
    char *errbuf = safemalloc(PCAP_ERRBUF_SIZE);
    SV *err_sv = SvRV(err);

    RETVAL = pcap_getnonblock(p, errbuf);

    if (RETVAL == -1) {
        sv_setpv(err_sv, errbuf);
    } else {
        err_sv = &PL_sv_undef;
    }

    safefree(errbuf);

  OUTPUT:
    err
    RETVAL


int
pcap_dispatch(p, cnt, callback, user)
	pcap_t *p
	int cnt
	SV *callback
	SV *user

	CODE:
		callback_fn = newSVsv(callback);
		user = newSVsv(user);

		RETVAL = pcap_dispatch(p, cnt, callback_wrapper, (u_char *)user);

		SvREFCNT_dec(user);
		SvREFCNT_dec(callback_fn);
		
	OUTPUT:
		RETVAL


int
pcap_loop(p, cnt, callback, user)
	pcap_t *p
	int cnt
	SV *callback
	SV *user

	CODE:	
		callback_fn = newSVsv(callback);
		user = newSVsv(user);

		RETVAL = pcap_loop(p, cnt, callback_wrapper, (u_char *)user);

		SvREFCNT_dec(user);
		SvREFCNT_dec(callback_fn);

	OUTPUT:
		RETVAL


SV *
pcap_next(p, h)
        pcap_t *p
	SV *h

	CODE:
		if (SvROK(h) && (SvTYPE(SvRV(h)) == SVt_PVHV)) {
			struct pcap_pkthdr real_h;
			const u_char *result;
			HV *hv;

			memset(&real_h, '\0', sizeof(real_h));

			result = pcap_next(p, &real_h);

			hv = (HV *)SvRV(h);	
	
			if (result != NULL) {

				hv_store(hv, "tv_sec", strlen("tv_sec"),
					 newSViv(real_h.ts.tv_sec), 0);
				hv_store(hv, "tv_usec", strlen("tv_usec"),
					 newSViv(real_h.ts.tv_usec), 0);
				hv_store(hv, "caplen", strlen("caplen"),
					 newSViv(real_h.caplen), 0);
				hv_store(hv, "len", strlen("len"),
					 newSViv(real_h.len), 0);	

				RETVAL = newSVpv((char *)result, 
						 real_h.caplen);
			} else 
				RETVAL = &PL_sv_undef;

		} else
            croak("arg2 not a hash ref");	

	OUTPUT:
	        h
		RETVAL     


void 
pcap_dump(p, h, sp)
	pcap_dumper_t *p
	SV *h
	SV *sp

	CODE:
		/* Check h (packet header) is a hashref */

		if (SvROK(h) && (SvTYPE(SvRV(h)) == SVt_PVHV)) {
		        struct pcap_pkthdr real_h;
			char *real_sp;
			HV *hv;
			SV **sv;

			memset(&real_h, '\0', sizeof(real_h));

			/* Copy from hash to pcap_pkthdr */

			hv = (HV *)SvRV(h);

			sv = hv_fetch(hv, "tv_sec", strlen("tv_sec"), 0);
			if (sv != NULL) {
				real_h.ts.tv_sec = SvIV(*sv);
			}

			sv = hv_fetch(hv, "tv_usec", strlen("tv_usec"), 0);
			if (sv != NULL) {
				real_h.ts.tv_usec = SvIV(*sv);
			}

			sv = hv_fetch(hv, "caplen", strlen("caplen"), 0);
			if (sv != NULL) {
			        real_h.caplen = SvIV(*sv);
		        }

			sv = hv_fetch(hv, "len", strlen("len"), 0);
			if (sv != NULL) {
			        real_h.len = SvIV(*sv);
			}

			real_sp = SvPV(sp, PL_na);

			/* Call pcap_dump() */

			pcap_dump((u_char *)p, &real_h, real_sp);
		
		} else
            croak("arg2 not a hash ref");


int 
pcap_compile(p, fp, str, optimize, mask)
	pcap_t *p
	SV *fp;
	char *str
	int optimize
	bpf_u_int32 mask

	CODE:
		if (SvROK(fp)) {
			struct bpf_program *real_fp = safemalloc(sizeof(struct bpf_program));

			RETVAL = pcap_compile(p, real_fp, str, optimize, mask);

			sv_setref_pv(SvRV(ST(1)), "struct bpf_programPtr",
				     (void *)real_fp);
		} else
			croak("arg2 not a reference");

	OUTPUT:
		fp
		RETVAL


int 
pcap_setfilter(p, fp)
	pcap_t *p
	struct bpf_program *fp


void
pcap_breakloop(p)
    pcap_t *p


void
pcap_close(p)
	pcap_t *p


void
pcap_dump_close(p)
	pcap_dumper_t *p


int 
pcap_datalink(p)
	pcap_t *p


int
pcap_set_datalink(p, linktype)
    pcap_t *p
    int linktype


int
pcap_datalink_name_to_val(name)
    const char *name


const char *
pcap_datalink_val_to_name(linktype)
    int linktype


const char *
pcap_datalink_val_to_description(linktype)
    int linktype


int 
pcap_snapshot(p)
	pcap_t *p


int 
pcap_is_swapped(p)
	pcap_t *p


int 
pcap_major_version(p)
	pcap_t *p


int 
pcap_minor_version(p)
	pcap_t *p


void
pcap_perror(p, prefix)
	pcap_t *p
	char *prefix
 

char *
pcap_geterr(p)
	pcap_t *p


char *
pcap_strerror(error)
	int error


const char *
pcap_lib_version()


FILE *
pcap_file(p)
	pcap_t *p


int
pcap_fileno(p)
	pcap_t *p


int
pcap_stats(p, ps)
	pcap_t *p;
	SV *ps;

	CODE:
		/* Call pcap_stats() function */

		if (SvROK(ps) && (SvTYPE(SvRV(ps)) == SVt_PVHV)) {
			struct pcap_stat real_ps;
			HV *hv;

			RETVAL = pcap_stats(p, &real_ps);

			/* Copy pcap_stats fields into hash */

			hv = (HV *)SvRV(ps);

			hv_store(hv, "ps_recv", strlen("ps_recv"), 
		                 newSViv(real_ps.ps_recv), 0);
			hv_store(hv, "ps_drop", strlen("ps_drop"), 
			         newSViv(real_ps.ps_drop), 0);
			hv_store(hv, "ps_ifdrop", strlen("ps_ifdrop"), 
		                 newSViv(real_ps.ps_ifdrop), 0);

		} else
            croak("arg2 not a hash ref");

	OUTPUT:
		RETVAL

