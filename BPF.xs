#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>

typedef PerlIO * OutputStream;


MODULE = Net::BPF	PACKAGE = Net::BPF

#include "const-c.inc"
INCLUDE: const-xs.inc


SV *
BPF_WORDALIGN(x)
	unsigned int x;
    CODE:
	XSRETURN_UV(BPF_WORDALIGN(x));
    OUTPUT:
	RETVAL


SV *
interface(stream, ...)
	OutputStream stream
    CODE:
	char *ifname;
	struct ifreq ifreq;
	int ret;

	if (items <= 1) {
		memset(&ifreq, 0, sizeof(ifreq));
		ret = ioctl(PerlIO_fileno(stream), BIOCGETIF, &ifreq);
		if (ret < 0)
			XSRETURN_UNDEF;

		RETVAL = newSVpvn((char *)ifreq.ifr_name, strlen(ifreq.ifr_name));
	} else {
		ifname = (char *)SvPVX(ST(1));
		memset(&ifreq, 0, sizeof(ifreq));
		strncpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));
		ret = ioctl(PerlIO_fileno(stream), BIOCSETIF, &ifreq);
		if (ret >= 0)
			XSRETURN_IV(1);
		else
			XSRETURN_UNDEF;
	}
    OUTPUT:
	RETVAL


SV *
pack_bpf_insn(...)
    PROTOTYPE: @
    CODE:
	struct bpf_insn insn;

	if (items < 4)
		XSRETURN_UNDEF;

	insn.code = SvIV(ST(0));
	insn.jt = SvIV(ST(1));
	insn.jf = SvIV(ST(2));
	insn.k = SvIV(ST(3));

	RETVAL = newSVpvn((char *)&insn, sizeof(insn));
    OUTPUT:
	RETVAL


void
unpack_bpf_hdr(hdr_sv)
    SV *hdr_sv
    PPCODE:
    {
	STRLEN len;
	struct bpf_hdr bpfhdr;
	char *hdr = SvPVbyte(hdr_sv, len);
	if (len < sizeof(bpfhdr)) {
		EXTEND(SP, 1);
		PUSHs(&PL_sv_undef);
	} else {
		Copy(hdr, &bpfhdr, sizeof(bpfhdr), char);
		EXTEND(SP, 5);
		mPUSHu(bpfhdr.bh_tstamp.tv_sec);
		mPUSHu(bpfhdr.bh_tstamp.tv_usec);
		mPUSHu(bpfhdr.bh_caplen);
		mPUSHu(bpfhdr.bh_datalen);
		mPUSHu(bpfhdr.bh_hdrlen);
	}
    }


void
setf(stream, ...)
	OutputStream stream
    CODE:
	struct bpf_program bpf_prog;
	STRLEN len;
	int ret;

	if (items > 1) {
		bpf_prog.bf_insns = (struct bpf_insn *)SvPV(ST(1), len);
		bpf_prog.bf_len = len / sizeof(struct bpf_insn);

		ret = ioctl(PerlIO_fileno(stream), BIOCSETF, &bpf_prog);
		if (ret >= 0)
			XSRETURN_IV(1);
	}
	XSRETURN_UNDEF;


void
promiscuous(stream)
	OutputStream stream
    CODE:
	int ret;

	ret = ioctl(PerlIO_fileno(stream), BIOCPROMISC);
	if (ret >= 0)
		XSRETURN_IV(1);
	else
		XSRETURN_UNDEF;


void
flush(stream)
	OutputStream stream
    CODE:
	int ret;

	ret = ioctl(PerlIO_fileno(stream), BIOCFLUSH);
	if (ret >= 0)
		XSRETURN_IV(1);
	else
		XSRETURN_UNDEF;


void
blen(stream, ...)
	OutputStream stream
    CODE:
	int ret;
	u_int len;

	if (items > 1) {
		len = SvUV(ST(1));

		ret = ioctl(PerlIO_fileno(stream), BIOCSBLEN, &len);
		if (ret >= 0)
			XSRETURN_IV(len);
	} else {
		ret = ioctl(PerlIO_fileno(stream), BIOCGBLEN, &len);
		if (ret >= 0)
			XSRETURN_IV(len);
	}
	XSRETURN_UNDEF;


void
dlt(stream, ...)
	OutputStream stream
    CODE:
	int ret;
	u_int dlt;

	if (items > 1) {
		dlt = SvUV(ST(1));

		ret = ioctl(PerlIO_fileno(stream), BIOCSDLT, &dlt);
		if (ret >= 0)
			XSRETURN_IV(1);
	} else {
		ret = ioctl(PerlIO_fileno(stream), BIOCGDLT, &dlt);
		if (ret >= 0)
			XSRETURN_IV(dlt);
	}
	XSRETURN_UNDEF;


void
rtimeout(stream, ...)
	OutputStream stream
    CODE:
	int ret;
	NV timeout;
	struct timeval tv;

	if (items > 1) {
		timeout = SvNV(ST(1));
		if (timeout < 0.0)
			timeout = 0.0;
		tv.tv_sec = (long)timeout;
		timeout -= (NV)tv.tv_sec;
		tv.tv_usec = (long)(timeout * 1000000.0);
		ret = ioctl(PerlIO_fileno(stream), BIOCSRTIMEOUT, &tv);
		if (ret >= 0)
			XSRETURN_IV(1);
	} else {
		ret = ioctl(PerlIO_fileno(stream), BIOCGRTIMEOUT, &tv);
		if (ret >= 0) {
			timeout = (NV)tv.tv_sec;
			timeout += (NV)tv.tv_usec / 1000000.0;
			XSRETURN_NV(timeout);
		}
	}
	XSRETURN_UNDEF;


void
stats(stream)
	OutputStream stream
    PPCODE:
	int ret;
	struct bpf_stat bs;

	ret = ioctl(PerlIO_fileno(stream), BIOCGSTATS, &bs);
	if (ret >= 0) {
		EXTEND(SP, 3);
		mPUSHu(bs.bs_recv);
		mPUSHu(bs.bs_drop);
#ifdef __NetBSD__
		mPUSHu(bs.bs_capt);
#else
		mPUSHu(0);
#endif
	} else {
		EXTEND(SP, 1);
		PUSHs(&PL_sv_undef);
	}


void
version(stream)
	OutputStream stream
    PPCODE:
	int ret;
	struct bpf_version bv;

	ret = ioctl(PerlIO_fileno(stream), BIOCVERSION, &bv);
	if (ret >= 0) {
		EXTEND(SP, 2);
		mPUSHu(bv.bv_major);
		mPUSHu(bv.bv_minor);
	} else {
		EXTEND(SP, 1);
		PUSHs(&PL_sv_undef);
	}


void
immediate(stream, ...)
	OutputStream stream
    CODE:
	int i, ret;
	u_int on;

	if (items > 1) {
		on = SvIV(ST(1));
		ret = ioctl(PerlIO_fileno(stream), BIOCIMMEDIATE, &on);
		if (ret >= 0)
			XSRETURN_IV(1);
	}
	XSRETURN_UNDEF;


void
buffersize(stream, ...)
	OutputStream stream
    CODE:
	int i, ret;
	u_int size;

	if (items > 1) {
		size = SvIV(ST(1));
		ret = ioctl(PerlIO_fileno(stream), BIOCSBLEN, &size);
		if (ret >= 0)
			XSRETURN_IV(1);
	} else {
		ret = ioctl(PerlIO_fileno(stream), BIOCGBLEN, &size);
		if (ret >= 0) {
			XSRETURN_IV(size);
		}
	}
	XSRETURN_UNDEF;


void
hdrcmplt(stream, ...)
	OutputStream stream
    CODE:
	int i, ret;
	u_int on;

	if (items > 1) {
		on = SvIV(ST(1));
		ret = ioctl(PerlIO_fileno(stream), BIOCSHDRCMPLT, &on);
		if (ret >= 0)
			XSRETURN_IV(1);
	} else {
		ret = ioctl(PerlIO_fileno(stream), BIOCGHDRCMPLT, &on);
		if (ret >= 0) {
			XSRETURN_IV(on);
		}
	}
	XSRETURN_UNDEF;


void
seesent(stream, ...)
	OutputStream stream
    CODE:
	int i, ret;
	u_int on;

	if (items > 1) {
		on = SvIV(ST(1));
		ret = ioctl(PerlIO_fileno(stream), BIOCSSEESENT, &on);
		if (ret >= 0)
			XSRETURN_IV(1);
	} else {
		ret = ioctl(PerlIO_fileno(stream), BIOCGSEESENT, &on);
		if (ret >= 0) {
			XSRETURN_IV(on);
		}
	}
	XSRETURN_UNDEF;


void
feedback(stream, ...)
	OutputStream stream
    CODE:
	int i, ret;
	u_int on;

	if (items > 1) {
		on = SvIV(ST(1));
#ifdef BIOCSFEEDBACK
		ret = ioctl(PerlIO_fileno(stream), BIOCSFEEDBACK, &on);
#elif defined(BIOCFEEDBACK)
		ret = ioctl(PerlIO_fileno(stream), BIOCSFEEDBACK, &on);
#else
		ret = -1;
#endif
		if (ret >= 0)
			XSRETURN_IV(1);
	} else {
#ifdef BIOCGFEEDBACK
		ret = ioctl(PerlIO_fileno(stream), BIOCGFEEDBACK, &on);
#else
		ret = -1;
#endif
		if (ret >= 0) {
			XSRETURN_IV(on);
		}
	}
	XSRETURN_UNDEF;


