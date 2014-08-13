package Net::BPF;

use 5.008008;
use strict;
use warnings;
use Carp;
use Exporter;
use IO::File;
our @ISA = qw(IO::Handle);

our @EXPORT = qw(
	BPF_STMT
	BPF_JUMP
	BPF_LD BPF_LDX BPF_ST BPF_STX BPF_ALU BPF_JMP BPF_RET BPF_MISC
	BPF_W BPF_H BPF_B
	BPF_IMM BPF_ABS BPF_IND BPF_MEM BPF_LEN BPF_MSH
	BPF_ADD BPF_SUB BPF_MUL BPF_DIV BPF_OR BPF_AND BPF_LSH BPF_RSH BPF_NEG
	BPF_JA BPF_JEQ BPF_JGT BPF_JGE BPF_JSET
	BPF_K BPF_X BPF_A
	BPF_TAX BPF_TXA
);

our @EXPORT_OK = qw(
	BPF_ALIGNMENT
	BPF_MAXINSNS
	BPF_DFLTBUFSIZE
	BPF_MAXBUFSIZE
	BPF_MINBUFSIZE
);

our %EXPORT_TAGS = (
	all => [@EXPORT, @EXPORT_OK],
);


our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Net::BPF', $VERSION);

# Preloaded methods go here.

sub BPF_STMT {
	my ($code, $k) = @_;
	($code, 0, 0, $k);
}

sub BPF_JUMP {
	my ($code, $k, $jt, $jf) = @_;
	($code, $jt, $jf, $k);
}

sub new {
	my ($class, %arg) = @_;

	my $mode = (exists($arg{'capture'}) && $arg{'capture'}) ? O_RDWR : O_WRONLY;
	my $bpf = IO::File->new("/dev/bpf", $mode) or do {
		$@ = "Cannot open /dev/bpf: $!\n";
		return undef;
	};
	bless $bpf, $class;

	# set and get bpf buffer size
	$bpf->buffersize(1024 * 1024 * 4);
	${*$bpf}{_bpfbuflen} = $bpf->buffersize();

	${*$bpf}{_recvpkt} = [];
	${*$bpf}{_recvbuf} = '';

	while (my ($key, $value) = each %arg) {
		if ($key =~ m/^interface$/) {
			# nothong to do now
		} elsif ($key =~ m/^buffersize$/) {
			$bpf->buffersize($value);
		} elsif ($key =~ m/^capture$/) {
			# nothong to do here
		} elsif ($key =~ m/^immediate?$/) {
			$bpf->immediate($value);
		} elsif ($key =~ m/^hdrcmplt$/) {
			$bpf->hdrcmplt($value);
		} elsif ($key =~ m/^promisc(uous)?$/) {
			# nothong to do now
		} else {
			warn "unknown parameter: $key\n";
			return undef;
		}
	}

	if (exists $arg{interface}) {
		$bpf->interface($arg{interface});

		# promiscuous() requires attached interface
		while (my ($key, $value) = each %arg) {
			if ($key =~ m/^promisc(uous)?$/) {
				$bpf->promiscuous($value);
			}
		}
	}

	$bpf;
}

sub filter {
	my $bpf = shift;
	my @filter = @_;

	my $bf_insn = '';

	while ($#filter >= 3) {
		my @insn = splice(@filter, 0, 4);
		$bf_insn .= pack_bpf_insn(@insn);
	}
	if ($#filter >= 0) {
		confess "Net::BPF::filter: invalid length of bpf_insns\n";
	}

	$bpf->setf($bf_insn);
}

sub send {
	my $bpf = shift;
	my $data = shift;

	$bpf->syswrite($data);
}

sub receive {
	my $bpf = shift;

	if ($#{${*$bpf}{_recvpkt}} < 0) {
		$bpf->sysread(${*$bpf}{_recvbuf}, ${*$bpf}{_bpfbuflen});
	}

	while (1) {
		my ($sec, $usec, $caplen, $datalen, $hdrlen) = unpack_bpf_hdr(${*$bpf}{_recvbuf});
		last unless (defined $sec);

		push(@{${*$bpf}{_recvpkt}}, substr(${*$bpf}{_recvbuf}, $hdrlen, $caplen));
		substr(${*$bpf}{_recvbuf}, 0, BPF_WORDALIGN($hdrlen + $caplen)) = '';
	}

	if ($#{${*$bpf}{_recvpkt}} >= 0) {
		return shift @{${*$bpf}{_recvpkt}};
	}

	undef;
}


1;
__END__
=head1 NAME

Net::BPF - Perl interface to reading or writing bpf

=head1 SYNOPSIS

use Net::BPF qw(:all);

  my $bpf = Net::BPF->new(
    interface => "wm0",
    promisc => 1,
    hdrcmplt => 1,
  ) or die "Cannot construct bpf - $@\n";
  
  # arp filter
  $bpf->filter(
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0806, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, -1),
    BPF_STMT(BPF_RET + BPF_K, 0),
  );
  
  while (1) {
    my $packet = $bpf->receive();
    next unless (defined $packet);  # when read-timeout
  
    my ($ether_dst, $ether_src, $ether_type, $ether_data) = unpack("H12H12H4H*", $packet);
    print "ETHER HEADER: $ether_type: $ether_src -> $ether_dst\n";
    printf "DATA[%5d]:  ", length($data) / 2;
    print $ether_data, "\n";
  }

=head1 DESCRIPTION

Net::BPF module provides a raw interface to BPF(4)

=head1 CONSTRUCTOR

=head2 $bpf = Net::BPF->new( %args )

Create a new C<Net::BPF> object.
The recognised arguments are:

=over 8

=item interface => STRING

specify name of interface.

=item buffersize => INT

sets the buffer length for reads on bpf files.

=item promisc => BOOL

enables or disables C<promiscuous mode>.

=item immediate => BOOL

enables or disables C<immediate mode>.

=item hdrcmplt => BOOL

sets the status of the C<header complete> flag.

=item capture => BOOL

if C<capture> is true, bpf will be opened readonly.
if C<capture> is false (default), bpf is readable and writable. and it is able to send packet.

=back

=head1 METHODS

=over 8

=item $bpf->filter(ARRAY)

sets the bpf_program.

  $bpf->filter(
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0806, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, -1),
    BPF_STMT(BPF_RET + BPF_K, 0),
  );


=item $bpf->send(STRING)

send a packet.

  $bpf->send(pack("C*", 0x01 .. 0xff));

=item $bpf->receive();

receive a packet.

  my $packet = $bpf->receive();

=item $bpf->interface(STRING)

specify name of interface

=item $bpf->promiscuous(BOOL)

enables or disables C<promiscuous mode>.

=item $bpf->setf(STRING)

much the same of $bpf->filter, but setf() treat raw scalar of C<struct bpf_program>.

=item $bpf->flush()

flushes the buffer of incoming packets,
and resets the statistics that are returned by C<stats()>.

=item $bpf->blen([INT])

sets or gets the buffer length for reads on bpf files.

=item $bpf->dlt([INT])

set or gets the type of the data link layer underlying the attached interface

=item $bpf->rtimeout([INT])

sets or gets the read timeout parameter.
you can set timeout 250 milliseconds this way:

  $bpf->rtimeout(0.25);

=item $bpf->stats()

return array of statistics.

  my ($receive_counter, $drop_counter, $capture_counter) = $bpf->stats().

$capture_counter is available only on NetBSD.

=item $bpf->version()

return the major and minor version number of the filter language currently recognized by the kernel.

  my ($major, $minor) = $bpf->version();

=item $bpf->immediate([BOOL])

Enables or disables C<immediate mode>.

=item $bpf->buffersize([INT])

sets or gets the buffer length for reads on bpf files.

=item $bpf->hdrcmplt([BOOL])

sets or gets the status of the C<header complete> flag.

=item $bpf->seesent([BOOL])

enables or disables C<see sent> flag.

=item $bpf->feedback([BOOL])

sets or gets the status of the C<packet feedback mode> flag.

=back

=head1 FUNCTIONS

=over 8

=item BPF_STMT(code, k)

return bpf_insn. see also BPF(4).

=item BPF_JUMP(code, k, jt, jf)

return bpf_insn. see also BPF(4).

=item BPF_WORDALIGN(len)

return aligned length.

=item pack_bpf_insn(code, k, jt, jf)

return the binary pack of struct bpf_insn.

=item unpack_bpf_hdr($rawdata)

unpack bpf raw-data from sysread().
unpack_bpf_hdr() return ARRAY contains 5 values.

  my ($sec, $usec, $caplen, $datalen, $hdrlen) = unpack_bpf_hdr($rawdata);

usually, you can use $bpf->receive(), and you need not to use C<unpack_bpf_hdr()>.

=back

=head1 EXPORT

=over 8

=item BPF_LD BPF_LDX BPF_ST BPF_STX BPF_ALU BPF_JMP BPF_RET BPF_MISC

=item BPF_W BPF_H BPF_B

=item BPF_IMM BPF_ABS BPF_IND BPF_MEM BPF_LEN BPF_MSH

=item BPF_ADD BPF_SUB BPF_MUL BPF_DIV BPF_OR BPF_AND BPF_LSH BPF_RSH BPF_NEG

=item BPF_JA BPF_JEQ BPF_JGT BPF_JGE BPF_JSET

=item BPF_K BPF_X BPF_A

=item BPF_TAX BPF_TXA

=item BPF_ALIGNMENT BPF_MAXINSNS BPF_DFLTBUFSIZE BPF_MAXBUFSIZE BPF_MINBUFSIZE

=back

=head1 SEE ALSO

bpf(4)

=head1 AUTHOR

Ryo Shimizu E<lt>ryo@nerv.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Ryo Shimizu.
All rights reserved.
This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
