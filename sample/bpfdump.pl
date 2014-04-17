#!/usr/local/bin/perl

use strict;
use warnings;
use Net::BPF;

my $bpf = Net::BPF->new(interface => 'wm0', 'capture' => 1, 'immediate' => 1);


# arp filter
$bpf->filter(
	Net::BPF::BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	Net::BPF::BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0806, 0, 1),
	Net::BPF::BPF_STMT(BPF_RET + BPF_K, -1),
	Net::BPF::BPF_STMT(BPF_RET + BPF_K, 0),
);

$bpf->rtimeout(3.141592);
print "READ TIMEOUT: ", $bpf->rtimeout(), "\n";
print "DLT: ", $bpf->dlt(), "\n";


print "BPF VERSION: ", join(".", $bpf->version()), "\n";


#exit;



$| = 1;
while (1) {
	my $packet = $bpf->receive();
	unless (defined $packet) {

		my ($recv, $drop, $capt) = $bpf->stats();
		print "recv=$recv, drop=$drop, capt=$capt\n";


		print "read timeout. next\n";
		next;
	}

	my ($ether_dst, $ether_src, $ether_type, $data) = unpack("H12H12H4H*", $packet);

	print "ETHER HEADER: $ether_type: $ether_src -> $ether_dst\n";
	printf "DATA(%5d):  ", length($data) / 2;
	print $data, "\n";
}
