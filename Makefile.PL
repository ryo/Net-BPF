#!perl

use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::Constant 0.23 'WriteConstants';

WriteMakefile(
	NAME			=> 'Net::BPF',
	VERSION_FROM		=> 'lib/Net/BPF.pm',
	($] >= 5.005 ?		## Add these new keywords supported since 5.005
	  (ABSTRACT_FROM	=> 'lib/Net/BPF.pm', # retrieve abstract from module
	   AUTHOR		=> 'Ryo Shimizu <ryo@nerv.org>') : ()),
	realclean		=> { FILES => 'const-c.inc const-xs.inc'},
);

my @names = qw(
BPF_ALIGNMENT
BPF_MAXINSNS
BPF_DFLTBUFSIZE
BPF_MAXBUFSIZE
BPF_MINBUFSIZE

BPF_LD
BPF_LDX
BPF_ST
BPF_STX
BPF_ALU
BPF_JMP
BPF_RET
BPF_MISC
BPF_W
BPF_H
BPF_B
BPF_IMM
BPF_ABS
BPF_IND
BPF_MEM
BPF_LEN
BPF_MSH
BPF_ADD
BPF_SUB
BPF_MUL
BPF_DIV
BPF_OR
BPF_AND
BPF_LSH
BPF_RSH
BPF_NEG
BPF_JA
BPF_JEQ
BPF_JGT
BPF_JGE
BPF_JSET
BPF_K
BPF_X
BPF_A
BPF_TAX
BPF_TXA
);

WriteConstants(
	PROXYSUBS => {autoload => 1},
	NAME => 'Net::BPF',
	NAMES => \@names,
);
