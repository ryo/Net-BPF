print "1..7\n";

use Net::BPF;

my $bpf = Net::BPF->new();
print "not " unless (defined $bpf);
print "ok 1\n";

print "not " unless ($bpf->buffersize(1024 * 32));
print "ok 2\n";
print "not " unless ($bpf->buffersize() == 1024 * 32);
print "ok 3\n";

print "not " unless ($bpf->interface('lo0'));
print "ok 4\n";
print "not " unless ($bpf->interface() eq 'lo0');
print "ok 5\n";

print "not " unless ($bpf->immediate(1));
print "ok 6\n";

print "not " unless ($bpf->hdrcmplt(1));
print "ok 7\n";
