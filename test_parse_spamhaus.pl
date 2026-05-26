#!/usr/bin/env perl
use v5.32; use strict; use warnings;
use Socket qw(AF_INET AF_INET6 inet_pton inet_ntop);
use Math::BigInt;

my @lines = (
"; Spamhaus DROP List 2026/05/26 - (c) 2026 The Spamhaus Project SLU",
"; https://www.spamhaus.org/drop/drop.txt",
"; Last-Modified: Tue, 26 May 2026 11:00:16 GMT",
"; Expires: Tue, 26 May 2026 12:14:02 GMT",
"1.10.16.0/20 ; SBL256894",
"1.19.0.0/16 ; SBL434604",
"1.32.128.0/18 ; SBL286275",
);

sub pack_ip { my ($ip)=@_; return unless defined $ip && length $ip; my $p = inet_pton(AF_INET, $ip); return $p if defined $p; return inet_pton(AF_INET6,$ip); }
sub packed_to_bigint { my ($packed)=@_; return unless defined $packed; my $hex = unpack('H*',$packed); return Math::BigInt->from_hex('0x'.$hex); }
sub bigint_to_packed { my ($bi,$len)=@_; return unless defined $bi; my $hex = $bi->as_hex(); $hex =~ s/^0x//i; $hex = '0'.$hex unless length($hex) %2 ==0; my $need = $len*2; $hex = ('0' x ($need-length($hex))).$hex if length($hex) < $need; return pack('H*',$hex); }

sub cidr_to_range {
    my ($cidr)=@_; return unless $cidr =~ m{^([^/]+)/(\d+)$}; my ($ip,$prefix)=($1,$2);
    my $p = pack_ip($ip); return unless defined $p; my $len = length $p; my @mask; my $bits=$prefix;
    for my $i (1..$len) { if ($bits >=8) { push @mask,0xFF; $bits-=8 } elsif ($bits<=0) { push @mask,0x00 } else { push @mask, ((0xFF << (8-$bits)) & 0xFF); $bits=0 } }
    my ($start,$end) = ('','');
    for my $i (0..$len-1) { my $b=ord(substr($p,$i,1)); my $m=$mask[$i]; my $nb=$b & $m; my $eb = $nb | (~$m & 0xFF); $start .= chr($nb); $end .= chr($eb); }
    return ($start,$end);
}

sub range_to_cidrs {
    my ($start_packed,$end_packed)=@_; my $len = length $start_packed; my $maxbits = $len*8;
    my $start_bi = packed_to_bigint($start_packed); my $end_bi = packed_to_bigint($end_packed);
    my @cidrs;
    while ($start_bi <= $end_bi) {
        my $max_pref = 0;
        for (my $pref=0;$pref<=$maxbits;$pref++){
            my $block = Math::BigInt->new(2)->bpow($maxbits-$pref);
            my $mod = $start_bi->copy()->bmod($block);
            last if $mod != 0; $max_pref = $pref;
        }
        while (1) {
            my $block = Math::BigInt->new(2)->bpow($maxbits-$max_pref);
            my $block_end = $start_bi->copy()->badd($block)->bdec();
            last if $block_end <= $end_bi; $max_pref++;
        }
        my $packed = bigint_to_packed($start_bi,$len);
        my $ip_text = inet_ntop($len==4?AF_INET:AF_INET6,$packed);
        push @cidrs, "$ip_text/$max_pref";
        my $advance = Math::BigInt->new(2)->bpow($maxbits-$max_pref);
        $start_bi = $start_bi->copy()->badd($advance);
    }
    return @cidrs;
}

# parse lines: strip comments starting with # or ;
my @entries;
for my $line (@lines) {
    $line =~ s/^\s+|\s+$//g;
    next if $line =~ /^\s*[#;]/;
    $line =~ s/\s*[#;].*$//;
    $line =~ s/^\s+|\s+$//g;
    next if $line eq '';
    push @entries,$line;
}

# get ranges
my @ranges;
for my $e (@entries) {
    if ($e =~ m{^([^/]+)/(?=\d+$)(\d+)$}) { # naive
        my ($s,$p) = cidr_to_range($e);
        push @ranges, [$s,$e, $p];
    }
}
# sort by start
@ranges = sort { $a->[0] cmp $b->[0] } @ranges;
# merge contiguous/overlapping ranges
my @merged;
for my $r (@ranges) {
    my ($start,$cidr,$prefix) = @$r;
    my ($s,$e) = cidr_to_range($cidr);
    if (!@merged) { push @merged, [$s,$e]; next }
    my ($ms,$me) = @{ $merged[-1] };
    if ($s le $me) {
        # overlap/adjacent
        $me = $e if $e gt $me;
        $merged[-1] = [$ms,$me];
    } else {
        push @merged, [$s,$e];
    }
}

# convert merged ranges back to minimal CIDRs
for my $m (@merged) {
    my ($s,$e) = @$m;
    my @c = range_to_cidrs($s,$e);
    print "Merged range yields CIDRs:\n";
    print "  $_\n" for @c;
}
