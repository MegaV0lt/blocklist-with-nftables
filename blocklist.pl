#!/usr/bin/env perl
use v5.32;
use strict;
use warnings;

use Fcntl qw(:flock);
use File::Spec;
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use Getopt::Long qw(GetOptions);
use HTTP::Tiny;
use Socket qw(AF_INET AF_INET6 inet_pton);

#################################################################
###### Script to parse blocklists. Block new IPs and       ######
###### remove deleted entries by rebuilding nftables sets. ######
###### Multiple lists possible. IPv4 and IPv6 supported.   ######
#################################################################

## config ##
my @list_url;
my $log_file;
my $white_list;
my $black_list;
my $version = '1.2.1';

## binaries ##
$ENV{PATH} = '/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin';
my $nft = $ENV{NFT} // "nft";

my $table = "blocklist";
my $mode  = "input";

my %stats = (
    added      => 0,
    removed    => 0,
    skipped    => 0,
    added_ipv4 => 0,
    added_ipv6 => 0,
);

open my $self, '<', $0 or die "Couldn't open self: $!";
flock $self, LOCK_EX | LOCK_NB or die "This script is already running\n";

init();

sub init {
    my $help;
    my $cleanup;
    my $bridge;
    my $nat;

    GetOptions(
        'h|help'    => \$help,
        'c|cleanup' => \$cleanup,
        'b|bridge'  => \$bridge,
        'n|nat'     => \$nat,
    ) or usage(1);

    usage(0) if $help;
    die "Options --bridge and --nat are mutually exclusive\n" if $bridge && $nat;

    cleanup_all() if $cleanup;
    exit 0 if $cleanup;

    $mode = "bridge" if $bridge;
    $mode = "nat"    if $nat;

    # determine the config file path
    my ($volume, $directories, $script_name) = File::Spec->splitpath(File::Spec->rel2abs(__FILE__));
    my $default_config = File::Spec->catfile($directories, 'blocklist.conf');
    my $installed_config = '/etc/blocklist/blocklist.conf';
    my $config_file = $ENV{BLOCKLIST_CONFIG} // $default_config;

    unless (-e $config_file) {
        $config_file = $installed_config if -e $installed_config;
    }

    die "Config file not found: $config_file" unless -e $config_file;

    my %c;
    open my $cfg, '<', $config_file or die "Could not open config file $config_file: $!";
    while (my $line = <$cfg>) {
        chomp $line;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';
        next if $line =~ /^\s*#/;
        $line =~ s/\s*#.*$//;    # strip inline comments
        next if $line =~ /^\s*$/;
        if ($line =~ /^([^=\s]+)\s*=\s*(.+)$/) {
            my ($k, $v) = ($1, $2);
            if ($k eq 'list_url') {
                push @{ $c{list_url} }, $v;
            } else {
                $c{$k} = $v;
            }
        }
    }
    close $cfg;

    if (!exists $c{list_url} || !exists $c{log_file} || !exists $c{white_list} || !exists $c{black_list}) {
        die "Invalid config file: missing required configuration keys";
    }

    @list_url   = @{ $c{list_url} };
    $log_file   = $c{log_file};
    $white_list = $c{white_list};
    $black_list = $c{black_list};

    ensure_log_file_exists();
    ensure_list_files_exist();

    # print the version and config for debugging
    print "blocklist-with-nftables version $version\n";
    print "Using the following configuration:\n";
    print "List URLs:\n";
    print "  - $_\n" for @list_url;
    print "Log file: $log_file\n";
    print "Whitelist file: $white_list\n";
    print "Blacklist file: $black_list\n";

    main();
}

sub ensure_log_file_exists {
    return unless defined $log_file && length $log_file;

    my ($volume, $directories, $filename) = File::Spec->splitpath($log_file);
    if ($directories && !-d $directories) {
        make_path($directories) or die "Could not create log directory $directories: $!";
    }

    unless (-e $log_file) {
        open my $fh, '>>', $log_file or die "Could not create log file $log_file: $!";
        close $fh or die "Could not close log file $log_file: $!";
    }
}

sub ensure_list_files_exist {
    for my $path ($white_list, $black_list) {
        die "Missing required file: $path\n" unless defined $path && length $path;
        die "Required file not found: $path\n" unless -e $path;
        die "Required file is not readable: $path\n" unless -r $path;
    }
}

sub usage {
    my ($exit_code) = @_;
    print STDERR <<'EOF';
blocklist-with-nftables

This script downloads and parses text files with IPs and blocks them.
Just run ./blocklist.pl

If you want to clean everything up run:
./blocklist.pl -c

If you want to block IPs on the bridge table run:
./blocklist.pl -b

If you want to block IPs on inet table prerouting to protect NAT run:
./blocklist.pl -n

EOF
    exit $exit_code;
}

sub main {
    logging("Starting blocklist refresh");
    logging("Removing Blocklist Tables");
    cleanup_all();

    logging("Generating Whitelist Array");
    my @whitelist = read_list_file($white_list);

    logging("Generating Blacklist Array");
    my @blacklist = read_list_file($black_list);

    logging("Generating Blocklist Array");
    my @blocklist = download_blocklists(@list_url);

    logging("Adding IPs to Blocklist");
    my ($ipv4, $ipv6) = collect_blocklist_entries(\@blocklist, \@blacklist, \@whitelist);

    logging("Adding Blocklist to ruleset");
    apply_blocklist($ipv4, $ipv6);

    logging("Starting Cleanup");
    logging(
        "We added $stats{added} (IPv4 = $stats{added_ipv4}, IPv6 = $stats{added_ipv6}), "
        . "removed $stats{removed}, skipped $stats{skipped} Rules"
    );

    exit 0;
}

sub read_list_file {
    my ($path) = @_;
    open my $fh, '<', $path or die "Could not open $path: $!";
    my @lines;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';
        $line =~ s/^\s*#.*$//;    # skip full-line comments
        $line =~ s/\s*#.*$//;     # strip inline comments
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';
        push @lines, $line;
    }
    return @lines;
}

sub download_blocklists {
    my (@urls) = @_;
    my $http = HTTP::Tiny->new(timeout => 60);
    my @entries;

    for my $url (@urls) {
        my $response = $http->get($url);
        die "Can not download $url: $response->{status} $response->{reason}\n"
            unless $response->{success};

        for my $line (split /\R/, $response->{content}) {
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            $line =~ s/^\s*#.*$//;    # skip commented lines
            $line =~ s/\s*#.*$//;     # strip inline comments
            $line =~ s/^\s+|\s+$//g;
            next if $line eq '';
            push @entries, $line;
        }
        print "Downloaded blocklist from $url\n";
    }

    return @entries;
}

sub collect_blocklist_entries {
    my ($blocklist, $blacklist, $whitelist) = @_;
    my %whitelist = map { $_ => 1 } @$whitelist;
    my @ipv4;
    my @ipv6;

    for my $line (uniq(@$blacklist, @$blocklist)) {
        next unless defined $line;
        $line =~ s/^\s+|\s+$//g;
        # skip empty or commented
        next if $line eq '';

        if ($whitelist{$line}) {
            $stats{skipped}++;
            next;
        }

        if (is_ipv4($line)) {
            push @ipv4, $line;
            $stats{added}++;
            $stats{added_ipv4}++;
        } elsif (is_ipv6($line)) {
            push @ipv6, $line;
            $stats{added}++;
            $stats{added_ipv6}++;
        } else {
            $stats{skipped}++;
        }
    }

    return (\@ipv4, \@ipv6);
}

sub is_ipv4 {
    my ($value) = @_;
    return 0 unless defined $value && length $value;
    if ($value =~ m{^([^/]+)/(\d+)$}) {
        $value = $1;
    }
    return defined inet_pton(AF_INET, $value);
}

sub is_ipv6 {
    my ($value) = @_;
    return 0 unless defined $value && length $value;
    if ($value =~ m{^([^/]+)/(\d+)$}) {
        $value = $1;
    }
    return defined inet_pton(AF_INET6, $value);
}

sub render_set {
    my ($name, $type, $entries) = @_;
    my $rules = "\tset $name {\n"
        . "\t\ttype $type\n"
        . "\t\tflags interval\n"
        . "\t\telements = {\n";

    $rules .= join "", map { "\t\t\t$_,\n" } @$entries;
    $rules .= "\t\t}\n\t}\n";
    return $rules;
}

sub input_ruleset {
    my ($family, $set_name, $set_type, $field, $entries) = @_;
    return "table $family $table {\n"
        . render_set($set_name, $set_type, $entries)
        . "\tchain input {\n"
        . "\t\ttype filter hook input priority filter; policy accept;\n"
        . "\t\t$field \@$set_name log prefix \"Blocklist Dropped: \" drop\n"
        . "\t}\n"
        . "}\n";
}

sub bridge_or_nat_ruleset {
    my ($family, $prefix, $ipv4, $ipv6) = @_;
    return "table $family $table {\n"
        . render_set("ipv4", "ipv4_addr", $ipv4)
        . render_set("ipv6", "ipv6_addr", $ipv6)
        . "\tchain prerouting {\n"
        . "\t\ttype filter hook prerouting priority filter; policy accept;\n"
        . "\t\tip saddr \@ipv4 log prefix \"$prefix\" drop\n"
        . "\t\tip6 saddr \@ipv6 log prefix \"$prefix\" drop\n"
        . "\t}\n"
        . "}\n";
}

sub apply_blocklist {
    my ($ipv4, $ipv6) = @_;

    if ($mode eq "input") {
        if (@$ipv4) {
            apply_ruleset(input_ruleset("ip", "ipv4", "ipv4_addr", "ip saddr", $ipv4));
            logging("Added Blocklist for IPv4 to ruleset");
        }
        if (@$ipv6) {
            apply_ruleset(input_ruleset("ip6", "ipv6", "ipv6_addr", "ip6 saddr", $ipv6));
            logging("Added Blocklist for IPv6 to ruleset");
        }
        return;
    }

    return unless @$ipv4 || @$ipv6;

    my $family = $mode eq "bridge" ? "bridge" : "inet";
    my $prefix = $mode eq "bridge"
        ? "Blocklist Bridge Dropped: "
        : "Blocklist Prerouting Dropped: ";

    apply_ruleset(bridge_or_nat_ruleset($family, $prefix, $ipv4, $ipv6));
    logging("Added Bridge or NAT Blocklist for IPv4/IPv6 to ruleset");
}

sub apply_ruleset {
    my ($ruleset) = @_;
    my ($fh, $filename) = tempfile();
    print {$fh} $ruleset;
    close $fh or die "Could not close temp ruleset $filename: $!";
    run_nft("-f", $filename);
    unlink $filename or warn "Could not delete temp ruleset $filename: $!";
}

sub cleanup_all {
    for my $family (qw(ip ip6 bridge inet)) {
        next unless nft_table_exists($family);
        run_nft("delete", "table", $family, $table);
    }
}

sub nft_table_exists {
    my ($family) = @_;
    return run_command_quiet($nft, "list", "table", $family, $table);
}

sub run_nft {
    my (@args) = @_;
    system($nft, @args) == 0
        or die "nft @args failed with exit code " . ($? >> 8) . "\n";
}

sub run_command_quiet {
    my (@command) = @_;

    my $pid = fork();
    die "Could not fork for @command: $!" unless defined $pid;

    if ($pid == 0) {
        open STDOUT, '>', File::Spec->devnull
            or die "Could not redirect STDOUT to null device: $!";
        open STDERR, '>', File::Spec->devnull
            or die "Could not redirect STDERR to null device: $!";
        exec @command;
        exit 127;
    }

    waitpid $pid, 0;
    return $? == 0;
}

sub logging {
    my ($message) = @_;
    my ($sec, $min, $hour, $mday, $mon) = localtime();
    my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $date_time = sprintf("%s  %02d %02d:%02d:%02d", $months[$mon], $mday, $hour, $min, $sec);

    open my $fh, '>>', $log_file or die "Can't open logfile $log_file: $!";
    print {$fh} "$date_time $message\n";
    print "$message\n";
}

sub uniq {
    my %seen;
    return grep { !$seen{$_}++ } @_;
}
