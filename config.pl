# config.pl
#################################################
######  Set options for blocklist.pl here  ######
#################################################

our %CONFIG = (
    list_url   => [
        "http://lists.blocklist.de/lists/all.txt",
        "https://www.spamhaus.org/drop/drop.txt",
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level2.netset",
        "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level3.netset",
    ],
    log_file   => "/var/log/blocklist",
    white_list => "/etc/blocklist/whitelist",
    black_list => "/etc/blocklist/blacklist",
);
