blocklist-with-nftables
====================
Use at your own risk :)

Tested on Debian Bookworm.

## What it does ##
This script automatically downloads blocklists from sources you can define in `blocklist.conf` (simple key=value format).

Then it will create nftables sets. One for IPv4 IPs and one for IPv6 IPs.

It will then create nftables chains which log access attempts from blocked IPs to your syslog and DROP the request.

Next time you run the script it rebuilds the managed nftables tables from the configured lists.

This can be overruled by a white and blacklist you can define in the corresponding whitelist and blacklist files.

Changes
--------
- V1.2.1: move configuration values to external `blocklist.conf` and document external config usage

> Upgrade note: if you are upgrading from an older release that used `config.pl`, migrate your configuration into `blocklist.conf` and place it either next to the script or in `/etc/blocklist/blocklist.conf`.

- V1.2.0: modernize Perl implementation, remove wget/rm shell calls, and use safer nft execution
- V1.1.8: @pingou2712: add option to block nat instead and add files and script for systemd
- V1.1.7: @pingou2712: Update README.md in order to include systemd
- V1.1.6: @pingou2712: add option to block bridge instead
- V1.1.5: @kubax: greatly improved speed. switching to nft -f instead of pushing every
- V1.1.4: switch to nftables
- V1.1.3: @Sheogorath-SI: increase maxelemt to fit more than 65536 entries
- V1.1.2: @kubax: add support for ip6tables (iptables on Arch Linux refuses ipv6 rules)
- V1.1.1: short Help (-h) and Cleanup (-c) available. Binary should now be found automatically.
- V1.1.0: blocklist-with-ipset is now IPV6 compatible (Yayyy :) )
- V1.0.4: Path to white and blacklist is now set automatically
- V1.0.3: Now you can set multiple blocklist sources
- V1.0.2: Added a whitelist and blacklist

<br>
**!!! IMPORTANT !!!!**

When upgrading to V1.1.2+ you might want to manually delete the iptables INPUT BLOCKLIST rule with the target match-set blocklist-v6 src

--

When upgrading from a version lower than 1.1.0 you might have to manually remove duplicated INPUT Rules or run

	./blocklist -c

*Ignore error messages that might show up.*

The script uses the `nft` binary. If the script complains that it can't find it, make sure it is in the environment `PATH`, or set the `NFT` environment variable to the full binary path.

You can find the binary path with `which nft`.

## IP Blocking Strategies

### Blocking IPs at the Input Level (No Flag Required)

The foundational defense mechanism involves blocking incoming malicious IPs right at the network interface level. This straightforward approach ensures immediate protection against external threats trying to infiltrate the system.

### Pre-routing for Host and NAT (Use Flag -n)

To secure both the host and manage NAT configurations, pre-routing rules are applied within the inet table. Utilizing the -n flag enables this dual-purpose protection, preventing malicious IPs from affecting the host and any internal networks operating behind NAT.

### Bridge Pre-routing Protection (Use Flag -b)

Activating the -b flag, our IP blocking system addresses scenarios involving virtual bridges linked to physical interfaces. This setup guarantees comprehensive defense for both the host and virtual machines equipped with real IP addresses, fortifying the network against unauthorized access through these bridges.

## INSTALL ##

1. Make sure you have Perl 5.32+ and nftables installed! If not you can usually install it with your distribution software management tool. E.g. apt for Debian/Ubuntu/Mint.

		apt-get install perl nftables

2. Download the ZIP, or Clone the repository, to a folder on your system.

3. Edit `blocklist.conf` with your favorite text editor and set up your blocklist URLs, log file path, whitelist path, and blacklist path. The script now loads these values from this external config file instead of executing Perl code.

Example `blocklist.conf` (simple `key=value` format):

    # blocklist.conf
    list_url=http://lists.blocklist.de/lists/all.txt
    list_url=https://www.spamhaus.org/drop/drop.txt
    log_file=/var/log/blocklist
    white_list=/etc/blocklist/whitelist
    black_list=/etc/blocklist/blacklist

    # You can repeat `list_url=` for multiple sources and add inline comments with `#`.

4. Schedule the script execution using either a cron job or systemd (see below).

5. Create an logrotate for the logfile. E.g. under /etc/logrotate.d/blocklist

		/var/log/blocklist
		{
			rotate 4
        	daily
			missingok
			notifempty
			delaycompress
			compress
		}

6. If you have an ip you definitly want to block just put it in blacklist. If you have an IP you definitly never want to have blocked put it in whitelist. This two files are just text lists seperated by new lines. So for example

		#blacklist
		2.2.2.2
		3.3.3.3

		#and in whitelist
		4.4.4.4
	 	5.5.5.5

That's it. If you want to manually run the script just cd to the folder where the script is located and run

	./blocklist.pl

## Scheduling Execution
### Using a Cron Job
Create an cronjob. I have and hourly cronjob in /etc/crontab

        0 */1   * * *   root    /usr/bin/perl /path/to/the/script/blocklist.pl > /dev/null

	Or in order to block bridge instead:

        0 */1   * * *   root    /usr/bin/perl /path/to/the/script/blocklist.pl -b > /dev/null

    Or in order to block nat instead:

        0 */1   * * *   root    /usr/bin/perl /path/to/the/script/blocklist.pl -n > /dev/null

### Using systemd

#### Automated Approach

The helper script `create_symlinks.sh` creates or replaces the systemd symlinks:

- `/etc/systemd/system/blocklist.service`
- `/etc/systemd/system/blocklist.timer`

It points them to the files under `/etc/blocklist/systemd/` and prompts before replacing any existing symlink.

If you installed the package via `make install`, make sure the systemd files are available under `/etc/blocklist/systemd/` before running the script. If you are running from the repository directly, you can copy the `systemd/` directory into `/etc/blocklist/` first.

To execute the script, run:

```bash
sudo /etc/blocklist/systemd/create_symlinks.sh
```

If the helper script is not installed in that location, use the repository version instead:

```bash
sudo ./systemd/create_symlinks.sh
```

Then reload systemd and enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable blocklist.timer
sudo systemctl start blocklist.timer
```

#### Manual Method

Create `blocklist.service` and `blocklist.timer` in `/etc/systemd/system/`.

In `blocklist.service`:

```ini
[Unit]
Description=Run blocklist script

[Service]
Type=oneshot
# If installed via `make install` (default):
ExecStart=/sbin/blocklist.pl

# Or if you run from repo/source location:
# ExecStart=/usr/bin/perl /path/to/the/script/blocklist.pl
```

In `blocklist.timer`:

```ini
[Unit]
Description=Timer for blocklist script

[Timer]
# Start 1 minute after boot
OnBootSec=1min
# Execute every hour
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable blocklist.timer
sudo systemctl start blocklist.timer
```

To use the bridge blocking option with systemd, modify `ExecStart` in `blocklist.service` to include `-b`.
To use the nat blocking option with systemd, modify `ExecStart` in `blocklist.service` to include `-n`.

## CLEANUP ##
If you want to remove the managed nftables tables just run

	./blocklist.pl -c

## FORWARD CONNECTION ##
If you want to block bridge instead, add the -b flag:

	./blocklist.pl -b

If you want to block nat instead, add the -n flag:

	./blocklist.pl -n

## Credits ##

virus2500: https://github.com/virus2500

Sheogorath-SI: https://github.com/Sheogorath-SI
