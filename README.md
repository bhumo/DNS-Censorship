**DNS Censorship Tool Readme**

**Overview**
The DNS Censorship tool is a command-line utility designed to function as a DNS resolver, allowing users to forward DNS queries to upstream servers, log queries, and restrict access to specific websites using a deny list. This tool also supports DNS over HTTPS (DoH) for enhanced security and privacy.

**Usage**
To use the DNS Censorship tool, follow these instructions:

Open a terminal.

Run the following command to start the DNS Censorship tool:


sudo python3 dns_forwarder.py --doh -f deny.list -l queries.log
sudo python3: Execute the Python script with superuser privileges to listen on privileged ports.

dns_forwarder.py: This is the main script of the tool.

--doh: Enable DNS over HTTPS (DoH) for secure and private DNS resolution.

-f deny.list: Specify the location of the "deny.list" file. This file contains a list of domain names or IP addresses to restrict or block.

-l queries.log: Specify the location of the "queries.log" file. The tool will log DNS queries in this file.

Make sure that the "dns_forwarder.py" script and the "deny.list" file are in the correct locations on your system. Ensure that you have Python 3 installed.

Important Note: DNS censorship and filtering may have legal and ethical implications. Make sure to use this tool responsibly and in compliance with applicable laws and regulations.

