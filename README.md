It uses pledge and unveil for OpenBSD version 6.4 and later snapshots.

It determines and prints the fastest OpenBSD mirror for your version and architecture for the /etc/installurl file and if run 
as root, will write it to disk.
Compiler optimization for speed is not necessary as the calls using ftp will take up the vast majority of the run-time. 
pledge() and unveil() is updated throughout. 
This program works on OpenBSD versions 6.4 and 6.5-beta and won't compile for earlier versions.

It uses several commandline options:

-v will make it print out the information of the mirrors in real time. A second one will print out the results sorted in 
reverse order by time and print a line that you can copy and paste into a root terminal to install that mirror.

-u will make it search for only non-USA mirrors for export encryption compliance if you are searching from outside of the USA.

-s will accept floating-point timeout like 1.5 seconds using strtod() and handrolled validation, eg. "-s 1.5", default 5.

-c will check "snapshots" for -current.

-h will print the options with -h. these options can be mixed and matched as well.

-i (insecure) option will also choose http and ftp mirrors, where the ftp mirrors are turned into http mirror listings and
deduplicated. http/ftp mirrors are faster than the https mirror selections, however they pass over the internet insecurely.

It will shorten the timeout period to the download time of the fastest mirror throughout execution if no -v are used.

cc pkg_ping.c -o pkg_ping

eg. "./pkg_ping -vs1.5 -ivu"
