It determines and prints the fastest OpenBSD mirror for your version and architecture for the /etc/installurl file. compiler optimization for speed is not necessary as the calls using ftp will take up the vast majority of the run-time. pledge() is used. This program works on OpenBSD versions 6.1 - 6.3 as of this writing.

It uses several commandline options including 2 additional levels of verbosity -v and -vv. It will search for only non-USA mirrors for export encryption compliance if you are searching from outside of the USA with -u. It will accept floating-point timeout like 1.5 seconds using strtod() for downloading a small SHA256 file with "-s 1.5" and it will print the options with -h. these options can be mixed and matched as well.

The -i (insecure) option will also choose http and ftp mirrors, where the ftp mirrors are turned into http mirror listings and duplicates are pruned. between them the http/ftp mirrors are faster than the https mirror selections.

Running as the superuser is prohibited. running the command shown at the end of program execution as root will install the mirror.

$ pkg_ping -vs1.5 -ivu

It will shorten the timeout period to the download time of the fastest mirror throughout execution if no -v are used.

gcc pkg_ping.c -o pkg_ping
