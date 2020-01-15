It uses pledge and unveil for OpenBSD version 6.4 and later.

It determines and prints the fastest OpenBSD mirror for your version and architecture for the /etc/installurl file and if run 
as root, will write it to disk unless the -f flag is used.
Compiler optimization for speed is not necessary as the calls using ftp will take up the vast majority of the run-time. 
pledge() is updated throughout, while because of how unveil() is designed, creates all of the unveil() limits up front and
immediately takes away the possibility to unveil() any further.

It automatically discovers whether you are running a release vs a current or beta snapshot!

It will precache your dns server by looking up the mirror's ip addresses.
This way, there is no inconsistency between runs after your dns cache is updated.

I did some reworking, including restarting for most cases.
 
This program should work on OpenBSD versions 6.4+ (Up to 6.6 as of this writing) and won't compile for earlier versions.

It uses several commandline options:

-6 causes it to only lookup ipv6 addresses on mirrors.

-d causes DNS caching to be skipped.

-f prohibits a fork()ed process from writing the fastest mirror to file even if it has the power to do so as root.

-g generates the massive https list from which to retrieve and parse "ftplist", which you no doubt, noticed when you look at the
   source code. It downloads a 11 byte timestamp which is in all mirrors, whereas not all mirrors might have snapshots or your
   architecture or version. It presets various other options such as minimum verboseness and secure mirrors.

-h will print the "help" options.

-O will override and search for release mirrors if it a snapshot. It will search for snapshot mirrors if it is a release.

-s will accept floating-point timeout like 1.5 seconds using strtod() and handrolled validation, eg. "-s 1.5", default 5.

-S (“Secure only”) option will only choose https mirrors. Otherwise, http and ftp mirrors will be chosen. The ftp mirrors
   are turned into http mirror listings and deduplicated. http/ftp mirrors are faster than most https mirror selections, however 
   they pass over the internet without encryption. Integrity is still preserved by not using -S, but it will not provide
   secrecy.

-u will make it search for only non-USA mirrors for export encryption compliance if you are searching from outside of the USA.

-v will show when it is fetching "ftplist" from one of the many mirrors hard coded from running the -g option, print out the
   results sorted in reverse order by time or if timed out, or download error, alphabetically and print a line that you can
   copy and paste into a root terminal to install that mirror.
   
   -vv will also make it print out the information of the mirrors in real time.
   
   -vvv will also show verboseness in the ftp calls to mirrors.
   
   -vvvv will also show dns lookup output.

-V will stop all output except error messages. It overrides all -v instances.

It will shorten the timeout period to the download time of the fastest mirror throughout execution if no -v or if -V is used.

cc pkg_ping.c -o pkg_ping

eg. ./pkg_ping -vs1.5 -vvu

eg. ./pkg_ping -vSvs 2
