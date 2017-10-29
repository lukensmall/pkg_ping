# pkg_ping
determines and writes the fastest OpenBSD mirror for your version and architecture into the /etc/installurl file.
compiler optimization for speed is not necessary as the calls using ftp will take up the vast majority of the run-time.
priviledge separation and pledge are used. It assumes that there is a 1000 user, which is the standard when a new user is made.
It will need to be run as root to take advantage of automatically writing the result into /etc/installurl file and only searches
for encrypted "https" mirrors, even though "http" mirrors are faster. This program works on OpenBSD 6.1 and the current 6.2 
version as of this writing.

It uses several commandline options including 3 levels of verbosity -v, -vv, -vvv. It will search for only non-USA mirrors for
export encryption compliance if you are searching from outside of the USA with -u. It will accept floating-point time-out like 1.5
seconds for downloading a small SHA256 file with "-s 1.5" and it will print the options with -h. these options can be mixed and 
matched as well: "pkg_ping -vs2 -vuv"
