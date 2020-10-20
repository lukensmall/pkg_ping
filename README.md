I didn't think about it before, but perhaps some of you may be put off by the source code containing a hard-coded mirror snippet array.
If you don't trust the array, you can run it with the -g flag and it will print out another hard-coded mirror source code section generated from
the cdn.openbsd.org mirror owned by the OpenBSD project. I designed this feature for you to substitute for my generated code section.

It determines and prints the fastest OpenBSD mirror for your version and architecture for the /etc/installurl file and if run 
as root, will write it to disk unless -f is used.

Compiler optimizations for speed is not worth the compile time. Waiting for ftp calls and dns queries will take up the vast majority of the
run-time; everything else happens in the blink of an eye.

pledge() is updated throughout. Because of how unveil() is designed, unveil() limits are created up front and
immediately takes away the possibility to unveil() any further.

It automatically discovers whether you are running a release vs a current or beta snapshot!

It defaults to precaching your dns server by looking up a mirror's ip address(es);
this way, there is no inconsistency caused by ftp timed with inconsistent dns query times.

It restarts for most initial ftp call error cases which can be fixed with a different random number.

pkg_ping uses pledge and unveil for OpenBSD version 6.4 and later. I don't recommend running it altered without pledge() or unveil().
The use of /etc/installurl came about in 6.1 is also required. 
OpenBSD 5.8-6.0 is supported in the "ancient" branch which uses pkg.conf(5) and starting with 5.9 uses pledge().

It uses several commandline options:

-6 causes it to only lookup ipv6 addresses on mirrors.
   Maybe you want to make an ipv6 only box, but want to test it with ipv4 connected first?

-d causes the fork()ed DNS caching process to be skipped.

-f prohibits a fork()ed process from writing the fastest mirror to file even if it has the power to do so as root.

-g generates the massive https list from which to retrieve and parse "ftplist", which you no doubt, noticed when
   you look at the source code. It downloads an 11 byte timestamp which is in all mirrors, whereas not all mirrors
   might have snapshots of your architecture or version. It presets options such as minimum verboseness of -v, 
   -f, and finally: -S because the mirror list needs to be securely downloaded.

-h will print the "help" options.

-O will override and search for snapshot mirrors if it is a release; and will search for release mirrors if it a snapshot.
   Useful when you are running a pre-release snapshot without available release mirrors or...are just curious?

-r will not automatically restart if there is a ftplist download error. It will return a value of 2 instead.
   perhaps if it is constantly restarting because of no internet access, you'd perfer it to be handled in a script loop.

-s will accept floating-point timeout like 1.5 seconds using strtold() and handrolled validation, eg. "-s 1.5", default 5.

-S (“Secure only”) option will convert the http mirrors to https mirrors. Otherwise, http mirrors will be chosen.
   http mirrors are likely faster than all https mirror selections, however they pass over the internet without encryption.
   Integrity is still preserved by not using -S, but it will not provide secrecy...maybe you don't want the internets to know you're downloading hot-babe! LOL!

-u will make it search for only non-USA mirrors for export encryption
   compliance if you are searching from outside of the USA and Canada.

-v will show when it is fetching "ftplist" from one of the many hard coded mirrors, prints out the results 
   sorted in reverse order by time or if it is timed out, or a download error,
   subsorts whether it is a USA mirror, further subsorts alphabetically.
   prints a line for each mirror which you can copy and paste into a root terminal to "install" a mirror.
   
-vv (an additional -v) will also make it print out the information of the mirrors in real time.

-vvv (an additional -v) will also show ftp call output to mirrors; which includes a progress bar.
     The progress bar could be interesting if you are on dial-up. Is that still a thing?

-vvvv (an additional -v) will also show dns lookup output if -d is not used. It will temporarily print a * with less -v's to indicate dns caching.

-V will stop all output except error messages. It overrides all -v instances.
   It's useful I suppose, if run from a script or daemon as root so that it writes the result to file.
   I won't stop you if you run ./pkg_ping -Vf .... Maybe you need to heat your house?

pkg_ping will shorten the timeout period to the download time of the fastest previous mirror throughout ftp timing calls
if no -v or if -V is used, so if you want the fastest single result, don't use -v or you could use -V, but it won't print the result to the screen.

If it is run as root, it will make ftp calls run as user pkg_fetch.

If the parent process spins up dns caching, file writing and is calling ftp, it can run 4 processes at one time, all with very different pledge() sets.

If you are running this from a script, I suggest making a loop and specifying the -r flag.
If your computer doesn't yet have internet access, it will also have this error and will restart until you do have internet access. 
You will likely find it easier to handle an error in a loop than it is to kill a constantly restarting process.
It generates a different random mirror from which to download ftplist everytime it runs.

If it returns 1, something very bad has occurred or the timeout value is too low to find a successful mirror;
something that running it again won't likely solve.

If an error is thrown in the processes that precache dns records and writes the mirror to disk, it will restart.
It will also restart if downloading 'ftplist' becomes unresponsive past a wait time defined in 'timeout0'.
'timeout0' can be extended by defining a larger -s value than what is hard-coded.

cc pkg_ping.c -o pkg_ping

eg. ./pkg_ping -vs1.5 -vvu

eg. ./pkg_ping -vSvs 2
