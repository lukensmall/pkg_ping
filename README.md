### Major update:
It fork()s a 5th potential process to scrape the download speed from ftp(1), send it back to the parent process and uses that bandwidth and the response speed to average out what mirrors are the best, not based upon the order alone,
but based upon translating it to a linear equation for more equitable rankings so super fast and super responsive mirrors will be weighed stronger!
However you may choose to purely rate by the most responsive or the fastest instead!

responsiveness_ranking^2 + bandwidth_ranking^2 == unified_ranking

New flags: -a, -b, and -r

-a: makes -V or zero -v take it's time and not shorten the time out and evaluate average time. Otherwise for -vv and above, it has no effect.
Average is the default setting otherwise.

-b: rate purely by bandwidth

-r: rate purely by responsiveness like before



### It determines and prints the fastest OpenBSD mirror(s) for your version and architecture for the /etc/installurl file and if run as root, will write the fastest successful one to disk unless -f is used.

Perhaps some of you may be put off by the source code containing a hard-coded mirror snippet array.
If you don't trust the array, you can run it with the -g flag and it will print out another hard-coded
mirror source code section generated from openbsd.org domain mirrors from the OpenBSD project.
I designed this feature for you to substitute my generated code section.

Compiler optimizations for speed is probably not worth the extra second of compile time. Waiting for ftp calls and dns queries will take up the vast majority of the
run-time; everything else happens in the blink of an eye.

pledge() is updated throughout. Because of how unveil() is designed, unveil() limits are created up front and
immediately takes away the possibility to unveil() any further. To run smoothly, this program may need to call itself.
If it is called from another program such as a C program, it will need to be able to call the program passed by the exec family of functions into argv[0]

It automatically discovers whether you are running a release vs a current or beta snapshot!

It defaults to precaching your dns server by looking up a mirror's ip address(es)
so there is no inconsistency caused by determining ftp download speed with inconsistent dns query times.

It restarts for most initial ftp call error cases which can be fixed by selecting a different random mirror.

pkg_ping uses pledge and unveil for OpenBSD version 6.4 and later. I don't recommend running it altered without pledge() or unveil().
The use of /etc/installurl came about in 6.1 is also required to store to disk.
OpenBSD 5.8-6.0 is supported in the "ancient" branch which uses pkg.conf(5) and starting with 5.9 uses pledge().

It uses several commandline options:

-6 causes it to only lookup ipv6 addresses on mirrors.
   Maybe you want to make an ipv6 only box, but want to test it with ipv4 connected first?

-d causes the fork()ed DNS caching process to be skipped.

-D is "Debug" mode. It makes the ftp calls after the initial one short circuit. and sets up a timer.
   I use it along with -d to look at performance. It uses about a third of a second for me.

-f prohibits a fork()ed process from writing the fastest mirror to file even if it has the power to do so as root.

-g generates the large https list from which to retrieve and parse "ftplist", which you no doubt, noticed if
   you looked at the source code. It downloads an 11 byte timestamp which is in all mirrors, whereas not all mirrors
   might have snapshots or desired release of your architecture or version. It presets options such as minimum 
   verboseness of -v, -f, and finally: -S because the mirror list needs to be securely downloaded. 
   This flag will also reset variables set by -O, -p and -n.

-h will print the "help" options.

-l (letter ell) will automatically loop a specified integer number of times if there are repeated potentially correctable errors.
   It will randomly select a different mirror each time it runs.
   It will return a value of 2 when the looping is exhausted. If it isn't specified, a 20x loop will be started.
   when it loops, it will detect if the last argv argument starts with "-l" if it does, it will ignore it to minimize the
   -l arguments. Then, in the instance of the first time, it will append a "-l19" to loop 19 more times.
   You may specify up to "-l 9999" It won't loop unless it needs to do so. 

-O will override and search for snapshot mirrors if it is a release; and will search for release mirrors if it a snapshot.
   Useful when you are running a pre-release snapshot without available release mirrors or...are just curious?

-p searches for previous release package folders! It subtracts .1 from your version and searches for the release.

-n searches for next release package folders! It adds .1 to your version and searches for the release.

If both -n and -p are specified, it will default to the last argument specified.

-s will accept floating-point timeout like 1.5 seconds using strtold() and handrolled validation, eg. "-s 1.5" . Default 5.
   If -g is specified -s defaults to 10.

-S (“Secure only”) option will convert the http mirrors to https mirrors. Otherwise, http mirrors will be chosen.
   http mirrors are likely faster than all https mirror selections, however they pass over the internet without encryption.
   for pkg_add, syspatch, sysupgrade, etc., integrity is still preserved by not using -S, but it will not provide
   secrecy...maybe you don't want the internets to know you're downloading hot-babe! LOL!

-u will make it avoid loading mirrors with "USA" in the label for encryption export compliance
   (if that's still a thing) if you are searching from outside of the USA and Canada.
   I'm not sure if this eliminates all mirrors located in the USA. Mirrors with "(CDN)" label may be from the USA.
   Use your best judgement. If -u is used, usa_cmp() won't be used which will sort USA mirrors followed by CDN mirrors
   then followed by Canada mirrors.

-v will show when it is fetching "ftplist" from one of the many hard coded mirrors, prints out the results 
   sorted in reverse order by time or if it is timed out, or a download error,
   subsorts whether it is a USA mirror, further subsorts alphabetically.
   prints a line for each mirror which you can copy and paste into a root terminal to "install" a mirror.
   
-vv (an additional -v) will also make it print out the information of the mirrors in real time.

-vvv (an additional -v) will also show ftp call output to mirrors; which includes a progress bar.
     The progress bar could be interesting if you are on dial-up. Is that still a thing?

-vvvv (an additional -v) will also show dns lookup output if -d is not used. It will temporarily print a * with less -v's to indicate dns caching.
      Further -v arguments are ignored

-V will stop all output except error messages. It overrides all -v instances.
   It's useful I suppose, if run from a script or daemon as root so that it writes the result to file.
   I won't stop you if you run ./pkg_ping -Vf .... Maybe you need to heat your house?

pkg_ping will shorten the timeout period to the download time of the fastest previous mirror throughout ftp timing calls
if no -v or if -V is used, so if you want the fastest single result, don't use -v or you could use -V, but it won't print the result to the screen.

If it is run as root, it will make ftp calling processes change to the pkg_fetch user and ftp will revert to its environment which only has read access to the /var/empty directory,
and ftp(1) doesn't unveil() so it probably is safer to run as root.

If the parent process spins up dns caching, file writing and is calling ftp, it can be running 4 processes at one time, all with very different pledge sets.

If it returns 1, something very bad has occurred or the timeout value is too low to find a successful mirror;
something that running it again won't likely solve.

If an error is thrown in the processes that precache dns records and writes the mirror to disk, it will restart.
It will also restart if downloading 'ftplist' becomes unresponsive past a wait time defined in 'timeout0'.
timeout0 specifies the maximum time it will wait to download the fresh mirror list: "ftplist"
'timeout0' can be extended by defining a larger -s value than what is hard-coded.

I've observed at least one instance in which the dns caching process stalled for such a long time that
I gave up on it. I make it restart if it takes longer than 50 seconds for a single dns caching attempt.
If the timeout is too short, it could cause many loops which may both exhaust the quantity of -l loops
which may cause a needless failure and may needlessly and repeatedly beat up on the mirrors.


cc pkg_ping.c -o /usr/local/bin/pkg_ping

cc pkg_ping.c -march=native -mtune=native -O3 -flto -pipe -o /usr/local/bin/pkg_ping

Example usages:

pkg_ping -vs1.5 -vvu

/usr/local/bin/pkg_ping -vSvs 2
