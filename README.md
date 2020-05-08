This could be useful on the most recent Zaurus, Sparc (not Sparc64), and Vax releases which dropped back when!

I dug it up from the crypt in case there's a desire to run OpenBSD 5.8 - 6.0, when installurl(5) didn't exist!
It still has potential vulnerabilities and slight inefficiencies I got rid of YEARS AGO.
I basically copied and pasted a file I last wrote in April 2017.

It determines and prints several of the fastest OpenBSD mirrors.
As root, will write them all to /etc/pkg.conf and change to user 1000, which is the standard initial user number.

pkg_ping uses pledge(), but not unveil(), 'cuz it didn't exist yet!
I don't recommend running it at all. If you're running pre-6.1 are you really that worried?

If you need to run version 5.8, when pledge() didn't exist, put at the top: #define pledge(x,y) 0

It doesn't have DNS caching, so for the best results: run it twice.

It uses a few commandline options:

-h will print the "help" options.

-s will accept floating-point timeout like 1.5 seconds using strtod() and handrolled validation, eg. "-s 1.5", default 5.

-u will make it search for only non-USA mirrors for export encryption
   compliance if you are searching from outside of the USA and Canada.

-v increases verbosity. Can specify meaningfully up to 3 times. I forgot what exactly they do.

-n sets a maximum number of mirrors to specify in /etc/pkg.conf

cc pkg_ping.c -o pkg_ping

eg. ./pkg_ping -vs1.5 -vvu

eg. ./pkg_ping -vvs 2 -n10
