/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2017 - 2020, Luke N Small, lukensmall@gmail.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/*
 * 	   Based upon idea from "Dan Mclaughlin" on misc@
 *
 * 	
 * 	    ftp -o - http://www.openbsd.org/ftp.html | \
 * 	    sed -n \
 * 	     -e 's:</a>$::' \
 * 	         -e 's:  <strong>\([^<]*\)<.*:\1:p' \
 * 	         -e 's:^\(       [hfr].*\):\1:p'
 * 	
 */

/*
 *	indent pkg_ping.c -bap -br -ce -ci4 -cli0 -d0 -di0 -i8 \
 *	-ip -l79 -nbc -ncdb -ndj -ei -nfc1 -nlp -npcs -psl -sc -sob
 *	
 *	cc pkg_ping.c -pipe -o pkg_ping
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct mirror_st {
	char *label;
	char *http;
	long double diff;
};

static int
diff_cmp(const void *a, const void *b)
{
	struct mirror_st *one = *( (struct mirror_st **)a );
	struct mirror_st *two = *( (struct mirror_st **)b );

	if (one->diff < two->diff)
		return -1;
	if (one->diff > two->diff)
		return 1;
	return 0;
}

static int
label_cmp(const void *a, const void *b)
{
	struct mirror_st *one = *( (struct mirror_st **)a );
	struct mirror_st *two = *( (struct mirror_st **)b );
	
	/* list the USA mirrors first */
	int8_t temp = (strstr(one->label, "USA") != NULL);
	if (temp != (strstr(two->label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}

	return strcmp(one->label, two->label);
}

static int
label_rev_cmp(const void *a, const void *b)
{
	struct mirror_st *one = *( (struct mirror_st **)a );
	struct mirror_st *two = *( (struct mirror_st **)b );

	/* list the USA mirrors first */
	int8_t temp = (strstr(one->label, "USA") != NULL);
	if (temp != (strstr(two->label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}

	/* will reverse subsort */
	return strcmp(two->label, one->label);
}

static void
manpage(char a[])
{
	printf("%s\n", a);
	printf("[-6 (only return ipv6 compatible mirrors)]\n");

	printf("[-d (don't cache DNS)]\n");

	printf("[-f (don't write to File even if run as root)]\n");

	printf("[-g (generate source ftp list)]\n");

	printf("[-h (print this Help message and exit)]\n");

	printf("[-O (if your kernel is a snapshot, it will Override it and ");
	printf("search for release kernel mirrors.\n");
	printf("\tif your kernel is a release, it will Override it and ");
	printf("search for snapshot kernel mirrors.)\n");

	printf("[-S (converts http mirrors into Secure https mirrors\n");
	printf("\thttp mirrors still preserve file integrity!)]\n");

	printf("[-s floating-point timeout in Seconds (eg. -s 2.3)]\n");

	printf("[-u (no USA mirrors to comply ");
	printf("with USA encryption export laws)]\n");

	printf("[-v (increase Verbosity. It recognizes up to 4 of these)]\n");
	
	printf("[-V (no Verbose output. No output but error messages)]\n");
}

int
main(int argc, char *argv[])
{
	const char table6[16] = { '0','1','2','3',
				  '4','5','6','7',
				  '8','9','a','b',
				  'c','d','e','f' };
				  
	int8_t f = (getuid() == 0) ? 1 : 0;
	int8_t num, current, secure, u, verbose, generate;
	int8_t override, dns_cache, six;
	long double s0, s, S;
	pid_t ftp_pid, write_pid;
	int kq, i, pos, c, n, array_max, array_length, tag_len;
	int parent_to_write[2], ftp_out[2], block_pipe[2];
	FILE *input;
	struct mirror_st **array;
	struct kevent ke;
	struct timespec tv_start, tv_end, timeout;
	
	/* 20 seconds and 0 nanoseconds */
	struct timespec timeout0 = { 20, 0 };
	char *line;
	
   if (pledge("stdio proc exec flock cpath wpath rpath dns unveil", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	if (unveil("/usr/bin/ftp", "x") == -1)
		err(1, "unveil, line: %d", __LINE__);
	
	if (unveil(argv[0], "x") == -1)
		err(1, "unveil, line: %d", __LINE__);
	

	if (f) {

		if (unveil("/etc/installurl", "cwr") == -1)
			err(1, "unveil, line: %d", __LINE__);

    if (pledge("stdio proc exec flock cpath wpath rpath dns", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	} else if (pledge("stdio proc exec dns", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	
	u = verbose = secure = current = override = six = generate = 0;
	dns_cache = 1;
	s0 = s = 5;

	char *version;
	size_t len = 300;
	version = malloc(len);
	if (version == NULL) err(1, "malloc, line: %d\n", __LINE__);

	/* stores results of "sysctl kern.version" into 'version' */
	const int mib[2] = { CTL_KERN, KERN_VERSION };
	if (sysctl(mib, 2, version, &len, NULL, 0) == -1)
                   err(1, "sysctl, line: %d", __LINE__);
	
	/* Discovers if the kernel is not a release version */
	if (strstr(version, "beta"))
		current = 1;
	else if (strstr(version, "current"))
		current = 1;
		
	free(version);

	while ((c = getopt(argc, argv, "6dfghOSs:uvV")) != -1) {
		switch (c) {
		case '6':
			six = 1;
			break;
		case 'd':
			dns_cache = 0;
			break;
		case 'f':
			if (f == 0)
				break;
			if (pledge("stdio proc exec dns", NULL) == -1)
				err(1, "pledge, line: %d", __LINE__);
			f = 0;
			break;
		case 'g':
			generate = 1;
			break;
		case 'h':
			manpage(argv[0]);
			return 0;
		case 'O':
			override = 1;
			break;
		case 'S':
			secure = 1;
			break;
		case 's':
			if (strlen(optarg) > 20)
				errx(1, "too many characters in -s");
			c = -1;
			i = n = 0;
			while (optarg[++c] != '\0') {
				if (optarg[c] >= '0' && optarg[c] <= '9') {
					n = 1;
					continue;
				}
				if (optarg[c] == '.' && ++i == 1)
					continue;

				if (optarg[c] == '-')
					errx(1, "No negative sign.");
				errx(1, "Bad floating point format.");
			}
			if (n == 0) {
				errx(1, "-s needs a numeric character.");
			}
			
			errno = 0;
			s0 = s = strtold(optarg, NULL);
			if (errno == ERANGE)
				err(1, "strtold");
			if (s > (long double)1000)
				errx(1, "-s should be <= 1000");
			if (s < (long double)0.01)
				errx(1, "-s should be >= 0.01");
			break;
		case 'u':
			u = 1;
			break;
		case 'v':
			if (verbose == -1)
				break;
			if (++verbose > 4)
				verbose = 4;
			break;
		case 'V':
			verbose = -1;
			break;
		default:
			manpage(argv[0]);
			return 1;
		}
	}
	if (optind < argc) {
		manpage(argv[0]);
		errx(1, "non-option ARGV-element: %s", argv[optind]);
	}
	
	if (generate) {
		s0 = s = timeout0.tv_sec / 4;
		verbose = 4;
		secure = 1;
		dns_cache = 0;
		f = 0;
		if (pledge("stdio proc exec dns", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	}


	char **ftp_list;
	ftp_list = calloc(50, sizeof(char*));
	if (ftp_list == NULL) err(1, "calloc");

	ftp_list[0] = malloc(2336);
	if (ftp_list[0] == NULL) err(1, "malloc");



	/* Waterloo, Ontario, Canada : 0.959271846 */

	strlcpy(ftp_list[0], "https://mirror.csclub.uwaterloo.ca/pub/OpenBSD/ftplist", 54 + 1);


	/* Cloudflare (CDN) : 1.132705580 */

	ftp_list[1] = ftp_list[0] + 54 + 1;
	strlcpy(ftp_list[1], "https://cloudflare.cdn.openbsd.org/pub/OpenBSD/ftplist", 54 + 1);


	/* Montreal, QC, Canada : 1.175043871 */

	ftp_list[2] = ftp_list[1] + 54 + 1;
	strlcpy(ftp_list[2], "https://openbsd.mirror.netelligent.ca/pub/OpenBSD/ftplist", 57 + 1);


	/* San Francisco, CA, USA : 1.208147591 */

	ftp_list[3] = ftp_list[2] + 57 + 1;
	strlcpy(ftp_list[3], "https://mirrors.sonic.net/pub/OpenBSD/ftplist", 45 + 1);


	/* Piscataway, NJ, USA : 1.219135920 */

	ftp_list[4] = ftp_list[3] + 45 + 1;
	strlcpy(ftp_list[4], "https://openbsd.mirror.constant.com/pub/OpenBSD/ftplist", 55 + 1);


	/* Arlington Heights, IL, USA : 1.233858448 */

	ftp_list[5] = ftp_list[4] + 55 + 1;
	strlcpy(ftp_list[5], "https://mirrors.gigenet.com/pub/OpenBSD/ftplist", 47 + 1);


	/* New York, NY, USA : 1.347425233 */

	ftp_list[6] = ftp_list[5] + 47 + 1;
	strlcpy(ftp_list[6], "https://ftp4.usa.openbsd.org/pub/OpenBSD/ftplist", 48 + 1);


	/* Costa Rica : 1.375017804 */

	ftp_list[7] = ftp_list[6] + 48 + 1;
	strlcpy(ftp_list[7], "https://mirrors.ucr.ac.cr/pub/OpenBSD/ftplist", 45 + 1);


	/* Boise, ID, USA : 1.442362992 */

	ftp_list[8] = ftp_list[7] + 45 + 1;
	strlcpy(ftp_list[8], "https://mirrors.syringanetworks.net/pub/OpenBSD/ftplist", 55 + 1);


	/* Toronto, ON, Canada : 1.451336561 */

	ftp_list[9] = ftp_list[8] + 55 + 1;
	strlcpy(ftp_list[9], "https://openbsd.cs.toronto.edu/pub/OpenBSD/ftplist", 50 + 1);


	/* Aachen, Germany : 1.473903072 */

	ftp_list[10] = ftp_list[9] + 50 + 1;
	strlcpy(ftp_list[10], "https://ftp.halifax.rwth-aachen.de/pub/OpenBSD/ftplist", 54 + 1);


	/* Copenhagen, Denmark : 1.522610244 */

	ftp_list[11] = ftp_list[10] + 54 + 1;
	strlcpy(ftp_list[11], "https://mirror.one.com/pub/OpenBSD/ftplist", 42 + 1);


	/* Aalborg, Denmark : 1.567646241 */

	ftp_list[12] = ftp_list[11] + 42 + 1;
	strlcpy(ftp_list[12], "https://mirrors.dotsrc.org/pub/OpenBSD/ftplist", 46 + 1);


	/* Kent, United Kingdom : 1.568139389 */

	ftp_list[13] = ftp_list[12] + 46 + 1;
	strlcpy(ftp_list[13], "https://www.mirrorservice.org/pub/OpenBSD/ftplist", 49 + 1);


	/* Linthal, GL, Switzerland : 1.578555452 */

	ftp_list[14] = ftp_list[13] + 49 + 1;
	strlcpy(ftp_list[14], "https://mirror.ungleich.ch/pub/OpenBSD/ftplist", 46 + 1);


	/* Paris, France : 1.630480873 */

	ftp_list[15] = ftp_list[14] + 46 + 1;
	strlcpy(ftp_list[15], "https://ftp.fr.openbsd.org/pub/OpenBSD/ftplist", 46 + 1);


	/* Skovde, Sweden : 1.637351625 */

	ftp_list[16] = ftp_list[15] + 46 + 1;
	strlcpy(ftp_list[16], "https://mirror.linux.pizza/pub/OpenBSD/ftplist", 46 + 1);


	/* Esslingen, Germany : 1.637933437 */

	ftp_list[17] = ftp_list[16] + 46 + 1;
	strlcpy(ftp_list[17], "https://mirror.hs-esslingen.de/pub/OpenBSD/ftplist", 50 + 1);


	/* Utrecht, The Netherlands : 1.654106964 */

	ftp_list[18] = ftp_list[17] + 50 + 1;
	strlcpy(ftp_list[18], "https://ftp.nluug.nl/pub/OpenBSD/ftplist", 40 + 1);


	/* Rochester, NY, USA : 1.665657101 */

	ftp_list[19] = ftp_list[18] + 40 + 1;
	strlcpy(ftp_list[19], "https://ftp.usa.openbsd.org/pub/OpenBSD/ftplist", 47 + 1);


	/* Amsterdam, The Netherlands : 1.683460372 */

	ftp_list[20] = ftp_list[19] + 47 + 1;
	strlcpy(ftp_list[20], "https://mirrors.dalenys.com/pub/OpenBSD/ftplist", 47 + 1);


	/* Oslo, Norway : 1.690296696 */

	ftp_list[21] = ftp_list[20] + 47 + 1;
	strlcpy(ftp_list[21], "https://ftp.eu.openbsd.org/pub/OpenBSD/ftplist", 46 + 1);


	/* Dallas, TX, USA : 1.699432775 */

	ftp_list[22] = ftp_list[21] + 46 + 1;
	strlcpy(ftp_list[22], "https://mirror.esc7.net/pub/OpenBSD/ftplist", 43 + 1);


	/* Bucharest, Romania : 1.783132605 */

	ftp_list[23] = ftp_list[22] + 43 + 1;
	strlcpy(ftp_list[23], "https://mirrors.pidginhost.com/pub/OpenBSD/ftplist", 50 + 1);


	/* Bucharest, Romania : 1.798170779 */

	ftp_list[24] = ftp_list[23] + 50 + 1;
	strlcpy(ftp_list[24], "https://mirrors.nav.ro/pub/OpenBSD/ftplist", 42 + 1);


	/* Oldenburg, Germany : 1.801906095 */

	ftp_list[25] = ftp_list[24] + 42 + 1;
	strlcpy(ftp_list[25], "https://ftp.bytemine.net/pub/OpenBSD/ftplist", 44 + 1);


	/* Estonia : 1.818430245 */

	ftp_list[26] = ftp_list[25] + 44 + 1;
	strlcpy(ftp_list[26], "https://ftp.eenet.ee/pub/OpenBSD/ftplist", 40 + 1);


	/* Frankfurt, Germany : 1.826814980 */

	ftp_list[27] = ftp_list[26] + 40 + 1;
	strlcpy(ftp_list[27], "https://ftp.hostserver.de/pub/OpenBSD/ftplist", 45 + 1);


	/* Taoyuan, Taiwan : 1.841192168 */

	ftp_list[28] = ftp_list[27] + 45 + 1;
	strlcpy(ftp_list[28], "https://ftp.yzu.edu.tw/pub/OpenBSD/ftplist", 42 + 1);


	/* Ede, The Netherlands : 1.845395759 */

	ftp_list[29] = ftp_list[28] + 42 + 1;
	strlcpy(ftp_list[29], "https://ftp.bit.nl/pub/OpenBSD/ftplist", 38 + 1);


	/* Alberta, Canada : 1.872687517 */

	ftp_list[30] = ftp_list[29] + 38 + 1;
	strlcpy(ftp_list[30], "https://ftp.OpenBSD.org/pub/OpenBSD/ftplist", 43 + 1);


	/* Curitiba, Brazil : 1.875845199 */

	ftp_list[31] = ftp_list[30] + 43 + 1;
	strlcpy(ftp_list[31], "https://openbsd.c3sl.ufpr.br/pub/OpenBSD/ftplist", 48 + 1);


	/* Hong Kong : 1.881952969 */

	ftp_list[32] = ftp_list[31] + 48 + 1;
	strlcpy(ftp_list[32], "https://openbsd.hk/pub/OpenBSD/ftplist", 38 + 1);


	/* Hamburg, Germany : 1.947180730 */

	ftp_list[33] = ftp_list[32] + 38 + 1;
	strlcpy(ftp_list[33], "https://artfiles.org/openbsd/ftplist", 36 + 1);


	/* Moscow, Russia : 1.968921364 */

	ftp_list[34] = ftp_list[33] + 36 + 1;
	strlcpy(ftp_list[34], "https://mirror.yandex.ru/pub/OpenBSD/ftplist", 44 + 1);


	/* Anycast within NZ, New Zealand : 2.005941361 */

	ftp_list[35] = ftp_list[34] + 44 + 1;
	strlcpy(ftp_list[35], "https://mirror.fsmg.org.nz/pub/OpenBSD/ftplist", 46 + 1);


	/* London, United Kingdom : 2.018981943 */

	ftp_list[36] = ftp_list[35] + 46 + 1;
	strlcpy(ftp_list[36], "https://mirror.exonetric.net/pub/OpenBSD/ftplist", 48 + 1);


	/* Manchester, United Kingdom : 2.118278016 */

	ftp_list[37] = ftp_list[36] + 48 + 1;
	strlcpy(ftp_list[37], "https://mirror.bytemark.co.uk/pub/OpenBSD/ftplist", 49 + 1);


	/* Rome, Italy : 2.147470750 */

	ftp_list[38] = ftp_list[37] + 49 + 1;
	strlcpy(ftp_list[38], "https://openbsd.mirror.garr.it/pub/OpenBSD/ftplist", 50 + 1);


	/* Heraklion, Greece : 2.174740108 */

	ftp_list[39] = ftp_list[38] + 50 + 1;
	strlcpy(ftp_list[39], "https://ftp.cc.uoc.gr/pub/OpenBSD/ftplist", 41 + 1);


	/* Warsaw, Poland : 2.183179501 */

	ftp_list[40] = ftp_list[39] + 41 + 1;
	strlcpy(ftp_list[40], "https://ftp.icm.edu.pl/pub/OpenBSD/ftplist", 42 + 1);


	/* Berlin, Germany : 2.205932266 */

	ftp_list[41] = ftp_list[40] + 42 + 1;
	strlcpy(ftp_list[41], "https://ftp.spline.de/pub/OpenBSD/ftplist", 41 + 1);


	/* Fastly (CDN) : 2.210630137 */

	ftp_list[42] = ftp_list[41] + 41 + 1;
	strlcpy(ftp_list[42], "https://cdn.openbsd.org/pub/OpenBSD/ftplist", 43 + 1);


	/* Wako-City, Saitama, Japan : 2.222907716 */

	ftp_list[43] = ftp_list[42] + 43 + 1;
	strlcpy(ftp_list[43], "https://ftp.riken.jp/pub/OpenBSD/ftplist", 40 + 1);


	/* Erlangen, Germany : 2.284093436 */

	ftp_list[44] = ftp_list[43] + 40 + 1;
	strlcpy(ftp_list[44], "https://ftp.fau.de/pub/OpenBSD/ftplist", 38 + 1);


	/* Budapest, Hungary : 2.288506200 */

	ftp_list[45] = ftp_list[44] + 38 + 1;
	strlcpy(ftp_list[45], "https://ftp.fsn.hu/pub/OpenBSD/ftplist", 38 + 1);


	/* Indonesia : 2.526528717 */

	ftp_list[46] = ftp_list[45] + 38 + 1;
	strlcpy(ftp_list[46], "https://mirror.labkom.id/pub/OpenBSD/ftplist", 44 + 1);


	/* Vienna, Austria : 2.840226399 */

	ftp_list[47] = ftp_list[46] + 44 + 1;
	strlcpy(ftp_list[47], "https://ftp2.eu.openbsd.org/pub/OpenBSD/ftplist", 47 + 1);


	/* Lisbon, Portugal : 3.219601367 */

	ftp_list[48] = ftp_list[47] + 47 + 1;
	strlcpy(ftp_list[48], "https://ftp.rnl.tecnico.ulisboa.pt/pub/OpenBSD/ftplist", 54 + 1);


	/* Verizon Digital Media (Edgecast) (CDN) : 4.643871000 */

	ftp_list[49] = ftp_list[48] + 54 + 1;
	strlcpy(ftp_list[49], "https://mirror.vdms.com/pub/OpenBSD/ftplist", 43 + 1);


	int index = arc4random_uniform(50);




	if (dns_cache == 0)
		goto jump_dns;

	int dns_cache_socket[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
	    PF_UNSPEC, dns_cache_socket) == -1)
		err(1, "socketpair, line: %d\n", __LINE__);

	pid_t dns_cache_pid = fork();
	if (dns_cache_pid == (pid_t) 0) {
		
		if (pledge("stdio dns", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("dns_cache pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		
		free(ftp_list[0]);
		free(ftp_list);
				
		close(dns_cache_socket[1]);
		char *host, *last;
		
		uint8_t line_max;
		struct addrinfo hints, *res0 = NULL, *res;
		
		i = read(dns_cache_socket[0], &line_max, 1);
		if (i < 1) _exit(1);

		line = malloc(line_max + 1);
		if (line == NULL) {
			printf("%s ", strerror(errno));
			printf("malloc, line: %d\n", __LINE__);
			_exit(1);
		}
		

		loop:


		i = read(dns_cache_socket[0], line, line_max + 1);
		if (i == 0) _exit(0);
		
		if (i > line_max) {
			printf("i > line_max, line: %d\n", __LINE__);
			_exit(1);
		}
		
		if (i == -1) {
			printf("%s ", strerror(errno));
			printf("read error line: %d\n", __LINE__);
			_exit(1);
		}
		line[i] = '\0';

		host = strstr(line, "://");
		if (host == NULL) {
			printf("strstr(%s, \"://\")", line);
			printf(" == NULL line: %d\n", __LINE__);
			_exit(1);
		}
		
		/* null terminator for 'line' in getaddrinfo() */
		/* 'line' will resolve to either "http" or "https" */
		*host = '\0';
			
		host += 3;
			
		last = strstr( host, "/");
		if (last != NULL)
			*last = '\0';
		
		if (verbose >= 2) printf("DNS caching: %s\n", host);


		bzero(&hints, sizeof(hints));
		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		n = getaddrinfo(host, line, &hints, &res0);
		if (n) {
			printf("%s ", gai_strerror(n));
			printf("getaddrinfo() failed\n");
			_exit(2);
		}

		if (verbose < 4 && !six) {
			i = write(dns_cache_socket[0], "0", 1);		
			if (i < 1) _exit(1);
			freeaddrinfo(res0);
			goto loop;
		}
			
		if (verbose == 4 && res0->ai_canonname) {
			if (strcmp(res0->ai_canonname, host))
				printf("canon name: %s\n", res0->ai_canonname);
		}

		struct sockaddr_in *sa4;
		uint32_t sui4;
		
		struct sockaddr_in6 *sa6;
		unsigned char *suc6;
		
		int8_t j, max, h, i_temp, i_max, six_available = 0;
		
		for (res = res0; res; res = res->ai_next) {
			
			if (res->ai_family == AF_INET) {
				if (six) continue;
				sa4 = (struct sockaddr_in*)res->ai_addr;
				sui4 = sa4->sin_addr.s_addr;
				printf("       %d.%d.%d.%d\n",
				     sui4 & 0x000000FF,
				    (sui4 & 0x0000FF00) >>  8,
				    (sui4 & 0x00FF0000) >> 16,
				     sui4               >> 24);
				continue;
			}
			
			six_available = 1;
			if (verbose < 4) break;
			
			printf("       ");
			
			sa6 = (struct sockaddr_in6*)res->ai_addr;
			suc6 = sa6->sin6_addr.s6_addr;
			
			j = max = 0;
			i_max = -1;

			/* load largest gap beginning into i_max */
			for (i = 0; i < 16; i += 2) {
						
				/* suc6[i] == 0 && suc6[i + 1] == 0 */
				if (  *( (uint16_t*)(suc6 + i) )  ) {
					j = 0;
					continue;
				}
				
				if (j == 0) {
					i_temp = i;
					j = h = 1;
					continue;
				}
				
				if (max < ++h) {
					max = h;
					i_max = i_temp;
				}
			}
			
			/* 'i' is even so I can use "i|1" instead of "i+1" */
			for (i = 0; i < 16; i += 2) {
								
				if (i == i_max) {
					if (i == 0) printf("::");
					else printf(":");
					i += 2 * max;
					if (i >= 16) break;
				}
				
				if (suc6[i  ] >> 4) {
					printf("%c%c%c%c",
					    table6[suc6[i  ] >> 4],
					    table6[suc6[i  ] & 15],
					    table6[suc6[i|1] >> 4],
					    table6[suc6[i|1] & 15]);
					    
				} else if (suc6[i  ]) {
					printf("%c%c%c",
					    table6[suc6[i  ]],
					    table6[suc6[i|1] >> 4],
					    table6[suc6[i|1] & 15]);
					    
				} else if (suc6[i|1] >> 4) {
					printf("%c%c",
					    table6[suc6[i|1] >> 4],
					    table6[suc6[i|1] & 15]);
				} else
					printf("%c", table6[suc6[i|1]]);
				
				if (i < 14) printf(":");
			}
			printf("\n");
		}

		if (six_available == 0)
			i = write(dns_cache_socket[0], "0", 1);
		else		
			i = write(dns_cache_socket[0], "1", 1);		
		
		if (i < 1)
			_exit(1);
		
		freeaddrinfo(res0);
		goto loop;
	}
	if (dns_cache_pid == -1)
		err(1, "dns_cache fork, line: %d\n", __LINE__);

	close(dns_cache_socket[0]);
	
	jump_dns:

	if (f == 0)
		goto jump_f;

	if (pledge("stdio proc exec flock cpath wpath rpath", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	if (pipe2(parent_to_write, O_CLOEXEC) == -1)
		err(1, "pipe2, line: %d", __LINE__);

	write_pid = fork();
	if (write_pid == (pid_t) 0) {
		
		char *tag_w, *tag_r;
		FILE *pkg_write, *pkg_read;
		
		if (pledge("stdio flock cpath wpath rpath", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		close(parent_to_write[STDOUT_FILENO]);
		
		if (dns_cache) close(dns_cache_socket[1]);

		free(ftp_list[0]);
		free(ftp_list);
				
		uint8_t w_line_max, r_line_max = 0;
		
		pkg_read = fopen("/etc/installurl", "r");
		
		if (pledge("stdio flock cpath wpath", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}

		if (pkg_read) {
			if (flock(fileno(pkg_read), LOCK_EX) == -1) _exit(1);
			fseek(pkg_read, 0, SEEK_END);
			r_line_max = ftell(pkg_read);
			if (r_line_max == 0)
				goto jump_write;
			tag_r = malloc(r_line_max + 1);
			if (tag_r == NULL) {
				r_line_max = 0;
				goto jump_write;
			}
			fseek(pkg_read, 0, SEEK_SET);
			n = fread(tag_r, 1, r_line_max, pkg_read);
			if (n < r_line_max) {
				free(tag_r);
				r_line_max = 0;
			}
			jump_write:
			flock(fileno(pkg_read), LOCK_UN);
			fclose(pkg_read);
		}
		

		
		pkg_write = fopen("/etc/installurl", "w");
		
		if (pledge("stdio flock", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}

		if (pkg_write == NULL) {
			printf("%s ", strerror(errno));
			printf("/etc/installurl not opened.\n");
			_exit(1);
		}

		if (flock(fileno(pkg_write), LOCK_EX | LOCK_NB) == -1) {
			printf("couldn't obtain write lock\n");
			fclose(pkg_write);
			_exit(1);
		}
		
		if (pledge("stdio", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		
		i = read(parent_to_write[STDIN_FILENO], &w_line_max, 1);
		if (i < 1) goto rewrite;
		
		tag_w = malloc(w_line_max + 1);
		if (tag_w == NULL) {
			printf("%s ", strerror(errno));
			printf("malloc, line: %d\n", __LINE__);
			fclose(pkg_write);
			_exit(1);
		}
		
		i = read(parent_to_write[STDIN_FILENO], tag_w, w_line_max + 1);

		if (i < (int)strlen("http://") || i > w_line_max)
			goto rewrite;

		if (verbose >= 1)
			printf("\n");

		if ((int)fwrite(tag_w, 1, i, pkg_write) < i) {
			fclose(pkg_write);
			printf("write error occurred ");
			printf("line: %d\n", __LINE__);
			_exit(1);
		}
		fclose(pkg_write);
		
		if (verbose >= 0) {
			tag_w[i] = '\0';
			printf("/etc/installurl: %s", tag_w);
		}
		
		_exit(0);
		
		
		rewrite:
		
		if (r_line_max == 0) {
			fclose(pkg_write);
			_exit(1);
		}
		n = fwrite(tag_r, 1, r_line_max, pkg_write);
		if (n < r_line_max)
			printf("fwrite error occurred line: %d\n", __LINE__);
		else
			printf("/etc/installurl re-established.\n");
		
		fclose(pkg_write);
		_exit(1);
		
	}
	if (write_pid == -1)
		err(1, "write fork, line: %d", __LINE__);
		
	close(parent_to_write[STDIN_FILENO]);



	jump_f:
	
	
	
	if (pledge("stdio proc exec", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);


	if (pipe(ftp_out) == -1)
		err(1, "pipe, line: %d", __LINE__);

	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

		if (pledge("stdio exec", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("ftp 1 pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		
		close(ftp_out[STDIN_FILENO]);

		if (dup2(ftp_out[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			printf("%s ", strerror(errno));
			printf("ftp STDOUT dup2, line: %d\n", __LINE__);
			_exit(1);
		}


		if (generate) {
			fprintf(stderr,
			    "https://cdn.openbsd.org/pub/OpenBSD/ftplist\n");
			execl("/usr/bin/ftp", "ftp", "-vmo", "-",
			    "https://cdn.openbsd.org/pub/OpenBSD/ftplist",
			    NULL);
		}
		
		if (verbose >= 2)
			fprintf(stderr, "%s\n", (char*)ftp_list[index]);
			
		if (verbose >= 2) {
			execl("/usr/bin/ftp", "ftp", "-vmo", "-",
			    (char*)ftp_list[index],
			    NULL);
		} else {
			execl("/usr/bin/ftp", "ftp", "-VMo", "-",
			    (char*)ftp_list[index],
			    NULL);
		}

		fprintf(stderr, "%s ", strerror(errno));
		fprintf(stderr, "ftp 1 execl failed, line: %d\n", __LINE__);
		_exit(1);
	}
	if (ftp_pid == -1)
		err(1, "ftp 1 fork, line: %d", __LINE__);

	close(ftp_out[STDOUT_FILENO]);



	free(ftp_list[0]);
	free(ftp_list);	



	if (verbose >= 2) {
		if (current == 1) {
			if (override == 0)
				printf("This is a snapshot.\n\n");
			else {
				printf("This is a snapshot, ");
				printf("but it has been overridden ");
				printf("to show release mirrors!\n\n");
			}
		} else {
			if (override == 0)
				printf("This is a release.\n\n");
			else {
				printf("This is a release, ");
				printf("but it has been overridden ");
				printf("to show snapshot mirrors!\n\n");
			}
		}
	}
	
	if (override == 1)
		current = !current;



	struct utsname *name = malloc(sizeof(struct utsname));
	if (name == NULL) {
		kill(ftp_pid, SIGKILL);
		errno = ENOMEM;
		err(1, "malloc, line: %d", __LINE__);
	}
	
	if (uname(name) == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1, "uname, line: %d", __LINE__);
	}
	
	i = strlen(name->release);
	char *release = malloc(i + 1);
	if (release == NULL) {
		kill(ftp_pid, SIGKILL);
		errno = ENOMEM;
		err(1, "malloc, line: %d", __LINE__);
	}
	strlcpy(release, name->release, i + 1);

	if (current == 0) {
		tag_len = strlen("/") + i + strlen("/") +
		    strlen(name->machine) + strlen("/SHA256");
	} else {
		tag_len = strlen("/snapshots/") +
		    strlen(name->machine) + strlen("/SHA256");
	}

	char *tag = malloc(tag_len + 1);
	if (tag == NULL) {
		kill(ftp_pid, SIGKILL);
		errno = ENOMEM;
		err(1, "malloc, line: %d", __LINE__);
	}

	if (current == 0) {
		n  = strlcpy(tag,           "/", tag_len + 1);
		n += strlcpy(tag + n,   release, tag_len + 1 - n);
		n += strlcpy(tag + n,       "/", tag_len + 1 - n);
	} else
		n  = strlcpy(tag, "/snapshots/", tag_len + 1);

	n +=  strlcpy(tag + n, name->machine, tag_len + 1 - n);
	(void)strlcpy(tag + n,     "/SHA256", tag_len + 1 - n);

	free(name);

	if(generate) {
		free(tag);

		tag_len = strlen("/timestamp");
		
		tag = malloc(tag_len + 1);
		if (tag == NULL) {
			kill(ftp_pid, SIGKILL);
			errno = ENOMEM;
			err(1, "malloc, line: %d", __LINE__);
		}

		strlcpy(tag, "/timestamp", tag_len + 1);
	}

	kq = kqueue();
	if (kq == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1, "kq! line: %d", __LINE__);
	}

	EV_SET(&ke, ftp_out[STDIN_FILENO], EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	i = kevent(kq, &ke, 1, &ke, 1, &timeout0);
	if (i == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1,
		    "kevent, timeout0 may be too large. line: %d", __LINE__);
	}
	if (i == 0) {
		kill(ftp_pid, SIGKILL);
		printf("timed out fetching ftplist.\n");
		printf("restarting...\n");
		goto restart;
	}
	
	input = fdopen(ftp_out[STDIN_FILENO], "r");
	if (input == NULL) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1, "fdopen ftp_out, line: %d", __LINE__);
	}

	/* if the index for line[] exceeds 254, it will error out */
	line = malloc(255);
	if (line == NULL) {
		kill(ftp_pid, SIGKILL);
		errno = ENOMEM;
		err(1, "malloc, line: %d", __LINE__);
	}	

	array_max = 100;
	array = calloc(array_max, sizeof(struct mirror_st *));
	if (array == NULL) {
		kill(ftp_pid, SIGKILL);
		errno = ENOMEM;
		err(1, "calloc, line: %d", __LINE__);
	}

	num = pos = array_length = 0;
	array[0] = malloc(sizeof(struct mirror_st));
	if (array[0] == NULL) {
		kill(ftp_pid, SIGKILL);
		errno = ENOMEM;
		err(1, "malloc, line: %d", __LINE__);
	}


	int pos_max = 0;


	while ((c = getc(input)) != EOF) {
		if (pos >= 254) {
			kill(ftp_pid, SIGKILL);
			line[pos] = '\0';
			printf("line: %s\n", line);
			errx(1, "pos got too big! line: %d", __LINE__);
		}
		if (num == 0) {

			if (c != ' ') {
				line[pos++] = c;
				continue;
			}
			
			if (secure) pos += 2;
				else ++pos;
			
			if (pos_max < pos)
				pos_max = pos;

			array[array_length]->http = malloc(pos);
			    
			if (array[array_length]->http == NULL) {
				kill(ftp_pid, SIGKILL);
				errno = ENOMEM;
				err(1, "malloc, line: %d", __LINE__);
			}
			
			if (secure) {
				strlcpy(array[array_length]->http + 1,
				    line, pos - 1);
				memcpy(array[array_length]->http,
				    "https", 5);
			} else
				strlcpy(array[array_length]->http, line, pos);

			pos = 0;
			num = 1;
		} else {
			if (pos == 0) {
				if (c == ' ')
					continue;
			}
				
			if (c != '\n') {
				line[pos++] = c;
				continue;
			}
			
			
			line[pos++] = '\0';
			if (u) {
				if (strstr(line, "USA")) {
					free(array[array_length]->http);
					num = pos = 0;
					continue;
				}
			}
			
			if (secure) {
				if (strstr(line, "Ishikawa")) {
					free(array[array_length]->http);
					num = pos = 0;
					continue;
				}
			}
			array[array_length]->label = malloc(pos);
			if (array[array_length]->label == NULL) {
				kill(ftp_pid, SIGKILL);
				errno = ENOMEM;
				err(1, "malloc, line: %d", __LINE__);
			}
			strlcpy(array[array_length]->label, line, pos);


			if (++array_length >= array_max) {
				array_max += 20;
				array = reallocarray(array, array_max,
				    sizeof(struct mirror_st *));

				if (array == NULL) {
					kill(ftp_pid, SIGKILL);
					errno = ENOMEM;
					err(1,
					    "reallocarray, line: %d", __LINE__);
				}
			}
			array[array_length] = malloc(sizeof(struct mirror_st));

			if (array[array_length] == NULL) {
				kill(ftp_pid, SIGKILL);
				errno = ENOMEM;
				err(1, "malloc, line: %d", __LINE__);
			}

			num = pos = 0;
		}
	}
	
	free(array[array_length]);

	free(line);

	fclose(input);
	close(ftp_out[STDIN_FILENO]);

	waitpid(ftp_pid, &n, 0);

	if (n != 0) {
		printf("ftp encountered an error...\n");
		printf("restarting...\n");
		goto restart;
	}

	
	uint8_t length;
	
	if (dns_cache) {
		length = pos_max;
		i = write(dns_cache_socket[1], &length, 1);
		if (i < 1) err(1, "'length' not sent to dns_cache");
	}
	
	pos_max += tag_len;
	
	if (f) {
		
		if (pos_max > 255)
			err(1, "pos_max is bigger than 255!\n");
		
		length = pos_max;
		i = write(parent_to_write[STDOUT_FILENO], &length, 1);
		if (i < 1) err(1, "'length' not sent to write process");
	}
	
	line = malloc(pos_max);
	if (line == NULL) err(1, "malloc, line: %d", __LINE__);

	if (array_length == 0)
		errx(1, "No file found. Is your network good?");



	array = reallocarray(array, array_length, sizeof(struct mirror_st *));
	if (array == NULL) err(1, "reallocarray, line: %d", __LINE__);
	
	qsort(array, array_length, sizeof(struct mirror_st *), label_cmp);
	
	S = s;

	timeout.tv_sec = (time_t) s;
	timeout.tv_nsec =
	    (long) ((s - (long double) timeout.tv_sec) *
	    (long double)1000000000);

	char **arg_list;
	
	for (c = 0; c < array_length; ++c) {

		pos = strlcpy(line, array[c]->http, pos_max);
		strlcpy(line + pos, tag, pos_max - pos);

		if (verbose >= 2) {
			if (verbose == 4 && dns_cache)
				printf("\n\n\n");
			else if (verbose >= 3)
				printf("\n");
			if (array_length >= 100) {
				printf("\n%3d : %s  :  %s\n", array_length - c,
				    array[c]->label, line);
			} else {
				printf("\n%2d : %s  :  %s\n", array_length - c,
				    array[c]->label, line);
			}
		} else if (verbose >= 0) {
			n = i = array_length - c;
			if (c > 0) {
				if ((i == 9) || (i == 99))
					printf("\b \b");
				do {
					printf("\b");
					n /= 10;
				} while (n > 0);
			}
			printf("%d", i);
			fflush(stdout);
		}



		if (dns_cache) {
		
			if (verbose == (verbose & 1)) {
				printf("*");
				fflush(stdout);
			}

			i = write(dns_cache_socket[1], line, pos);
			if (i < pos) err(1, "response not sent");

			char v;
			
			i = read(dns_cache_socket[1], &v, 1);		

			if (verbose == (verbose & 1)) {
				printf("\b \b");
				fflush(stdout);
			}
			
			if (i < 1) {
				
				if (f) close(parent_to_write[STDOUT_FILENO]);
				
				waitpid(dns_cache_pid, NULL, 0);
				
				if(pledge("stdio exec", NULL) == -1)
					err(1, "pledge, line: %d", __LINE__);
				
				if (verbose >= 2) {
					printf("getaddrinfo() failed again.\n");
					printf("restarting...\n");
				} else if (verbose >= 0) {
					n = array_length - c;
					do {
						printf("\b \b");
						n /= 10;
					} while (n > 0);
					fflush(stdout);
				}

				free(line);
				free(tag);
	restart:

				arg_list = calloc(argc + 1, sizeof(char*));
				if (arg_list == NULL) err(1, "calloc");
				for (i = 0; i < argc; ++i)
				{
					n = strlen(argv[i]) + 1;
					arg_list[i] = malloc(n);
					if (arg_list[i] == NULL)
						err(1, "malloc");
					memcpy(arg_list[i], argv[i], n);
				}
				execv(arg_list[0], arg_list);
				err(1, "execv failed, line: %d", __LINE__);
			}
			
			if (six && v == '0') {
				if (verbose >= 2)
					printf("No ipv6 address found.\n");
				array[c]->diff = s + 1;
				continue;
			}
		}


		

		if (pipe(block_pipe) == -1)
			err(1, "pipe, line: %d", __LINE__);

		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {

			if (pledge("stdio exec", NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("ftp 2 pledge, line: %d\n", __LINE__);
				_exit(1);
			}

			close(block_pipe[STDOUT_FILENO]);
			read(block_pipe[STDIN_FILENO], &n, sizeof(int));
			close(block_pipe[STDIN_FILENO]);
			
			if (verbose <= 2) {
				i = open("/dev/null", O_WRONLY);
				if (i != -1)
					dup2(i, STDERR_FILENO);
			}

			if (verbose >= 3 && six) {
				execl("/usr/bin/ftp", "ftp", "-vm6o",
				    "/dev/null", line, NULL);
			} else if (six) {
				execl("/usr/bin/ftp", "ftp", "-VM6o",
				    "/dev/null", line, NULL);
			}

			if (verbose >= 3) {
				execl("/usr/bin/ftp", "ftp", "-vmo",
				    "/dev/null", line, NULL);
			} else {
				execl("/usr/bin/ftp", "ftp", "-VMo",
				    "/dev/null", line, NULL);
			}

			printf("%s ", strerror(errno));
			printf("ftp 2 execl() failed, line: %d\n", __LINE__);
			_exit(1);
		}
		if (ftp_pid == -1)
			err(1, "ftp 2 fork, line: %d", __LINE__);


		close(block_pipe[STDIN_FILENO]);

		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
		    NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(1, "kevent register fail, line: %d", __LINE__);
		}
		clock_gettime(CLOCK_UPTIME, &tv_start);

		close(block_pipe[STDOUT_FILENO]);


		i = kevent(kq, NULL, 0, &ke, 1, &timeout);
		if (i == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(1, "kevent, line: %d", __LINE__);
		}
		
		/* timeout occurred before ftp() exit was received */
		if (i == 0) {
			kill(ftp_pid, SIGKILL);
			
			/* reap event */
			if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1)
				err(1, "kevent, line: %d", __LINE__);
			waitpid(ftp_pid, NULL, 0);
			if (verbose >= 2)
				printf("Timeout\n");
			array[c]->diff = s;
			continue;
		}
		
		waitpid(ftp_pid, &n, 0);
		
		if (n != 0) {
			array[c]->diff = s + 1;
			if (verbose >= 2)
				printf("Download Error\n");
			continue;
		}

		clock_gettime(CLOCK_UPTIME, &tv_end);

		array[c]->diff =
		    (long double)(tv_end.tv_sec - tv_start.tv_sec) +
		    (long double)(tv_end.tv_nsec - tv_start.tv_nsec) /
		    (long double)1000000000;
			
		if (verbose >= 2) {
			if (array[c]->diff >= s) {
				array[c]->diff = s;
				printf("Timeout\n");
			} else
				printf("%.9Lf\n", array[c]->diff);
		} else if (verbose <= 0 && array[c]->diff < S) {
			S = array[c]->diff;
			timeout.tv_sec = (time_t) S;
			timeout.tv_nsec =
			    (long) ((S - (long double) timeout.tv_sec)
			    * (long double)1000000000);
		} else if (array[c]->diff > s)
			array[c]->diff = s;
	}


	if (pledge("stdio", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	free(line);
	free(tag);		
	close(kq);

	/* identical to (verbose == 0 || verbose == 1) */
	if (verbose == (verbose & 1)) {
		printf("\b \b");
		fflush(stdout);
	}
	
	if (dns_cache) {
		close(dns_cache_socket[1]);
		waitpid(dns_cache_pid, NULL, 0);
	}


	qsort(array, array_length, sizeof(struct mirror_st *), diff_cmp);

	if (verbose >= 1) {
		
		int ds = -1, de = -1,   ts = -1, te = -1,   se = -1;
		
		for (c = array_length - 1; c >= 0; --c) {
			if (array[c]->diff < s) {
				se = c;
				break;
			} else if (array[c]->diff == s) {
				if (ts == -1) 
					ts = te = c;
				else
					ts = c;
			} else {
				if (ds == -1) 
					ds = de = c;
				else
					ds = c;
			}
		}
		
			
		if (generate) {
			
			if(se < 0) {
				printf("\n\nno good mirrors\n");
				return 1;
			}
			
	//~ printf("\n\n\t\tchar *ftp_list[%d] = {\n", se + 1);
	//~ for (c = 0; c <= se; ++c) {
		//~ printf("\n\t\t/* %s ", array[c]->label);
		//~ printf("%.9Lf */\n", array[c]->diff);
		//~ printf("\t\t\"%s/ftplist\"", array[c]->http);
		
		//~ if (c < se) printf(",\n");
		//~ else printf("\n");
	//~ }
	//~ printf("\t\t};\n");
	//~ printf("\n\n\t\tint index = ");
	//~ printf("arc4random_uniform(%d);\n\n", se + 1);
			
				
				
				
				
				
		
	//~ printf("\n\n\tchar **ftp_list;\n");
	//~ printf("\tftp_list = calloc(%d + 1, sizeof(char*));\n", se + 1);
	//~ printf("\tif (ftp_list == NULL) err(1, \"calloc\");\n\n");
		//~ for (c = 0; c <= se; ++c) {
			//~ printf("\n\n\t/* %s ", array[c]->label);
			//~ printf("%.9Lf */\n\n", array[c]->diff);
			
	//~ printf("\tftp_list[%d] = malloc(%lu + 1);\n",
	    //~ c, strlen(array[c]->http) + strlen("/ftplist"));
	    
	//~ printf("\tif (ftp_list[%d] == NULL) err(1, \"malloc\");\n", c);
	//~ printf("\tstrlcpy(ftp_list[%d], \"%s/ftplist\", %lu + 1);\n",
	    //~ c, array[c]->http,
	    //~ strlen(array[c]->http) + strlen("/ftplist"));
		//~ }
		//~ printf("\n\n\tint index = ");
		//~ printf("arc4random_uniform(%d);\n\n", se + 1);
		
			
			
			++se;
		
			n = 0;
			for (c = 0; c < se; ++c) {
				
		n += strlen(array[c]->http) + strlen("/ftplist") + 1;
	
			}
			
		printf("\n\n\tchar **ftp_list;\n");
		printf("\tftp_list = calloc(%d, sizeof(char*));\n", se);
		printf("\tif (ftp_list == NULL) err(1, \"calloc\");\n\n");
		
		printf("\tftp_list[0] = malloc(%d);\n", n);
		printf("\tif (ftp_list[0] == NULL) err(1, \"malloc\");\n\n");
		
			for (c = 0; c < se; ++c) {
				printf("\n\n\t/* %s :", array[c]->label);
				printf(" %.9Lf */\n\n", array[c]->diff);
		if (c) {
			printf("\tftp_list[%d] = ftp_list[%d] + %lu + 1;\n",
			    c, c - 1,
			    strlen(array[c-1]->http) + strlen("/ftplist"));
		}
		printf("\tstrlcpy(ftp_list[%d], \"%s/ftplist\", %lu + 1);\n",
		    c, array[c]->http,
		    strlen(array[c]->http) + strlen("/ftplist"));
			}
			printf("\n\n\tint index = ");
			printf("arc4random_uniform(%d);\n\n", se);
			
		
			return 0;
		}

		
		if (de > ds) {
			qsort(array + ds, 1 + de - ds, 
			    sizeof(struct mirror_st *), label_rev_cmp);
		}
		
		if (te > ts) {
			qsort(array + ts, 1 + te - ts,
			    sizeof(struct mirror_st *), label_rev_cmp);
		}

		c = array_length - 1;
		
		if (de == c)
			printf("\n\nDOWNLOAD ERROR MIRRORS:\n\n\n");
		else if (te == c)
			printf("\n\nTIMEOUT MIRRORS:\n\n\n");
		else
			printf("\n\nSUCCESSFUL MIRRORS:\n\n\n");
			
		for (; c >= 0; --c) {
			    
			if (array_length >= 100)
				printf("%3d", c + 1);
			else
				printf("%2d", c + 1);
			
			printf(" : %s:\n\techo ", array[c]->label);
			printf("\"%s\" > /etc/installurl", array[c]->http);

			if (c <= se)
				printf(" : %.9Lf\n\n", array[c]->diff);
			else if (c <= te) {
				/* printf(" Timeout"); */
				printf("\n\n");
				if (c == ts && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			} else {
				/* printf(" Download Error"); */
				printf("\n\n");
				if (c == ds && ts != -1)
					printf("\nTIMEOUT MIRRORS:\n\n\n");
				else if (c == ds && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			}
		}
	}

	if (array[0]->diff >= s) {
		
		if (current == 0 && !six) {
			printf("\n\nNo mirrors. It doesn't appear that the ");
			printf("%s release is present yet.\n", release);
		} else
			printf("No successful mirrors found.\n");
			
		if (six)
			printf("Perhaps try losing the -6 option?\n");
		if (override == 0)
			printf("Perhaps try the -O option?\n");
			
		printf("Perhaps try with a larger -s than %.9Lf", s0);

		return 1;
	}
	
	
	if (f) {		
				
		if (dup2(parent_to_write[STDOUT_FILENO], STDOUT_FILENO) == -1)
			err(1, "dup2, line: %d\n", __LINE__);
		
		/* sends the fastest mirror to write process */
		printf("%s\n", array[0]->http);
		
		fflush(stdout);

		waitpid(write_pid, &i, 0);

		return i;
	}

	if (verbose >= 0) {
		printf("As root, type: echo \"%s\" > /etc/installurl\n",
		    array[0]->http);
	}

	return 0;
}
