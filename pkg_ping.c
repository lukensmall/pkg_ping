/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2016 - 2020, Luke N Small, lukensmall@gmail.com
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
 * 	   Originally used this idea from "Dan Mclaughlin" on misc@
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
 *	cc pkg_ping.c -o pkg_ping
 * 
 * 	If you want bleeding edge performance, you can try:
 * 	
 *	cc pkg_ping.c -Ofast -o pkg_ping
 * 
 * 	You probably won't see an appreciable performance gain between
 * 	the dns lookups and ftp calls, which are the time killers.
 * 
 *
 * 	On big-endian systems like sparc64, you may need:
 * 	cc pkg_ping.c -mlittle-endian -o pkg_ping
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
	struct mirror_st one = *((struct mirror_st *) a);
	struct mirror_st two = *((struct mirror_st *) b);

	if (one.diff < two.diff)
		return -1;
	if (one.diff > two.diff)
		return 1;
		
	/* 
	 * one and two are undoubtedly timeout or
	 * download error mirrors to get past the
	 *            diff comparisons
	 */

	/* list the USA mirrors first */
	int8_t temp = (strstr(one.label, "USA") != NULL);
	if (temp != (strstr(two.label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}
	/* will reverse subsort */
	return strcmp(two.label, one.label);
}

static int
diff_cmp_g(const void *a, const void *b)
{
	struct mirror_st one = *((struct mirror_st *) a);
	struct mirror_st two = *((struct mirror_st *) b);

	if (one.diff < two.diff)
		return -1;
	if (one.diff > two.diff)
		return 1;
	return strcmp(one.http, two.http);
}

static int
label_cmp(const void *a, const void *b)
{
	char* one_label = ((struct mirror_st *) a)->label;
	char* two_label = ((struct mirror_st *) b)->label;

	/* list the USA mirrors first */
	int8_t temp = (strstr(one_label, "USA") != NULL);
	if (temp != (strstr(two_label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}
	return strcmp(one_label, two_label);
}

static void
manpage(char a[])
{
	printf("%s\n", a);
	printf("[-6 (only return ipv6 compatible mirrors)]\n");

	printf("[-d (don't cache DNS)]\n");

	printf("[-f (don't write to File even if run as root)]\n");

	printf("[-g (Generate source ftp list)]\n");

	printf("[-h (print this Help message and exit)]\n");

	printf("[-O (if your kernel is a snapshot, it will Override it and ");
	printf("search for release kernel mirrors.\n");
	printf("\tif your kernel is a release, it will Override it and ");
	printf("search for snapshot kernel mirrors.)\n");

	printf("[-r (don't automatically Restart and return 2");
	printf(" for a ftplist download error)]\n");

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
	int8_t to_file = (getuid() == 0);
	int8_t num, current, secure, usa, verbose, s_set, restart;
	int8_t generate, override, dns_cache_d, six, h;
	long double s, S;
	pid_t ftp_pid, write_pid, dns_cache_d_pid;
	int kq, i, pos, c, n, array_max, array_length, tag_len;
	int pos_max, std_err, entry_line = 0, exit_line = 0;
	int dns_cache_d_socket[2];
	int write_pipe[2], ftp_out[2], block_pipe[2];
	struct timespec start, end, timeout;
	char *line0, *line, *release, *tag, *time = NULL;
	struct mirror_st *array;
	struct utsname *name;
	struct kevent ke;
	size_t len;
	char v;

	/* 5 seconds and 0 nanoseconds to download ftplist */
	struct timespec timeout0 = { 5, 0 };

	if (pledge("stdio exec proc cpath wpath dns id unveil", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	if (unveil("/usr/bin/ftp", "x") == -1)
		err(1, "unveil, line: %d", __LINE__);

	if (unveil(argv[0], "x") == -1)
		err(1, "unveil, line: %d", __LINE__);


	if (to_file) {

		if (unveil("/etc/installurl", "cw") == -1)
			err(1, "unveil, line: %d", __LINE__);

		if (pledge("stdio exec proc cpath wpath dns id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	} else {
		if (pledge("stdio exec proc dns id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	}

	for(i = 1; i < argc; ++i) {
		if (strlen(argv[i]) >= 50)
			errx(1, "limit arguments to less than length 50");
	}

	verbose = secure = current = override = six = generate = 0;
	usa = dns_cache_d = restart = 1;
	s = 5;

	while ((c = getopt(argc, argv, "6dfghlOSs:uvV")) != -1) {
		switch (c) {
		case '6':
			six = 1;
			break;
		case 'd':
			dns_cache_d = 0;
			break;
		case 'f':
			to_file = 0;
			if (pledge("stdio exec proc dns id", NULL) == -1)
				err(1, "pledge, line: %d", __LINE__);
			break;
		case 'g':
			generate = 1;
			break;
		case 'h':
			manpage(argv[0]);
			return 0;
		case 'l':
			restart = 0;
			break;
		case 'O':
			override = 1;
			break;
		case 'S':
			secure = 1;
			break;
		case 's':
			c = -1;
			i = 0;
			
			if (!strcmp(optarg, "."))
				errx(1, "-s cannot be \".\"");
			
			while (optarg[++c] != '\0') {
				if (optarg[c] >= '0' && optarg[c] <= '9')
					continue;
				if (optarg[c] == '.' && ++i == 1)
					continue;

				if (optarg[c] == '-')
					errx(1, "don't enter a negative sign.");
				errx(1, "Bad floating point format.");
			}

			errno = 0;
			s = strtold(optarg, NULL);
			if (errno)
				err(1, "-s %s is an invalid value", optarg);
				
			free(time);
			time = strdup(optarg);
			if (time == NULL)
				errx(1, "strdup");
				
			break;
		case 'u':
			usa = 0;
			break;
		case 'v':
			if (verbose < 0)
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
	
	if (s > 1000)
		errx(1, "try an -s less than or equal to 1000");
	if (s < 0.015625)
		errx(1, "try an -s greater than or equal to 0.015625 (1/64)");
	
	if (s > (long double)timeout0.tv_sec) {
		timeout0.tv_sec = (time_t) s;
		timeout0.tv_nsec =
		    (long) ((s - (long double) timeout0.tv_sec) *
		    (long double) 1000000000);
	}
	

	if (generate) {
		if (verbose < 1)
			verbose = 1;
		secure = 1;
		dns_cache_d = 1;
		to_file = 0;
		if (pledge("stdio exec proc dns id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	}


	if (dns_cache_d == 0)
		goto jump_dns;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
	    PF_UNSPEC, dns_cache_d_socket) == -1)
		err(1, "socketpair, line: %d\n", __LINE__);

	dns_cache_d_pid = fork();
	if (dns_cache_d_pid == (pid_t) 0) {

			
		if (pledge("stdio dns", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("dns_cache_d pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		
		const char hex[16] = { '0','1','2','3',
				       '4','5','6','7',
				       '8','9','a','b',
				       'c','d','e','f' };
					  
		close(dns_cache_d_socket[1]);

		uint8_t line_max;
		struct addrinfo hints, *res0, *res;

		i = read(dns_cache_d_socket[0], &line_max, 1);
		if (i < 1)
			_exit(1);

		line = malloc(line_max + 1);
		if (line == NULL) {
			printf("malloc\n");
			_exit(1);
		}
		
dns_loop:

		i = read(dns_cache_d_socket[0], line, line_max + 1);
		if (i == 0)
			_exit(0);

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

		if (verbose == 4)
			printf("DNS caching: %s\n", line);


		bzero(&hints, sizeof(struct addrinfo));
		hints.ai_flags = AI_CANONNAME;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		n = getaddrinfo(line, "http", &hints, &res0);
		if (n) {
			// if (verbose >= 2) {
				// printf("%s ", gai_strerror(n));
				// printf("getaddrinfo() failed\n");
			// }
			i = write(dns_cache_d_socket[0], "f", 1);
			if (i < 1)
				_exit(1);
			goto dns_loop;
		}

		if (verbose < 4 && !six) {
			i = write(dns_cache_d_socket[0], "1", 1);
			if (i < 1)
				_exit(1);
			freeaddrinfo(res0);
			goto dns_loop;
		}
			
		if (verbose == 4 && res0->ai_canonname) {
			if (strcmp(res0->ai_canonname, line))
				printf("canon name: %s\n", res0->ai_canonname);
		}

		struct sockaddr_in *sa4;
		uint32_t sui4;

		struct sockaddr_in6 *sa6;
		unsigned char *suc6;

		int8_t max, i_temp, i_max;
		char six_available = '0';

		for (res = res0; res; res = res->ai_next) {

			if (res->ai_family == AF_INET) {
				if (six)
					continue;
				sa4 = (struct sockaddr_in *) res->ai_addr;
				sui4 = sa4->sin_addr.s_addr;
				printf("       %u.%u.%u.%u\n",
				     sui4        & 0xff,
				    (sui4 >>  8) & 0xff,
				    (sui4 >> 16) & 0xff,
				     sui4 >> 24        );
				continue;
			}
			
			/* 
			 * In case anybody wondered, I wrote this section
			 *       from scratch with a little googling
			 *           on ipv6 address formatting
			 */
			
			/* res->ai_family == AF_INET6 */

			six_available = '1';
			if (verbose < 4)
				break;

			printf("       ");

			sa6 = (struct sockaddr_in6 *) res->ai_addr;
			suc6 = sa6->sin6_addr.s6_addr;

			c = max = 0;
			i_max = -1;

			/* load largest >1 gap beginning into i_max */
			for (i = 0; i < 16; i += 2) {

				/* suc6[i] || suc6[i + 1] */
				if (  *( (uint16_t*)(suc6 + i) )  ) {
					c = 0;
					continue;
				}
				
				if (c == 0) {
					i_temp = i;
					c = 1;
					continue;
				}
				
				if (max < ++c) {
					max = c;
					i_max = i_temp;
				}
			}

			/* 
			 *  'i' is even so I can use "i|1" instead of "i+1"
			 * which may be more efficient. I think it's prettier
			 */
			for (i = 0; i < 16; i += 2) {

				if (i == i_max) {
					if (i == 0)
						printf("::");
					else
						printf(":");
					i += 2 * max;
					if (i >= 16)
						break;
				}
				
				if (suc6[i  ] >> 4) {
					printf("%c%c%c%c",
					    hex[suc6[i  ] >> 4],
					    hex[suc6[i  ] & 15],
					    hex[suc6[i|1] >> 4],
					    hex[suc6[i|1] & 15]);
					    
				} else if (suc6[i  ]) {
					printf("%c%c%c",
					    hex[suc6[i  ]     ],
					    hex[suc6[i|1] >> 4],
					    hex[suc6[i|1] & 15]);
					    
				} else if (suc6[i|1] >> 4) {
					printf("%c%c",
					    hex[suc6[i|1] >> 4],
					    hex[suc6[i|1] & 15]);
				} else {
					printf("%c",
					    hex[suc6[i|1]     ]);
				}
				
				if (i < 14)
					printf(":");
			}
			printf("\n");
		}

		i = write(dns_cache_d_socket[0], &six_available, 1);

		if (i < 1)
			_exit(1);

		freeaddrinfo(res0);
		goto dns_loop;
	}
	if (dns_cache_d_pid == -1)
		err(1, "dns_cache_d fork, line: %d\n", __LINE__);

	close(dns_cache_d_socket[0]);

jump_dns:

	if (to_file == 0)
		goto jump_f;

	if (pledge("stdio exec proc cpath wpath id", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	if (pipe2(write_pipe, O_CLOEXEC) == -1)
		err(1, "pipe2, line: %d", __LINE__);

	write_pid = fork();
	if (write_pid == (pid_t) 0) {

		char *file_w;
		FILE *pkg_write;

		if (pledge("stdio cpath wpath", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		close(write_pipe[STDOUT_FILENO]);

		if (dns_cache_d)
			close(dns_cache_d_socket[1]);


		if (verbose >= 1)
			printf("\n");

		kq = kqueue();
		if (kq == -1) {
			printf("%s ", strerror(errno));
			printf("kq! line: %d\n", __LINE__);
			_exit(1);
		}
		
		/* 
		 * It probably seems like overkill to use a kqueue for
		 *   a single file descriptor with no timeout, but I 
		 *    don't have to guess about how much data will
		 *  be sent down the pipe. I can allocate the perfect
		 * amount of buffer space AFTER the pipe receives it.
		 */
		EV_SET(&ke, write_pipe[STDIN_FILENO], EVFILT_READ,
		    EV_ADD | EV_ONESHOT, 0, 0, NULL);
		if (kevent(kq, &ke, 1, &ke, 1, NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("write_pid kevent register fail");
			printf(" line: %d\n", __LINE__);
			_exit(1);
		}
		
		int received = ke.data;

		/* parent exited before sending data */
		if (received == 0) {
			printf("/etc/installurl not written.\n");
			_exit(1);
		}
		if (received > 300) {
			printf("received mirror is too large\n");
			printf("/etc/installurl not written.\n");
			_exit(1);
		}
		
		/* unlink() to prevent possible symlinks by...root? */
		unlink("/etc/installurl");
		pkg_write = fopen("/etc/installurl", "w");

		if (pledge("stdio", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}

		if (pkg_write == NULL) {
			printf("%s ", strerror(errno));
			printf("/etc/installurl not opened.\n");
			_exit(1);
		}
		
		file_w = malloc(received + 1 + 1);
		if (file_w == NULL) {
			printf("malloc\n");
			_exit(1);
		}
			
		i = read(write_pipe[STDIN_FILENO], file_w, received);

		if (i < 0) {
			printf("%s ", strerror(errno));
			printf("read error occurred, line: %d\n", __LINE__);
			_exit(1);
		}

		if (i < received) {
			printf("didn't fully read from pipe, ");
			printf("line: %d\n", __LINE__);
			_exit(1);
		}

		if (i <= (int)(strlen("http://") + secure)) {
			printf("read <= \"http://\", line: %d\n", __LINE__);
			_exit(1);
		}
		
		memcpy(file_w + received, "\n", 1 + 1);

		i = fwrite(file_w, 1, received + 1, pkg_write);
		if (i < received + 1) {
			printf("%s ", strerror(errno));
			printf("write error occurred, line: %d\n", __LINE__);
			_exit(1);
		}

		if (verbose >= 0)
			printf("/etc/installurl: %s", file_w);

		_exit(0);

	}
	if (write_pid == -1)
		err(1, "write fork, line: %d", __LINE__);

	close(write_pipe[STDIN_FILENO]);


jump_f:


	if (getuid() == 0) {
		if (pledge("stdio exec proc id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	} else {
		if (pledge("stdio exec proc", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	}


	if (pipe(ftp_out) == -1)
		err(1, "pipe, line: %d", __LINE__);


	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

	
		
		if (getuid() == 0) {
		/* 
		 * user _pkgfetch: ftp will regain read pledge
		 *    just to chroot to /var/empty leaving
		 *      read access to an empty directory
		 */
			setuid(57);
		}
		
		if (pledge("stdio exec", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("ftp 1 pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		close(ftp_out[STDIN_FILENO]);

		n = 300;
		line = malloc(n);
		if (line == NULL) {
			printf("malloc\n");
			_exit(1);
		}
		
		entry_line = __LINE__;


		char *ftp_list[52] = {

      "ftp.bit.nl","ftp.fau.de","ftp.fsn.hu","openbsd.hk","ftp.eenet.ee",
 "ftp.nluug.nl","ftp.riken.jp","ftp.cc.uoc.gr","ftp.spline.de","www.ftp.ne.jp",
     "ftp.icm.edu.pl","mirror.one.com","cdn.openbsd.org","ftp.OpenBSD.org",
   "mirror.esc7.net","mirror.vdms.com","mirrors.mit.edu","mirror.labkom.id",
 "mirror.litnet.lt","mirror.yandex.ru","ftp.hostserver.de","mirrors.sonic.net",
         "mirrors.ucr.ac.cr","ftp.eu.openbsd.org","ftp.fr.openbsd.org",
        "mirror.fsmg.org.nz","mirror.ungleich.ch","mirrors.dotsrc.org",
       "openbsd.ipacct.com","ftp.usa.openbsd.org","ftp2.eu.openbsd.org",
      "mirror.leaseweb.com","mirrors.gigenet.com","ftp4.usa.openbsd.org",
     "mirror.aarnet.edu.au","mirror.exonetric.net","mirror.fsrv.services",
    "*artfiles.org/openbsd","mirror.bytemark.co.uk","mirror.planetunix.net",
   "www.mirrorservice.org","mirror.hs-esslingen.de","mirrors.pidginhost.com",
             "openbsd.cs.toronto.edu","cloudflare.cdn.openbsd.org",
           "ftp.halifax.rwth-aachen.de","ftp.rnl.tecnico.ulisboa.pt",
          "mirror.csclub.uwaterloo.ca","mirrors.syringanetworks.net",
          "openbsd.mirror.constant.com","plug-mirror.rcac.purdue.edu",
                        "openbsd.mirror.netelligent.ca"
		};

		int index = arc4random_uniform(52);


		exit_line = __LINE__;


		c = ftp_out[STDOUT_FILENO];
		
		if (generate) {
			
			errno = 0;
			i = write(c, &entry_line, sizeof(int));
			if ((ulong)i < sizeof(int)) {
				if (errno)
					printf("%s ", strerror(errno));
				printf("ftp write, line: %d\n", __LINE__);
				_exit(1);
			}
			i = write(c, &exit_line, sizeof(int));
			if ((ulong)i < sizeof(int)) {
				if (errno)
					printf("%s ", strerror(errno));
				printf("ftp write, line: %d\n", __LINE__);
				_exit(1);
			}

				
			i = strlcpy(line,
			    "https://cdn.openbsd.org/pub/OpenBSD/ftplist", n);
			
		
		} else {
			
			if (ftp_list[index][0] == '*') {
				i = snprintf(line, n,
				    "https://%s/ftplist",
				    1 + ftp_list[index]);
			} else {
				i = snprintf(line, n,
				    "https://%s/pub/OpenBSD/ftplist",
				    ftp_list[index]);
			}
		}

		if (i >= n) {
			printf("'line' length >= %d, line: %d\n", n, __LINE__);
			_exit(1);
		}
		
		if (verbose >= 2)
			printf("%s\n", line);


		if (dup2(c, STDOUT_FILENO) == -1) {
			printf("%s ", strerror(errno));
			printf("ftp STDOUT dup2, line: %d\n", __LINE__);
			_exit(1);
		}


		if (verbose >= 2)
			execl("/usr/bin/ftp", "ftp", "-vimo-", line, NULL);
		else
			execl("/usr/bin/ftp", "ftp", "-ViMo-", line, NULL);


		fprintf(stderr, "%s ", strerror(errno));
		fprintf(stderr, "ftp 1 execl failed, line: %d\n", __LINE__);
		_exit(1);
	}
	if (ftp_pid == -1)
		err(1, "ftp 1 fork, line: %d", __LINE__);

	close(ftp_out[STDOUT_FILENO]);


	/* Let's do some work while ftp is downloading ftplist */
	
	if (time == NULL) {
		s_set = 0;
		
		time = malloc(50);
		if (time == NULL) {
			kill(ftp_pid, SIGKILL);
			errx(1, "malloc");
		}
		snprintf(time, 50, "%Lf", s);
	} else
		s_set = 1;
	
	/* eliminate extra zeroes at the end of 'time' */
	if (strchr(time, '.') != NULL) {
		i = 0;
		n = strlen(time);
		while (time[--n] == '0')
			i = n;
			
		if (time[n] == '.')
			i = n;
			
		if (i > 0) {
			time[i] = '\0';
			time = realloc(time, i + 1);
			if (time == NULL) {
				kill(ftp_pid, SIGKILL);
				errx(1, "realloc");
			}
		}
	}

	len = 300;
	line = malloc(len);
	if (line == NULL)
		errx(1, "malloc");

	/* store results of "sysctl kern.version" into 'line' */
	const int mib[2] = { CTL_KERN, KERN_VERSION };
	if (sysctl(mib, 2, line, &len, NULL, 0) == -1)
		err(1, "sysctl, line: %d", __LINE__);

	/* Discovers if the kernel is not a release version */
	if (strstr(line, "current") || strstr(line, "beta"))
		current = 1;
	
	free(line);


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


	name = malloc(sizeof(struct utsname));
	if (name == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "malloc");
	}
	
	if (uname(name) == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1, "uname, line: %d", __LINE__);
	}
	
	release = strdup(name->release);
	if (release == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "strdup");
	}

	if (current == 1) {
		tag_len = strlen("/snapshots/") +
		    strlen(name->machine) + strlen("/SHA256");
	} else {
		tag_len = strlen("/") + strlen(release) + strlen("/") +
		    strlen(name->machine) + strlen("/SHA256");
	}
	
	tag = malloc(tag_len + 1);
	if (tag == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "malloc");
	}

	if (current == 1)
		sprintf(tag, "/snapshots/%s/SHA256", name->machine);
	else
		sprintf(tag, "/%s/%s/SHA256", release, name->machine);

	free(name);
	
	c = ftp_out[STDIN_FILENO];
	
	if (generate) {
		
		/* I can't think of a better way to get these two values */
		i = read(c, &entry_line, sizeof(int));
		if ((ulong)i < sizeof(int)) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(1, "read line: %d", __LINE__);
		}
			
		i = read(c, &exit_line, sizeof(int));
		if ((ulong)i < sizeof(int)) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(1, "read line: %d", __LINE__);
		}

		free(tag);

		tag = strdup("/timestamp");
		if (tag == NULL) {
			kill(ftp_pid, SIGKILL);
			errx(1, "strdup");
		}

		tag_len = strlen(tag);
	}

	/* if the index for line[] can exceed 254, it will error out */
	line = malloc(255);
	if (line == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "malloc");
	}

	array_max = 100;
	array = calloc(array_max, sizeof(struct mirror_st));
	if (array == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "calloc");
	}

	num = pos = pos_max = array_length = 0;

	h = strlen("http://");


	kq = kqueue();
	if (kq == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1, "kq! line: %d", __LINE__);
	}

	/* 
	 * I use kevent here, just so I can restart
	 *   the program again if ftp is sluggish
	 */
	EV_SET(&ke, ftp_out[STDIN_FILENO], EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	i = kevent(kq, &ke, 1, &ke, 1, &timeout0);
	if (i == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		printf("kevent, timeout0 may be too large. ");
		errx(1, "line: %d", __LINE__);
	}
	
	if (i == 0) {
		kill(ftp_pid, SIGKILL);
		goto restart_program;
	}

	i = secure;
	while (read(c, &v, 1) == 1) {
		if (pos >= 253) {
			kill(ftp_pid, SIGKILL);
			line[pos] = '\0';
			printf("'line': %s\n", line);
			errx(1, "pos got too big! line: %d", __LINE__);
		}
		
		if (num == 0) {

			if (v != ' ') {
				line[pos++] = v;
				continue;
			}
			line[pos++] = '\0';
			
			if (strncmp(line, "http://", h)) {
				kill(ftp_pid, SIGKILL);
				errx(1, "bad http format, line: %d", __LINE__);
			}				

			if (secure)
				++pos;

			if (pos_max < pos)
				pos_max = pos;

			array[array_length].http = malloc(pos);
			if (array[array_length].http == NULL) {
				kill(ftp_pid, SIGKILL);
				errx(1, "malloc");
			}
			
			if (secure) {
				
				memcpy(array[array_length].http, "https", 5);
				
				memcpy(5 + array[array_length].http,
				    strlen("http") + line, pos - 5);
			} else
				memcpy(array[array_length].http, line, pos);

			pos = 0;
			num = 1;
			continue;
		}
		
		if (pos == 0 && v == ' ')
			continue;
			
		if (v != '\n') {
			line[pos++] = v;
			continue;
		}
		
		line[pos++] = '\0';
		
		if (usa == 0 && strstr(line, "USA")) {
			free(array[array_length].http);
			pos = num = 0;
			continue;
		}
		
		/* https connection to Ishikawa mirror reverts to http */
		if (i && strstr(line, "Ishikawa")) {
			free(array[array_length].http);
			pos = num = i = 0;
			continue;
		}
		
		array[array_length].label = strdup(line);
		if (array[array_length].label == NULL) {
			kill(ftp_pid, SIGKILL);
			errx(1, "strdup");
		}


		if (++array_length >= array_max) {
			array_max += 20;
			array = reallocarray(array, array_max,
			    sizeof(struct mirror_st));

			if (array == NULL) {
				kill(ftp_pid, SIGKILL);
				errx(1, "reallocarray");
			}
		}

		pos = num = 0;
	}

	free(line);

	close(ftp_out[STDIN_FILENO]);

	waitpid(ftp_pid, &n, 0);

	/* 
	 * This will more likely be caused by no internet access than
	 * from a faulty mirror. If it is run by a script, it will be
	 *  far easier to run a loop based on return value, than to
	 *          kill the constantly restarting program.
	 *                         returns 2
	 */
	if (n != 0 || array_length == 0) {
		if (restart)
			goto restart_program;
		errx(2, "There was an ftplist download error. Try again.\n");
	}

	if (secure == 1)
		h = strlen("https://");
	else
		h = strlen("http://");


	if (dns_cache_d) {
		uint8_t length = pos_max - h;
		i = write(dns_cache_d_socket[1], &length, 1);
		if (i < 1)
			err(1, "'length' not sent to dns_cache_d");
	}
	
	pos_max += tag_len;

	line = malloc(pos_max);
	if (line == NULL)
		errx(1, "malloc");


	array = reallocarray(array, array_length, sizeof(struct mirror_st));
	if (array == NULL)
		errx(1, "reallocarray");

	/* sort by label, but USA mirrors first */
	qsort(array, array_length, sizeof(struct mirror_st), label_cmp);

	if (six == 1) {
		if (verbose >= 3)
			line0 = strdup("-vim6o-");
		else
			line0 = strdup("-ViM6o-");
	} else {
		if (verbose >= 3)
			line0 = strdup("-vimo-");
		else
			line0 = strdup("-ViMo-");
	}

	if (line0 == NULL)
		errx(1, "strdup");

	S = s;

	timeout.tv_sec = (time_t) s;
	timeout.tv_nsec =
	    (long) ((s - (long double) timeout.tv_sec) *
	    (long double) 1000000000);


	std_err = dup(STDERR_FILENO);
	if (std_err == -1)
		err(1, "dup, line: %d\n", __LINE__);
		
	if (fcntl(std_err, F_SETFD, FD_CLOEXEC) == -1)
		err(1, "fcntl, line: %d\n", __LINE__);		
		
	for (c = 0; c < array_length; ++c) {

		n = strlcpy(line, array[c].http, pos_max);
		memcpy(line + n, tag, tag_len + 1);

		if (verbose >= 2) {
			if (verbose == 4 && dns_cache_d)
				printf("\n\n\n");
			else if (verbose >= 3)
				printf("\n");
			if (array_length >= 100) {
				printf("\n%3d : %s  :  %s\n", array_length - c,
				    array[c].label, line);
			} else {
				printf("\n%2d : %s  :  %s\n", array_length - c,
				    array[c].label, line);
			}
		} else if (verbose >= 0) {
			i = array_length - c;
			if (c > 0) {
				if ((i == 9) || (i == 99))
					printf("\b \b");
				n = i;
				do {
					printf("\b");
					n /= 10;
				} while (n > 0);
			}
			printf("%d", i);
			fflush(stdout);
		}



		if (dns_cache_d) {
		
			char *host = h + line;
			
			/* strchr always succeeds. 'tag' starts with '/' */
			n = strchr(host, '/') - host;

			i = write(dns_cache_d_socket[1], host, n);
			if (i < n)
				goto restart_dns_err;

			/* 
			 * (verbose >= 0 && verbose <= 3)
			 * 0-3 need first 2 bits to store.
			 * Other values require extra bits.
			 */
			if ((verbose >> 2) == 0) {
				printf("*");
				fflush(stdout);
			}

			i = read(dns_cache_d_socket[1], &v, 1);

			if ((verbose >> 2) == 0) {
				printf("\b \b");
				fflush(stdout);
			}

			if (i < 1) {
				
restart_dns_err:

				if (verbose >= 2)
					printf("dns_cache process issues\n\n");
				else if (verbose >= 0) {
					n = array_length - c;
					do {
						printf("\b \b");
						n /= 10;
					} while (n > 0);
				}

restart_program:

				if (verbose >= 0)
					printf("restarting...\n");

				execv(argv[0], argv);
				err(1, "execv failed, line: %d", __LINE__);
			}
			
			if (six && v == '0') {
				if (verbose >= 2)
					printf("Ipv6 DNS record not found.\n");
				array[c].diff = s + 2;
				continue;
			}
			if (v == 'f') {
				if (verbose >= 2)
					printf("DNS record not found.\n");
				array[c].diff = s + 3;
				continue;
			}
		}


		

		if (pipe(block_pipe) == -1)
			err(1, "pipe, line: %d", __LINE__);

		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {

			if (getuid() == 0) {
			/* 
			 * user _pkgfetch: ftp will regain read pledge
			 *    just to chroot to /var/empty leaving
			 *      read access to an empty directory
			 */
				setuid(57);
			}
			
			if (pledge("stdio exec", NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("ftp 2 pledge, line: %d\n", __LINE__);
				_exit(1);
			}
			
			close(STDOUT_FILENO);
			if (verbose <= 2)
				close(STDERR_FILENO);

			/*
			 *   this read() is just to assure that the process
			 *        is alive for the parent kevent call.
			 *   It standardizes the timing of the ftp calling
			 *   process, and it is written as an efficient way 
			 * to signal the process to resume without ugly code.
			 */
			close(block_pipe[STDOUT_FILENO]);
			read(block_pipe[STDIN_FILENO], &v, 1);
			close(block_pipe[STDIN_FILENO]);
			

			execl("/usr/bin/ftp", "ftp", line0, line, NULL);

			dprintf(std_err, "%s ", strerror(errno));
			dprintf(std_err, "ftp 2 execl() failed, ");
			dprintf(std_err, "line: %d\n", __LINE__);
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
		
		close(block_pipe[STDOUT_FILENO]);


		clock_gettime(CLOCK_REALTIME, &start);
		i = kevent(kq, NULL, 0, &ke, 1, &timeout);
		clock_gettime(CLOCK_REALTIME, &end);
		
		if (i == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(1, "kevent, line: %d", __LINE__);
		}
		
		/* timeout occurred before ftp() exit was received */
		if (i == 0) {
			kill(ftp_pid, SIGKILL);

			/* reap both event and wait */
			if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1)
				err(1, "kevent, line: %d", __LINE__);
			waitpid(ftp_pid, NULL, 0);
			
			if (verbose >= 2)
				printf("Timeout\n");
			array[c].diff = s;
			continue;
		}
		waitpid(ftp_pid, &n, 0);

		if (n != 0) {
			array[c].diff = s + 1;
			if (verbose >= 2)
				printf("Download Error\n");
			continue;
		}

		array[c].diff =
		    (long double) (end.tv_sec  - start.tv_sec) +
		    (long double) (end.tv_nsec - start.tv_nsec) /
		    (long double) 1000000000;

		if (verbose >= 2) {
			if (array[c].diff >= s) {
				array[c].diff = s;
				printf("Timeout\n");
			} else
				printf("%.9Lf\n", array[c].diff);
		} else if (verbose <= 0 && array[c].diff < S) {
			S = array[c].diff;
			timeout.tv_sec = (time_t) S;
			timeout.tv_nsec =
			    (long) ((S - (long double) timeout.tv_sec)
			    * (long double) 1000000000);
		} else if (array[c].diff > s)
			array[c].diff = s;
	}


	if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);


	/* (verbose == 0 || verbose == 1) */
	if ((verbose >> 1) == 0) {
		printf("\b \b");
		fflush(stdout);
	}
	
	/* sort by time, subsort by USA label, then reverse subsort label */
	qsort(array, array_length, sizeof(struct mirror_st), diff_cmp);

	if (verbose >= 1) {
		
		int ds = -1, de = -1,   ts = -1, te = -1,   se = -1;
		
		for (c = array_length - 1; c >= 0; --c) {
			if (array[c].diff < s) {
				se = c;
				break;
			}
			
			if (array[c].diff == s) {
				if (te == -1)
					ts = te = c;
				else
					ts = c;
			} else {
				if (de == -1)
					ds = de = c;
				else
					ds = c;
			}
		}


		char *cut;

		if (!generate)
			goto generate_jump;

		if (se < 0)
			goto no_good;

		/* 
		 * load diff with what will be printed http lengths
		 *          and process http for printing
		 */
		for (c = 0; c <= se; ++c) {
			cut = strstr(array[c].http += h, "/pub/OpenBSD");
			if (cut == NULL) {
				(array[c].http -= 1)[0] = '*';
				array[c].diff = strlen(array[c].http);
			} else {
				*cut = '\0';
				array[c].diff = cut - array[c].http;
			}
		}

		/* sort by printed length, subsort http alphabetically */
		qsort(array, se + 1, sizeof(struct mirror_st), diff_cmp_g);

		printf("\n\n");
		printf("\t\t/* CODE BEGINS HERE */\n\n\n");
		printf("\t\tchar *ftp_list[%d] = {\n\n", se + 1);

		
		int16_t j, first = 0;
		
		n = 0;
		for (c = 0; c <= se; ++c) {

			/* 
			 *     3 is the size of the printed: "",
			 * if (c == se) it doesn't print the last ,
			 */
			 
			n += i = array[c].diff + 3 - (c == se);

			/* 
			 * mirrors printed on each line
			 * will not exceed 80 characters
			 */
			if (n > 80) {
				
				for (j = (80 - (n - i)) / 2; j > 0; --j)
					printf(" ");
				for (j = first; j < c; ++j)
					printf("\"%s\",", array[j].http);
				printf("\n");
				first = c;
				n = i;
				
			}
		}
		
		for (j = (80 - n) / 2; j > 0; --j)
			printf(" ");
		for (j = first; j < se; ++j)
			printf("\"%s\",", array[j].http);
		printf("\"%s\"\n", array[j].http);
		
		printf("\t\t};\n\n");
		printf("\t\tint index = arc4random_uniform(%d);\n\n\n", se + 1);

		printf("\t\t/* CODE ENDS HERE */\n\n");
		printf("Replace section after line: %d, but ", entry_line);
		printf("before line: %d with the code above.\n\n", exit_line);


		return 0;

generate_jump:

		c = array_length - 1;

		if (de == c)
			printf("\n\nDOWNLOAD ERROR MIRRORS:\n\n\n");
		else if (te == c)
			printf("\n\nTIMEOUT MIRRORS:\n\n\n");
		else
			printf("\n\nSUCCESSFUL MIRRORS:\n\n\n");

		for (; c >= 0; --c) {

			struct mirror_st temp = array[c];
			
			if (array_length >= 100)
				printf("%3d", c + 1);
			else
				printf("%2d", c + 1);

			printf(" : %s\n\t", temp.label);
			
			if (c <= se) {
				printf("echo \"%s\" > /etc/installurl",
				    temp.http);
				printf(" : %.9Lf\n\n", temp.diff);
				continue;
			}
			
			cut = strchr(temp.http += h, '/');
			if (cut)
				*cut = '\0';
			
			printf("%s : ", temp.http);
			
			if (c <= te) {
				printf("Timeout\n\n");
				if (c == ts && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
				continue;
			}
			
			if (temp.diff == s + 1)
				printf("Download Error");
			else if (temp.diff == s + 2)
				printf("IPv6 DNS records not found");
			else
				printf("DNS records not found");
			printf("\n\n");
				
			if (c == ds) {
				if (te != -1)
					printf("\nTIMEOUT MIRRORS:\n\n\n");
				else if (se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			}
		}
	}

	if (array[0].diff >= s) {
		
no_good:
		
		printf("No successful mirrors found.\n\n");

		if (current == 0 && override == 0) {
			printf("Perhaps the %s release isn't present yet?\n",
			    release);
			printf("The OpenBSD team tests prereleases ");
			printf("by marking them as release kernels before\n");
			printf("the appropriate release mirrors are ");
			printf("available to hash out any issues.\n");
			printf("This is solved by using the -O option ");
			printf("to retrieve snapshot mirrors.\n\n");
		}
		if (six)
			printf("Try losing the -6 option?\n\n");

		if (s_set == 0) {
			printf("Perhaps try the -s ");
			printf("option to choose a timeout");
			printf(" larger than the default: -s %s\n", time);
		} else
			printf("Perhaps try with a larger -s than %s\n", time);

		return 1;
	}
	
	
	if (to_file) {
		
		n = strlen(array[0].http);

		i = write(write_pipe[STDOUT_FILENO], array[0].http, n);

		if (i < n) {
			printf("not all of mirror sent to write_pid\n");
			goto restart_program;
		}
		
		waitpid(write_pid, &i, 0);

		if (i != 0) {
			printf("write_pid error.\n");
			goto restart_program;
		}

		return 0;
	}

	if (verbose >= 0) {
		printf("As root, type: echo \"%s\" > /etc/installurl\n",
		    array[0].http);
	}
	return 0;
}
