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
 *	cc pkg_ping.c -pipe -o pkg_ping
 *
 * 	On big-endian systems like sparc64, you may need:
 * 	cc pkg_ping.c -mlittle-endian -pipe -o pkg_ping
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
	struct mirror_st *one = *((struct mirror_st **) a);
	struct mirror_st *two = *((struct mirror_st **) b);

	if (one->diff < two->diff)
		return -1;
	if (one->diff > two->diff)
		return 1;

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

static int
diff_cmp_g(const void *a, const void *b)
{
	struct mirror_st *one = *((struct mirror_st **) a);
	struct mirror_st *two = *((struct mirror_st **) b);

	if (one->diff < two->diff)
		return -1;
	if (one->diff > two->diff)
		return 1;
	return strcmp(one->http, two->http);
}

static int
label_cmp(const void *a, const void *b)
{
	struct mirror_st *one = *((struct mirror_st **) a);
	struct mirror_st *two = *((struct mirror_st **) b);

	/* list the USA mirrors first */
	int8_t temp = (strstr(one->label, "USA") != NULL);
	if (temp != (strstr(two->label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}
	return strcmp(one->label, two->label);
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
	int8_t to_file = (getuid() == 0) ? 1 : 0;
	int8_t num, current, secure, usa, verbose;
	int8_t generate, override, dns_cache_d, six;
	long double s, S;
	pid_t ftp_pid, write_pid;
	int kq, i, pos, c, n, array_max, array_length, tag_len, pos_max;
	int parent_to_write[2], ftp_out[2], block_pipe[2];
	struct mirror_st **array;
	struct kevent ke;
	struct timespec start, end, timeout;
	char **arg_list;
	char *time = NULL;
	char v;

	/* 4 seconds and 0 nanoseconds to download ftplist */
	struct timespec timeout0 = { 4, 0 };
	char *line;

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
	usa = dns_cache_d = 1;
	s = 5;

	char *version;
	size_t len = 300;
	version = malloc(len);
	if (version == NULL)
		errx(1, "malloc");

	/* stores results of "sysctl kern.version" into 'version' */
	const int mib[2] = { CTL_KERN, KERN_VERSION };
	if (sysctl(mib, 2, version, &len, NULL, 0) == -1)
		err(1, "sysctl, line: %d", __LINE__);

	/* Discovers if the kernel is not a release version */
	if (strstr(version, "current"))
		current = 1;
	else if (strstr(version, "beta"))
		current = 1;

	while ((c = getopt(argc, argv, "6dfghOSs:uvV")) != -1) {
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
		case 'O':
			override = 1;
			break;
		case 'S':
			secure = 1;
			break;
		case 's':
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

			if (n == 0)
				errx(1, "-s needs a numeric character.");

			errno = 0;
			s = strtold(optarg, NULL);
			if (errno)
				err(1, "strtold, line: %d", __LINE__);
			if (s > (long double) 1000)
				errx(1, "-s should be <= 1000");
			if (s < (long double) 0.0078125)
				errx(1, "-s should be >= 0.0078125 (1/128)");
				
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
	
	if (time == NULL) {
		snprintf(version, len, "%Lf", s);
		time = strdup(version);
		if (time == NULL)
			errx(1, "strdup");
	}
	free(version);
	
	i = 0;
	if (strstr(time, ".")) {
		n = strlen(time);
		while (time[--n] != '.') {
			if (time[n] != '0')
				goto jump_time;
			i = n;
		}
		i = n;
	}

jump_time:
	
	if (i > 0) {
		time[i] = '\0';
		time = realloc(time, i + 1);
		if (time == NULL)
			errx(1, "realloc");
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

	int dns_cache_d_socket[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
	    PF_UNSPEC, dns_cache_d_socket) == -1)
		err(1, "socketpair, line: %d\n", __LINE__);

	pid_t dns_cache_d_pid = fork();
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
		
loop:

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

		if (verbose >= 2)
			printf("DNS caching: %s\n", line);
		
		if (verbose >= 0 && verbose <= 2) {
			printf("*");
			fflush(stdout);
		}


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
			goto loop;
		}

		if (verbose < 4 && !six) {
			i = write(dns_cache_d_socket[0], "1", 1);
			if (i < 1)
				_exit(1);
			freeaddrinfo(res0);
			goto loop;
		}
			
		if (verbose == 4 && res0->ai_canonname) {
			if (strcmp(res0->ai_canonname, line))
				printf("canon name: %s\n", res0->ai_canonname);
		}

		struct sockaddr_in *sa4;
		uint32_t sui4;

		struct sockaddr_in6 *sa6;
		unsigned char *suc6;

		int8_t j, max, h, i_temp, i_max;
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
			 *    I didn't steal it from ftp() or anything
			 */
			
			/* res->ai_family == AF_INET6 */

			six_available = '1';
			if (verbose < 4)
				break;

			printf("       ");

			sa6 = (struct sockaddr_in6 *) res->ai_addr;
			suc6 = sa6->sin6_addr.s6_addr;

			j = 0;
			max = 1;
			i_max = -1;

			/* load largest >1 gap beginning into i_max */
			for (i = 0; i < 16; i += 2) {

				/* suc6[i] || suc6[i + 1] */
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

			/* 
			 * 'i' is even so I can use "i|1" instead of "i+1"
			 *              which may be faster
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
				} else
					printf("%c",
					    hex[suc6[i|1]     ]);
				
				if (i < 14)
					printf(":");
			}
			printf("\n");
		}

		i = write(dns_cache_d_socket[0], &six_available, 1);

		if (i < 1)
			_exit(1);

		freeaddrinfo(res0);
		goto loop;
	}
	if (dns_cache_d_pid == -1)
		err(1, "dns_cache_d fork, line: %d\n", __LINE__);

	close(dns_cache_d_socket[0]);

jump_dns:

	if (to_file == 0)
		goto jump_f;

	if (pledge("stdio exec proc cpath wpath id", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	if (pipe2(parent_to_write, O_CLOEXEC) == -1)
		err(1, "pipe2, line: %d", __LINE__);

	write_pid = fork();
	if (write_pid == (pid_t) 0) {

		char *tag_w;
		FILE *pkg_write;

		if (pledge("stdio cpath wpath", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("pledge, line: %d\n", __LINE__);
			_exit(1);
		}
		close(parent_to_write[STDOUT_FILENO]);

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
		
		EV_SET(&ke, parent_to_write[STDIN_FILENO], EVFILT_READ,
		    EV_ADD | EV_ONESHOT, 0, 0, NULL);
		if (kevent(kq, &ke, 1, &ke, 1, NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("write_pid kevent register fail");
			printf(" line: %d\n", __LINE__);
			_exit(1);
		}
		close(kq);
		
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
		
		tag_w = malloc(received + 1 + 1);
		if (tag_w == NULL) {
			printf("malloc\n");
			_exit(1);
		}
			
		i = read(parent_to_write[STDIN_FILENO], tag_w, received);

		if (i < 0) {
			printf("%s ", strerror(errno));
			printf("read error occurred, line: %d\n", __LINE__);
			fclose(pkg_write);
			_exit(1);
		}

		if (i < received) {
			printf("didn't read from buffer, line: %d\n", __LINE__);
			fclose(pkg_write);
			_exit(1);
		}

		if (i <= (int)strlen("http://")) {
			printf("read <= \"http://\", line: %d\n", __LINE__);
			fclose(pkg_write);
			_exit(1);
		}
		
		memcpy(tag_w + received, "\n", 1 + 1);

		i = fwrite(tag_w, 1, received + 1, pkg_write);
		if (i < received + 1) {
			printf("%s ", strerror(errno));
			printf("write error occurred, line: %d\n", __LINE__);
			fclose(pkg_write);
			_exit(1);
		}
		fclose(pkg_write);

		if (verbose >= 0)
			printf("/etc/installurl: %s", tag_w);

		_exit(0);

	}
	if (write_pid == -1)
		err(1, "write fork, line: %d", __LINE__);

	close(parent_to_write[STDIN_FILENO]);


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



	int entry_line, exit_line;
	entry_line = __LINE__;


	char *ftp_list[52] = {

		"ftp.bit.nl","ftp.fau.de","ftp.fsn.hu","openbsd.hk",
		"ftp.eenet.ee","ftp.nluug.nl","ftp.riken.jp","ftp.cc.uoc.gr",
		"ftp.heanet.ie","ftp.spline.de","www.ftp.ne.jp",
		"ftp.icm.edu.pl","mirror.one.com","cdn.openbsd.org",
		"ftp.OpenBSD.org","mirror.vdms.com","mirrors.mit.edu",
		"mirror.labkom.id","mirror.litnet.lt","mirror.yandex.ru",
		"ftp.hostserver.de","mirrors.sonic.net","mirrors.ucr.ac.cr",
		"ftp.eu.openbsd.org","ftp.fr.openbsd.org","mirror.fsmg.org.nz",
		"mirror.ungleich.ch","mirrors.dotsrc.org","openbsd.ipacct.com",
		"ftp.usa.openbsd.org","ftp2.eu.openbsd.org",
		"mirror.leaseweb.com","mirrors.gigenet.com",
		"ftp4.usa.openbsd.org","mirror.aarnet.edu.au",
		"mirror.exonetric.net","mirror.fsrv.services",
		"*artfiles.org/openbsd","mirror.bytemark.co.uk",
		"mirror.planetunix.net","www.mirrorservice.org",
		"mirror.hs-esslingen.de","mirrors.pidginhost.com",
		"openbsd.cs.toronto.edu","cloudflare.cdn.openbsd.org",
		"ftp.halifax.rwth-aachen.de","ftp.rnl.tecnico.ulisboa.pt",
		"mirror.csclub.uwaterloo.ca","mirrors.syringanetworks.net",
		"openbsd.mirror.constant.com","plug-mirror.rcac.purdue.edu",
		"openbsd.mirror.netelligent.ca"
	};

	int index = arc4random_uniform(52);


	exit_line = __LINE__;


	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

	
		
		if (getuid() == 0) {
		/* 
		 * user _pkgfetch: ftp will regain read pledge
		 * just to chroot to /var/empty leaving
		 * read access to an empty directory
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
			printf("malloc");
			_exit(1);
		}
		
		if (generate) {
			
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


		if (dup2(ftp_out[STDOUT_FILENO], STDOUT_FILENO) == -1) {
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
		errx(1, "malloc");
	}
	
	if (uname(name) == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(1, "uname, line: %d", __LINE__);
	}
	
	char *release = strdup(name->release);
	if (release == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "strdup");
	}

	if (current == 0) {
		tag_len = strlen("/") + strlen(release) + strlen("/") +
		    strlen(name->machine) + strlen("/SHA256");
	} else {
		tag_len = strlen("/snapshots/") +
		    strlen(name->machine) + strlen("/SHA256");
	}
	
	n = tag_len + 1;

	char *tag = malloc(n);
	if (tag == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "malloc");
	}

	if (current == 0)
		snprintf(tag, n, "/%s/%s/SHA256", release, name->machine);
	else
		snprintf(tag, n, "/snapshots/%s/SHA256", name->machine);

	free(name);

	if (generate) {
		free(tag);

		tag = strdup("/timestamp");
		if (tag == NULL) {
			kill(ftp_pid, SIGKILL);
			errx(1, "strdup");
		}

		tag_len = strlen(tag);
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
		free(tag);
		free(time);
		free(release);
		goto restart;
	}

	/* if the index for line[] can exceed 254, it will error out */
	line = malloc(255);
	if (line == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "malloc");
	}

	array_max = 100;
	array = calloc(array_max, sizeof(struct mirror_st *));
	if (array == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "calloc");
	}

	i = secure;
	num = pos = array_length = pos_max = 0;
	array[0] = malloc(sizeof(struct mirror_st));
	if (array[0] == NULL) {
		kill(ftp_pid, SIGKILL);
		errx(1, "malloc");
	}

	c = ftp_out[STDIN_FILENO];
	while (read(c, &v, 1) == 1) {
		if (pos >= 253) {
			kill(ftp_pid, SIGKILL);
			line[pos] = '\0';
			printf("line: %s\n", line);
			errx(1, "pos got too big! line: %d", __LINE__);
		}
		
		if (num == 0) {

			if (v != ' ') {
				line[pos++] = v;
				continue;
			}
			line[pos++] = '\0';
			
			if (strncmp(line, "http://", strlen("http://")) != 0) {
				kill(ftp_pid, SIGKILL);
				errx(1, "bad http format, line: %d", __LINE__);
			}				

			if (secure)
				++pos;

			if (pos_max < pos)
				pos_max = pos;

			array[array_length]->http = malloc(pos);

			if (array[array_length]->http == NULL) {
				kill(ftp_pid, SIGKILL);
				errx(1, "malloc");
			}
				
			
			if (secure) {
				
				memcpy(array[array_length]->http, "https", 5);
				
				memcpy(5 + array[array_length]->http,
				    strlen("http") + line, pos - 5);
			} else
				memcpy(array[array_length]->http, line, pos);

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
			free(array[array_length]->http);
			pos = num = 0;
			continue;
		}
		
		/* https connection to Ishikawa mirror reverts to http */
		if (i && strstr(line, "Ishikawa")) {
			free(array[array_length]->http);
			pos = num = i = 0;
			continue;
		}
		
		array[array_length]->label = strdup(line);
		if (array[array_length]->label == NULL) {
			kill(ftp_pid, SIGKILL);
			errx(1, "strdup");
		}


		if (++array_length >= array_max) {
			array_max += 20;
			array = reallocarray(array, array_max,
			    sizeof(struct mirror_st *));

			if (array == NULL) {
				kill(ftp_pid, SIGKILL);
				errx(1, "reallocarray");
			}
		}
		array[array_length] = malloc(sizeof(struct mirror_st));

		if (array[array_length] == NULL) {
			kill(ftp_pid, SIGKILL);
			errx(1, "malloc");
		}
		pos = num = 0;
	}

	free(line);
	free(array[array_length]);

	close(ftp_out[STDIN_FILENO]);

	waitpid(ftp_pid, &n, 0);

	if (n != 0 || array_length == 0)
		errx(1, "There was a download error. Try again.\n");


	if (dns_cache_d) {
		uint8_t length = pos_max;
		i = write(dns_cache_d_socket[1], &length, 1);
		if (i < 1)
			err(1, "'length' not sent to dns_cache_d");
	}
	
	pos_max += tag_len;

	line = malloc(pos_max);
	if (line == NULL)
		errx(1, "malloc");


	array = reallocarray(array, array_length, sizeof(struct mirror_st *));
	if (array == NULL)
		errx(1, "reallocarray");

	/* sort by label, but USA mirrors first */
	qsort(array, array_length, sizeof(struct mirror_st *), label_cmp);

	S = s;

	timeout.tv_sec = (time_t) s;
	timeout.tv_nsec =
	    (long) ((s - (long double) timeout.tv_sec) *
	    (long double) 1000000000);

	for (c = 0; c < array_length; ++c) {

		n = strlcpy(line, array[c]->http, pos_max);
		memcpy(line + n, tag, tag_len + 1);
		
		if (verbose >= 2) {
			if (verbose == 4 && dns_cache_d)
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
		
			char *host = strlen("http://") + secure + line;
			n = strstr(host, "/") - host;

			i = write(dns_cache_d_socket[1], host, n);
			if (i < n)
				err(1, "response not sent");


			i = read(dns_cache_d_socket[1], &v, 1);

			if (verbose >= 0 && verbose <= 2) {
				printf("\b \b");
				fflush(stdout);
			}
			
			if (i < 1) {
				
				free(tag);
				free(line);
				free(time);
				free(release);
				waitpid(dns_cache_d_pid, NULL, 0);
				
				if (pledge("stdio exec", NULL) == -1)
					err(1, "pledge, line: %d", __LINE__);

				if (verbose >= 2)
					printf("dns_cache process failed.\n");
				else if (verbose >= 0) {
					n = array_length - c;
					do {
						printf("\b \b");
						n /= 10;
					} while (n > 0);
					fflush(stdout);
				}

restart:

				if (verbose >= 0)
					printf("restarting...\n");

				arg_list = calloc(argc + 1, sizeof(char *));
				if (arg_list == NULL)
					errx(1, "calloc");
				for (i = 0; i < argc; ++i) {
					arg_list[i] = strdup(argv[i]);
					if (arg_list[i] == NULL)
						errx(1, "strdup");
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
			if (v == 'f') {
				if (verbose >= 2)
					printf("DNS caching failed.\n");
				array[c]->diff = s + 1;
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
			 * just to chroot to /var/empty leaving
			 * read access to an empty directory
			 */
				setuid(57);
			}
			
			if (pledge("stdio exec", NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("ftp 2 pledge, line: %d\n", __LINE__);
				_exit(1);
			}

			close(block_pipe[STDOUT_FILENO]);
			read(block_pipe[STDIN_FILENO], &n, sizeof(int));
			close(block_pipe[STDIN_FILENO]);

			i = open("/dev/null", O_WRONLY);
			if (i != -1) {
				dup2(i, STDOUT_FILENO);

				if (verbose <= 2)
					dup2(i, STDERR_FILENO);
			} else
				printf("can't open /dev/null\n");


			if (six) {
				
				if (verbose >= 3) {
					execl("/usr/bin/ftp", "ftp",
					    "-vim6o-", line, NULL);
				} else {
					execl("/usr/bin/ftp", "ftp",
					    "-ViM6o-", line, NULL);
				}
				
			} else {
				
				if (verbose >= 3) {
					execl("/usr/bin/ftp", "ftp",
					    "-vimo-", line, NULL);
				} else {
					execl("/usr/bin/ftp", "ftp",
					    "-ViMo-", line, NULL);
				}
			}

			fprintf(stderr, "%s ", strerror(errno));
			fprintf(stderr, "ftp 2 execl() failed, ");
			fprintf(stderr, "line: %d\n", __LINE__);
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

		array[c]->diff =
		    (long double) (end.tv_sec  - start.tv_sec) +
		    (long double) (end.tv_nsec - start.tv_nsec) /
		    (long double) 1000000000;

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
			    * (long double) 1000000000);
		} else if (array[c]->diff > s)
			array[c]->diff = s;
	}


	if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	free(line);
	free(tag);
	close(kq);

	/* (verbose == 0 || verbose == 1) */
	if (verbose == (verbose & 1)) {
		printf("\b \b");
		fflush(stdout);
	}
	
	if (dns_cache_d) {
		close(dns_cache_d_socket[1]);
		waitpid(dns_cache_d_pid, NULL, 0);
	}


	/* sort by time, subsort by USA mirror, then reverse subsort label */
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


		if (!generate)
			goto generate_jump;

		if (se < 0)
			goto no_good;

		char *cut;
		int8_t h = strlen("https://");

		/* 
		 * load diff with what will be relative printed http lengths.
		 * the "https://" is included in every length but not printed
		 */
		for (c = 0; c <= se; ++c) {
			cut = strstr(array[c]->http, "/pub/OpenBSD");
			if (cut)
				array[c]->diff = cut - array[c]->http - h;
			else
				array[c]->diff = 1 + strlen(h + array[c]->http);
		}

		/* sort by printed length, subsort http alphabetically */
		qsort(array, se + 1, sizeof(struct mirror_st *), diff_cmp_g);

		printf("\n\n");
		printf("\t/* CODE BEGINS HERE */\n\n\n");
		printf("\tchar *ftp_list[%d] = {\n\n", se + 1);
		printf("\t\t");

		n = 0;
		for (c = 0; c <= se; ++c) {

			cut = strstr(array[c]->http, "/pub/OpenBSD");

			if (cut)
				*cut = '\0';

			/* 
			 * the 3 is the size of the printed: "",
			 * if (c == se) it doesn't print the: ,
			 */
			 
			i = (cut == NULL) + strlen(array[c]->http) + 3
			    - (h + (c == se));

			/* 
			 * more than one mirror will not exceed 80 characters
			 * with 2 tabs of length 8
			 */
			if ((n += i) > 80 - 8 * 2) {
				n = i;
				printf("\n\t\t");
			}

			if (cut == NULL)
				printf("\"*%s\"", h + array[c]->http);
			else
				printf( "\"%s\"", h + array[c]->http);

			if (c < se)
				printf(",");
		}
		printf("\n\t};\n\n");
		printf("\tint index = arc4random_uniform(%d);\n\n\n", se + 1);

		printf("\t/* CODE ENDS HERE */\n\n");
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

			if (array_length >= 100)
				printf("%3d", c + 1);
			else
				printf("%2d", c + 1);

			printf(" : %s:\n\t", array[c]->label);
			printf("echo \"%s\" > /etc/installurl", array[c]->http);
			
			if (c <= se)
				printf(" : %.9Lf\n\n", array[c]->diff);
			else if (c <= te) {
				/* printf(" : Timed Out"); */
				printf("\n\n");
				if (c == ts && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			} else {
				/* printf(" : Download Error"); */
				printf("\n\n");
				if (c == ds && ts != -1)
					printf("\nTIMEOUT MIRRORS:\n\n\n");
				else if (c == ds && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			}
		}
	}

	if (array[0]->diff >= s) {
		
no_good:
		
		printf("No successful mirrors found.\n\n");

		if (current == 0 && override == 0) {
			printf("Perhaps the %s release isn't present yet?\n",
			    release);
			printf("The OpenBSD team tests prereleases ");
			printf("by marking them as release kernels before\n");
			printf("the appropriate release mirrors are ");
			printf("available to hash out any issues.\n");
			printf("This is solved by using the -O option\n\n");
		}
		if (six)
			printf("Try losing the -6 option?\n");

		printf("Perhaps try with a larger -s than %s\n", time);

		return 1;
	}
	
	
	if (to_file) {
		
		n = strlen(array[0]->http);

		i = write(parent_to_write[STDOUT_FILENO],
		    array[0]->http, n);

		if (i < n) {
			printf("not all of mirror sent\n");
			free(time);
			free(release);
			goto restart;
		}
		
		
		waitpid(write_pid, &i, 0);

		if (i != 0) {
			printf("write error.\n");
			free(time);
			free(release);
			goto restart;
		}

		return 0;
	}

	if (verbose >= 0) {
		printf("As root, type: echo \"%s\" > /etc/installurl\n",
		    array[0]->http);
	}
	return 0;
}
