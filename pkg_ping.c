/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2016 - 2022, Luke N Small, lukensmall@gmail.com
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
 * 	Originally used the following from "Dan Mclaughlin"
 *                  on openbsd-misc mailing list
 *
 *
 * 	    ftp -o - http://www.openbsd.org/ftp.html | \
 * 	    sed -n \
 * 	     -e 's:</a>$::' \
 * 	         -e 's:  <strong>\([^<]*\)<.*:\1:p' \
 * 	         -e 's:^\(       [hfr].*\):\1:p'
 */

/*
 *	indent pkg_ping.c -bap -br -ce -ci4 -cli0 -d0 -di0 -i8 \
 *	-ip -l79 -nbc -ncdb -ndj -ei -nfc1 -nlp -npcs -psl -sc -sob
 *
 *	cc pkg_ping.c -o pkg_ping
 *
 * 	If you want bleeding edge performance, you can try:
 *
 * 	cc pkg_ping.c -march=native -mtune=native -O2 -pipe -o pkg_ping
 *
 * 	You probably won't see an appreciable performance gain between the
 * 	getaddrinfo(3) and ftp(1) calls which fetch data over the network.
 *
 * 	program designed to be viewed with tabs which are 8 characters wide
 */

#include <sys/types.h>

#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
	char *label;
	char *http;
	long double diff;
} MIRROR;

extern char *malloc_options;

/* strlen("http://") == 7 */
int8_t h = 7;
int array_length = 0;
MIRROR *array = NULL;

/* .1 second for an ftp SIGINT to turn into a SIGKILL */
const struct timespec timeout_kill = { 0, 100000000 };
/* 50 seconds for dns_cache_d to respond */
const struct timespec timeout_d = { 50, 0 };

static void
free_array()
{
	/*
	 * There's no need for useless junking while cleaning up.
	 * array_length is never decreased in the program
	 */
	malloc_options = "jj";
	
	MIRROR *ac = array + array_length;

	while (array <= --ac) {
		free(ac->label);
		free(ac->http);
	}
	free(array);
}

static int
usa_cmp(const void *a, const void *b)
{
	char *one_label = ((MIRROR *) a)->label;
	char *two_label = ((MIRROR *) b)->label;

	/* prioritize the USA mirrors first */
	int temp = (strstr(one_label, "USA") != NULL);
	if (temp != (strstr(two_label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}

	if (temp)
		return 0;

        /* prioritize Content Delivery Network "CDN" mirrors next */
        temp = (strstr(one_label, "CDN") != NULL);
        if (temp != (strstr(two_label, "CDN") != NULL)) {
                if (temp)
                        return -1;
                return 1;
        }

	if (temp)
		return 0;

	/* prioritize Canada mirrors last */
	temp = (strstr(one_label, "Canada") != NULL);
	if (temp != (strstr(two_label, "Canada") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}
	return 0;
}

/*
 * compare the labels alphabetically by proper decreasing
 * hierarchy which are in reverse order between commas.
 */
static int
label_cmp_minus_usa(const void *a, const void *b)
{

	char *one_label = ((MIRROR *) a)->label;
	char *two_label = ((MIRROR *) b)->label;
	int i = 3;

	/* start with the last comma */

	char *red = strrchr(one_label, ',');
	if (red == NULL) {
		red = one_label - 2;
		i = 1;
	}

	char *blue = strrchr(two_label, ',');
	if (blue == NULL) {
		blue = two_label - 2;
		--i;
	}

	int ret = strcmp(red + 2, blue + 2);

	while(ret == 0 && i == 3) {

		/*
		 * search for a comma before the one
		 * found in the previous iteration
		 */

		while (one_label <= --red) {
			if (*red == ',')
				goto red_jump;
		}
		--red;
		i = 1;

red_jump:

		while (two_label <= --blue) {
			if (*blue == ',')
				goto blue_jump;
		}
		--blue;
		--i;

blue_jump:

		ret = strcmp(red + 2, blue + 2);

	}

	if (ret == 0) {
		
		/* i equals 0, 1, or 2 */
		
		/*
		 * if (i):
		 * Either red or blue has no more comma
		 * separated entries while remaining, equal.
		 * The one with fewer commas is preferred first.
		 * If red: i == 1, if blue: i == 2
		 */
		if (i == 1)
			return -1;
		if (i == 2)
			return 1;


		/*
		 * exactly equal labels:
		 * Checking for this condition initially
		 * with a label strcmp() doesn't
		 * provide useful information unless
		 * the labels are exactly equal.
		 * It isn't worth wasting time testing
		 * for it initially because of its rarity.
		 */
		return strcmp(
			      ((MIRROR *) a)->http + h,
			      ((MIRROR *) b)->http + h
			     );
	}
	return ret;
}

static int
diff_cmp_minus_usa(const void *a, const void *b)
{
	long double one_diff = ((MIRROR *) a)->diff;
	long double two_diff = ((MIRROR *) b)->diff;

	if (one_diff < two_diff)
		return -1;
	if (one_diff > two_diff)
		return 1;

	/* reverse subsort label_cmp_minus_usa */
	return label_cmp_minus_usa(b, a);
}

static int
diff_cmp(const void *a, const void *b)
{
	long double one_diff = ((MIRROR *) a)->diff;
	long double two_diff = ((MIRROR *) b)->diff;

	if (one_diff < two_diff)
		return -1;
	if (one_diff > two_diff)
		return 1;

	/* 
	 *    Prioritize mirrors near to USA next.
	 * They most likely didn't succeed past here.
	 */
	int ret = usa_cmp(a, b);
	if (ret)
		return ret;

	/* reverse subsort label_cmp_minus_usa */
	return label_cmp_minus_usa(b, a);
}

/*
 * at this time, diff values represent the length of their http char*
 * stripped of the leading "http://" or "https://" and if it exists,
 * the trailing "/pub/OpenBSD".
 */
static int
diff_cmp_g(const void *a, const void *b)
{
	/* sort those with greater diff values first */

	int diff = (
		    (int) ((MIRROR *) b)->diff
		                 -
		    (int) ((MIRROR *) a)->diff
		   );

	if (!diff) {

		return strcmp(
			      ((MIRROR *) a)->http,
			      ((MIRROR *) b)->http
			     );

	}
	return diff;
}

/*
 * diff_cmp_g can be used in the place of this function, but it is
 * far more efficient to avoid the many unnecessary strcmp() for mirrors
 * which have been turned to diff == 0; to be excised from the output.
 */
static int
diff_cmp_g2(const void *a, const void *b)
{
	int one_len = (int) ((MIRROR *) a)->diff;
	int two_len = (int) ((MIRROR *) b)->diff;

	/*
	 * If either are an OpenBSD.org mirror...
	 *    (which means a non-zero diff)
	 *
	 *  Vast majority of the time both will be zero
	 *         if so, dont process further.
	 *
	 * Otherwise, process like diff_cmp_g
	 */
	if (one_len | two_len) {

		/* sort those with greater len values first */

		int diff = two_len - one_len;
		if (!diff) {

			return strcmp(
				      ((MIRROR *) a)->http,
				      ((MIRROR *) b)->http
				     );

		}
		return diff;
	}
	return 0;
}

static int
label_cmp(const void *a, const void *b)
{
	/* prioritize mirrors near to USA first */
	int ret = usa_cmp(a, b);
	if (ret)
		return ret;

	return label_cmp_minus_usa(a, b);
}

static void
manpage()
{
	printf("[-6 (only return IPv6 compatible mirrors)]\n");

	printf("[-d (don't cache DNS)]\n");

	printf("[-f (don't automatically write to File if run as root)]\n");

	printf("[-g (Generate source ftp list)]\n");

	printf("[-h (print this Help message and exit)]\n");

	printf("[-l (ell) quantity of attempts the program will restart\n");
	printf("        in a Loop for recoverable errors (default 20)]\n");

	printf("[-n (search for mirrors with the Next release!)]\n");

	printf("[-O (if you're running a snapshot, it will Override it and\n");
	printf("        search for release mirrors. if you're running a release,\n");
	printf("        it will Override it and search for snapshot mirrors.)\n");

	printf("[-p (search for mirrors with the Previous release!)]\n");

	printf("[-s timeout in Seconds (eg. -s 2.3) (default 10 if -g\n");
	printf("        is specified. Otherwise default 5)]\n");

	printf("[-S (converts http mirrors into Secure https mirrors\n");
	printf("        http mirrors still preserve file integrity!)]\n");

	printf("[-u (no USA mirrors to comply ");
	printf("with USA encryption export laws)]\n");

	printf("[-v (increase Verbosity. It recognizes up to 4 of these)]\n");

	printf("[-V (no Verbose output. No output but error messages)]\n\n");


	printf("More information at: ");
	printf("https://github.com/lukensmall/pkg_ping\n\n");

}

static __attribute__((noreturn)) void
dns_cache_d(const int dns_socket, const int8_t secure,
	     const int8_t six, const int8_t verbose)
{
	if (pledge("stdio dns", NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("dns_cache_d pledge, line: %d\n", __LINE__);
		_exit(1);
	}

	int i = 0, c = 0;

	struct addrinfo *res0 = NULL, *res = NULL;

/*
from: /usr/src/include/netdb.h
struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;
};
*/
	const struct addrinfo hints =
	    { AI_FQDN, AF_UNSPEC, SOCK_STREAM, 0, 0, NULL, NULL, NULL };

	struct sockaddr_in *sa4 = NULL;
	uint32_t sui4 = 0;

	struct sockaddr_in6 *sa6 = NULL;
	unsigned char *suc6 = NULL;

	int8_t max = 0, i_temp = 0, i_max = 0;
	char six_available = '0';

	const char *dns_line0     = (secure) ? "https" : "http";
	const char *dns_line0_alt = (secure) ?  "443"  :  "80";

	const char hexadec[16] = { '0','1','2','3',
				   '4','5','6','7',
				   '8','9','a','b',
				   'c','d','e','f' };

	char *dns_line = calloc(256, sizeof(char));
	if (dns_line == NULL) {
		printf("calloc\n");
		goto dns_exit1;
	}

dns_loop:

	i = read(dns_socket, dns_line, 256);
	if (i == 0) {
		free(dns_line);
		close(dns_socket);
		_exit(0);
	}

	if (i == 256) {
		printf("i > 255, line: %d\n", __LINE__);
		goto dns_exit1;
	}

	if (i == -1) {
		printf("%s ", strerror(errno));
		printf("read error line: %d\n", __LINE__);
		goto dns_exit1;
	}
	dns_line[i] = '\0';

	if (verbose == 4)
		printf("DNS caching: %s\n", dns_line);


	if (getaddrinfo(dns_line, dns_line0, &hints, &res0)) {
		
		c = getaddrinfo(dns_line, dns_line0_alt, &hints, &res0);
		
		if (c) {
			if (verbose == 4)
				printf("%s\n", gai_strerror(c));
			i = write(dns_socket, "f", 1);
			if (i < 1) {
				printf("%s ", strerror(errno));
				printf("write error line: %d\n", __LINE__);
				goto dns_exit1;
			}
			goto dns_loop;
		}
	}

	if (verbose < 4 && six == 0) {
		for (res = res0; res; res = res->ai_next) {
			
			if (res->ai_family == AF_INET) {

				sa4 = (struct sockaddr_in *) res->ai_addr;
				sui4 = sa4->sin_addr.s_addr;

				/* 
				 * I have an unbound blocklist where I
				 * force unwanted domains to resolve to
				 * 0.0.0.0 which translates to sui4 == 0
				 */
				if (sui4 == 0)
					continue;
				break;
			}
			
			if (res->ai_family == AF_INET6)
				break;
		}
		
		if (res == NULL)
			i = write(dns_socket, "u", 1);
		else
			i = write(dns_socket, "1", 1);

		if (i != 1) {
			if (i == -1)
				printf("%s ", strerror(errno));
			printf("write error line: %d\n", __LINE__);
			goto dns_exit1;
		}
		freeaddrinfo(res0);
		goto dns_loop;
	}

	six_available = 'u';

	for (res = res0; res; res = res->ai_next) {

		if (res->ai_family == AF_INET) {

			sa4 = (struct sockaddr_in *) res->ai_addr;
			sui4 = sa4->sin_addr.s_addr;

			/* 
			 * I have an unbound blocklist where I
			 * force unwanted domains to resolve to
			 * 0.0.0.0 which translates to sui4 == 0
			 */
			if (six_available == 'u' && sui4)
				six_available = '0';
				
			if (six)
				continue;

			printf("       %hhu.%hhu.%hhu.%hhu\n",
			    (uint8_t) sui4,
			    (uint8_t)(sui4 >>  8),
			    (uint8_t)(sui4 >> 16),
			    (uint8_t)(sui4 >> 24));
			continue;
		}

		if (res->ai_family != AF_INET6)
			continue;

		six_available = '1';

		if (verbose < 4)
			break;

		printf("       ");

		sa6 = (struct sockaddr_in6 *) res->ai_addr;
		suc6 = sa6->sin6_addr.s6_addr;

		c = max = 0;
		i_max = -1;

		/*
		 * load largest >1 gap beginning into i_max
		 *    and the length of the gap into max
		 */
		for (i = 0; i < 16; i += 2) {

			/* suc6[i] || suc6[i + 1] */
			if (  *( (uint16_t *)(suc6 + i) )  ) {
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
		 *                    ">> 4" == "/ 16"
		 *                "max << 1" == "2 * max"
		 *              "& 15" == "& 0x0f" == "% 16"
		 *    'i' is even so I can use "i|1" instead of "i+1"
		 * which may be more efficient. I think it's prettier too
		 */
		for (i = 0; i < 16; i += 2) {

			if (i)
				printf(":");

			if (i == i_max) {
				if (i == 0)
					printf("::");
				else
					printf(":");
				i += max << 1;
				if (i > 14)
					break;
			}

			if (suc6[i  ] >> 4) {
				printf("%c%c%c%c",
				    hexadec[suc6[i  ] >> 4],
				    hexadec[suc6[i  ] & 15],
				    hexadec[suc6[i|1] >> 4],
				    hexadec[suc6[i|1] & 15]);

			} else if (suc6[i  ]) {
				printf("%c%c%c",
				    hexadec[suc6[i  ]     ],
				    hexadec[suc6[i|1] >> 4],
				    hexadec[suc6[i|1] & 15]);

			} else if (suc6[i|1] >> 4) {
				printf("%c%c",
				    hexadec[suc6[i|1] >> 4],
				    hexadec[suc6[i|1] & 15]);
			} else {
				printf("%c",
				    hexadec[suc6[i|1]     ]);
			}
		}
		printf("\n");
	}
	freeaddrinfo(res0);

	i = write(dns_socket, &six_available, 1);

	if (i != 1) {
		if (i == -1)
			printf("%s ", strerror(errno));
		printf("write error line: %d\n", __LINE__);
		goto dns_exit1;
	}

	goto dns_loop;

dns_exit1:

	free(dns_line);
	close(dns_socket);
	_exit(1);
}

/*
 * I considered keeping this functionality in main(), but
 * if there's a possibility of the main() getting overrun,
 * this process performs some sanity checks to, among
 * other things, prevent /etc/installurl from becoming a
 * massive file which fills up the partition. That
 * scenario is perhaps possible if the program is
 * called with doas so that the program has root privileges
 * but the caller isn't root, so they don't have full
 * access to fill up the partition in which /etc/ resides
 * all by themselves.
 */
static __attribute__((noreturn)) void
file_d(const int write_pipe, const int8_t secure, const int8_t verbose)
{

	if (pledge("stdio cpath wpath", NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("pledge, line: %d\n", __LINE__);
		_exit(1);
	}

	int i = 0;

	char *file_w = NULL;
	FILE *pkg_write = NULL;

	file_w = calloc(302, sizeof(char));
	if (file_w == NULL) {
		printf("calloc\n");
		_exit(1);
	}

	int received = read(write_pipe, file_w, 301);

	if (received == -1) {
		printf("%s ", strerror(errno));
		close(write_pipe);
		printf("read error occurred, line: %d\n", __LINE__);
		printf("/etc/installurl not written.\n");
		goto file_cleanup;
	}

	close(write_pipe);

	if (received == 0) {
		printf("program exited without writing.\n");
		printf("/etc/installurl not written.\n");
		goto file_cleanup;
	}
	
	if (received == 301) {
		printf("received mirror is too large\n");
		printf("/etc/installurl not written.\n");
		goto file_cleanup;
	}

	file_w[received] = '\n';

	if (secure) {
		if (strncmp(file_w, "https://", 8)) {
			printf("file_w does't begin with ");
			printf("\"https://\", line: %d\n", __LINE__);
			printf("/etc/installurl not written.\n");
			goto file_cleanup;
		}
	} else {
		if (strncmp(file_w, "http://", 7)) {
			printf("file_w does't begin with ");
			printf("\"http://\", line: %d\n", __LINE__);
			printf("/etc/installurl not written.\n");
			goto file_cleanup;
		}
	}

	/* unlink() to prevent possible symlinks by...root? */
	unlink("/etc/installurl");
	pkg_write = fopen("/etc/installurl", "w");

	if (pledge("stdio", NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("pledge, line: %d\n", __LINE__);
		_exit(1);
	}

	if (verbose > 0)
		printf("\n");

	if (pkg_write == NULL) {
		printf("%s ", strerror(errno));
		printf("/etc/installurl not opened.\n");
		goto file_cleanup;
	}

	i = fwrite(file_w, 1, received + 1, pkg_write);
	if (i < received + 1) {
		printf("write error occurred, line: %d\n", __LINE__);
		fclose(pkg_write);
		goto file_cleanup;
	}

	fclose(pkg_write);

	if (verbose >= 0)
		printf("/etc/installurl: %s", file_w);

	free(file_w);

	_exit(0);

file_cleanup:
	free(file_w);
	_exit(1);
}

static __attribute__((noreturn)) void
restart(int argc, char *argv[], const int loop, const int8_t verbose)
{

	if (loop == 0)
		errx(2, "Looping exhausted: Try again.");

	if (verbose != -1)
		printf("restarting...loop: %d\n", loop);

	const int n = argc - (argc > 1 && !strncmp(argv[argc - 1], "-l", 2));

	char **arg_v = calloc(n + 1 + 1, sizeof(char *));
	if (arg_v == NULL)
		errx(1, "calloc");

	memcpy(arg_v, argv, n * sizeof(char *));

	const int len = 10;
	arg_v[n] = calloc(len, sizeof(char));
	if (arg_v[n] == NULL)
		errx(1, "calloc");
	int c = snprintf(arg_v[n], len, "-l%d", loop - 1);
	if (c >= len || c < 0) {
		if (c < 0)
			printf("%s", strerror(errno));
		else
			printf("arg_v[n]: %s,", arg_v[n]);
		printf(" snprintf, line: %d\n", __LINE__);
		exit(1);
	}

	execv(arg_v[0], arg_v);
	err(1, "execv failed, line: %d", __LINE__);
}

static void
easy_ftp_kill(const int kq, struct kevent *ke, const pid_t ftp_pid)
{
	EV_SET(ke, ftp_pid, EVFILT_PROC, EV_ADD |
	    EV_ONESHOT, NOTE_EXIT, 0, NULL);

	/* kevent registration returns -1, if ftp_pid is already dead */
	if (kevent(kq, ke, 1, NULL, 0, NULL) != -1) {

		kill(ftp_pid, SIGINT);

		/*
		 * give it time to gracefully abort, and play nice
		 * with the server before killing it with prejudice
		 */
		if (!kevent(kq, NULL, 0, ke, 1, &timeout_kill))
			kill(ftp_pid, SIGKILL);
			
    	} else if (errno != ESRCH) {
		printf("%s ", strerror(errno));
		printf("kevent, line: %d\n", __LINE__);
		/* Don't exit. Already dying. */
    	}
    	
 	waitpid(ftp_pid, NULL, 0);
}

char *diff_array = NULL;

/* 
 * print long double which is <1 and >0, without the leading '0'
 * eg. 0.25 is printed: .25
 * it doesn't get here unless diff <1 and >0
 */
static void
print_sub_one(long double diff)
{	
	int i = snprintf(diff_array, 12, "%.9Lf", diff);
	if (i != 11) {
		if (i < 0)
			 printf("%s", strerror(errno));
		else
			printf("'line': %s,", diff_array);
		printf(" snprintf, line: %d\n", __LINE__);
		exit(1);
	}
	printf("%s", 1 + diff_array);
}

int
main(int argc, char *argv[])
{

	malloc_options = "CFGJJU";

	int8_t root_user = !getuid();
	int8_t to_file = root_user;
	int8_t num = 0, current = 0, secure = 0, verbose = 0;
	int8_t generate = 0, override = 0, six = 0;
	int8_t previous = 0, next = 0, s_set = 0;
	int8_t dns_cache = 1, usa = 1;
	int loop = 20;
	long double S = 0;
	pid_t ftp_pid = 0, write_pid = 0, dns_cache_d_pid = 0;
	int kq = 0, i = 0, pos = 0, c = 0, n = 0;
	int array_max = 100, tag_len = 0, j = 0;
	int pos_max = 0, std_err = 0, entry_line = 0, exit_line = 0;

	int dns_cache_d_socket[2] = { -1, -1 };
	int         write_pipe[2] = { -1, -1 };
	int            ftp_out[2] = { -1, -1 };
	int         block_pipe[2] = { -1, -1 };

	struct timespec start = { 0, 0 }, end = { 0, 0 };
	struct timespec timeout = { 0, 0 };
	char *line_temp = NULL, *line0 = NULL, *line = NULL, *release = NULL;
	char *tag = NULL, *time = NULL;
	size_t len = 0;
	char v = '\0';
/*
from: /usr/src/sys/sys/event.h
struct kevent {
	__uintptr_t     ident;
	short           filter;
	unsigned short  flags;
	unsigned int    fflags;
	__int64_t       data;
	void            *udata;
};
*/
	struct kevent ke = { 0, 0, 0, 0, 0, NULL };

	/* 5 second default mirror timeout */
	long double s = 5;

	/* 10 seconds and 0 nanoseconds to download ftplist */
	struct timespec timeout0 = { 10, 0 };


/*
from: /usr/src/sys/sys/ttycom.h
struct winsize {
	unsigned short  ws_row;         // rows, in characters
	unsigned short  ws_col;         // columns, in characters
	unsigned short  ws_xpixel;      // horizontal size, pixels
	unsigned short  ws_ypixel;      // vertical size, pixels
};
*/
	struct winsize w = { 0, 0, 0, 0 };

	i = pledge("stdio exec proc cpath wpath dns id unveil tty", NULL);
	if (i == -1)
		err(1, "pledge, line: %d", __LINE__);

	i = ioctl(0, TIOCGWINSZ, &w);
	if (i == -1)
		err(1, "ioctl, line: %d", __LINE__);

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

	diff_array = calloc(12, sizeof(char));
	if (diff_array == NULL)
		errx(1, "calloc");

	for(c = 1; c < argc; ++c) {
		if (strnlen(argv[c], 35) == 35)
			errx(1, "keep argument lengths under 35");
	}


	if (argc >= 30) {
		i = !strncmp(argv[argc - 1], "-l", 2);
		if (argc - i >= 30)
			errx(1, "keep argument count under 30");
	}


	while ((c = getopt(argc, argv, "6dfghl:nOpSs:uvV")) != -1) {
		switch (c) {
		case '6':
			six = 1;
			break;
		case 'd':
			dns_cache = 0;
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
			manpage();
			return 0;
		case 'l':
			if (strlen(optarg) >= 5) {
				printf("keep -l argument under ");
				printf("5 characters long.\n");
				return 1;
			}

			c = loop = 0;
			do {
				if (optarg[c] < '0' || optarg[c] > '9') {
					printf("-l argument only accepts ");
					printf("numeric characters\n");
					return 1;
				}
				loop = loop * 10 + optarg[c] - '0';
			} while (optarg[++c] != '\0');
			break;
		case 'n':
			previous = 0;
			next = 1;
			break;
		case 'O':
			override = 1;
			break;
		case 'p':
			next = 0;
			previous = 1;
			break;
		case 'S':
			secure = 1;
			break;
		case 's':
		
			if (!strcmp(optarg, "."))
				errx(1, "-s argument should not be: \".\"");

			if (strlen(optarg) >= 15) {
				printf("keep -s argument under ");
				printf("15 characters long\n");
				return 1;
			}
			
			c = i = 0;
			do {
				if (optarg[c] >= '0' && optarg[c] <= '9')
					continue;
				if (optarg[c] == '.' && ++i == 1)
					continue;

				printf("-s argument should only have numeric ");
				printf("characters and a maximum ");
				printf("of one decimal point\n");
				return 1;

			} while (optarg[++c] != '\0');

			errno = 0;
			s = strtold(optarg, &line_temp);
			
			if (errno || optarg == line_temp) {
				printf("\"%s\" is an invalid ", optarg);
				printf("argument for -s\n");
				return 1;
			}

			free(time);
			time = strdup(optarg);
			if (time == NULL)
				errx(1, "strdup");

			break;
		case 'u':
			usa = 0;
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
			manpage();
			return 1;
		}
	}
	if (optind < argc) {
		manpage();
		errx(1, "non-option ARGV-element: %s", argv[optind]);
	}

	if (generate) {
		if (verbose < 1)
			verbose = 1;
		secure = 1;
		next = previous = override = to_file = 0;
		if (pledge("stdio exec proc dns id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);

		/* change default 's' value if not specified */
		if (time == NULL)
			s = 10;
	}

	if (s > 1000)
		errx(1, "try an -s less than, equal to 1000");
	if (s < (long double)0.015625)
		errx(1, "try an -s greater than or equal to 0.015625 (1/64)");



	if (dns_cache == 0 && verbose == 4)
		verbose = 3;


	if (dns_cache) {

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, dns_cache_d_socket) == -1)
			err(1, "socketpair, line: %d\n", __LINE__);

		dns_cache_d_pid = fork();
		switch(dns_cache_d_pid) {
			case -1:
				err(1, "dns_cache_d fork, line: %d\n",
				    __LINE__);
			case 0:
				close(dns_cache_d_socket[1]);
				dns_cache_d(dns_cache_d_socket[0], secure,
						six, verbose);
				errx(1, "dns_cache_d returned! line: %d\n",
				    __LINE__);
		}
		close(dns_cache_d_socket[0]);
	}

	if (to_file) {

		if (pipe2(write_pipe, O_CLOEXEC) == -1)
			err(1, "pipe2, line: %d", __LINE__);

		write_pid = fork();
		switch(write_pid) {
			case -1:
				err(1, "file_d fork, line: %d\n", __LINE__);
			case 0:
				close(dns_cache_d_socket[1]);
				close(write_pipe[STDOUT_FILENO]);
				file_d(write_pipe[STDIN_FILENO],
					secure, verbose);
				errx(1, "file_d returned! line: %d\n",
				    __LINE__);
		}
		close(write_pipe[STDIN_FILENO]);
	}


	if (root_user) {
		if (pledge("stdio exec proc id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	} else {
		if (pledge("stdio exec proc", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
	}



	kq = kqueue();
	if (kq == -1)
		err(1, "kq! line: %d", __LINE__);

	entry_line = __LINE__;


                        /* GENERATED CODE BEGINS HERE */


        const char *ftp_list[55] = {

          "openbsd.mirror.constant.com","plug-mirror.rcac.purdue.edu",
           "cloudflare.cdn.openbsd.org","ftp.halifax.rwth-aachen.de",
            "ftp.rnl.tecnico.ulisboa.pt","mirrors.gethosted.online",
  "mirrors.ocf.berkeley.edu","mirror.hs-esslingen.de","mirror2.sandyriver.net",
   "mirrors.pidginhost.com","openbsd.cs.toronto.edu","*artfiles.org/openbsd",
    "mirror.bytemark.co.uk","mirror.planetunix.net","www.mirrorservice.org",
      "ftp4.usa.openbsd.org","mirror.aarnet.edu.au","openbsd.c3sl.ufpr.br",
       "ftp.usa.openbsd.org","ftp2.eu.openbsd.org","mirror.edgecast.com",
       "mirror.leaseweb.com","mirror.telepoint.bg","mirrors.gigenet.com",
         "ftp.eu.openbsd.org","ftp.fr.openbsd.org","ftp.lysator.liu.se",
         "mirror.fsmg.org.nz","mirror.ungleich.ch","mirrors.dotsrc.org",
          "openbsd.ipacct.com","ftp.hostserver.de","mirrors.sonic.net",
  "mirrors.ucr.ac.cr","mirror.labkom.id","mirror.litnet.lt","cdn.openbsd.org",
    "ftp.OpenBSD.org","ftp.jaist.ac.jp","mirror.esc7.net","mirror.ihost.md",
     "mirror.ox.ac.uk","mirrors.mit.edu","ftp.icm.edu.pl","mirror.one.com",
 "ftp.cc.uoc.gr","ftp.heanet.ie","ftp.spline.de","www.ftp.ne.jp","ftp.nluug.nl",
       "ftp.riken.jp","ftp.psnc.pl","ftp.bit.nl","ftp.fau.de","ftp.fsn.hu"

        };

        const int index = 55;



     /* Trusted OpenBSD.org subdomain mirrors for generating this section */

        const char *ftp_list_g[8] = {

   "cloudflare.cdn.openbsd.org","ftp4.usa.openbsd.org","ftp.usa.openbsd.org",
        "ftp2.eu.openbsd.org","ftp.eu.openbsd.org","ftp.fr.openbsd.org",
                       "cdn.openbsd.org","ftp.OpenBSD.org"

        };

        const int index_g = 8;


                         /* GENERATED CODE ENDS HERE */


	exit_line = __LINE__;


	if (pipe(ftp_out) == -1)
		err(1, "pipe, line: %d", __LINE__);


	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

		if (root_user) {
		/*
		 * user _pkgfetch: ftp will regain read pledge
		 *    just to chroot to /var/empty leaving
		 *      read access to an empty directory
		 */
			setuid(57);
		}

		close(ftp_out[STDIN_FILENO]);

		n = 300;
		line = calloc(n, sizeof(char));
		if (line == NULL) {
			printf("calloc\n");
			_exit(1);
		}

		if (generate) {

			i = arc4random_uniform(index_g);

			if (ftp_list_g[i][0] == '*') {
				i = snprintf(line, n,
				   "https://%s/ftplist",
				   1 + ftp_list_g[i]);
			} else {
				i = snprintf(line, n,
				    "https://%s/pub/OpenBSD/ftplist",
				    ftp_list_g[i]);
			}

		} else {

			i = arc4random_uniform(index);

			if (ftp_list[i][0] == '*') {
				i = snprintf(line, n,
				    "https://%s/ftplist",
				    1 + ftp_list[i]);
			} else {
				i = snprintf(line, n,
				    "https://%s/pub/OpenBSD/ftplist",
				    ftp_list[i]);
			}
		}

		if (i >= n || i < 0) {
			if (i < 0)
				printf("%s", strerror(errno));
			else
				printf("'line': %s,", line);
			printf(" snprintf, line: %d\n", __LINE__);
			return 1;
		}

		if (verbose >= 2)
			printf("%s\n", line);
		else if (verbose >= 0) {
			printf("$");
			fflush(stdout);
		}


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


	/* Let's do some work while ftp is downloading ftplist */


	S = (long double) timeout0.tv_sec +
	    (long double) timeout0.tv_nsec /
	    (long double) 1000000000;

	if (s > S) {
		timeout0.tv_sec = (time_t) s;
		timeout0.tv_nsec =
		    (long) ((s -
		    (long double) timeout0.tv_sec) *
		    (long double) 1000000000);
	}

	S = s;

	if (time == NULL) {
		n = 20;
		time = calloc(n, sizeof(char));
		if (time == NULL) {
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "calloc");
		}
		i = snprintf(time, n, "%Lf", s);
		if (i >= n || i < 0) {
			if (i < 0)
				printf("%s", strerror(errno));
			else
				printf("time: %s,", time);
			printf(" snprintf, line: %d\n", __LINE__);
			easy_ftp_kill(kq, &ke, ftp_pid);
			return 1;
		}
	} else
		s_set = 1;

	/* trim extra zeroes after decimal point in 'time' */
	if (strchr(time, '.') != NULL) {
		i = 0;
		n = strlen(time);
		while (time[--n] == '0')
			i = n;

		/* if they are all zeroes after '.' then remove '.' */
		if (time[n] == '.')
			i = n;

		if (i) {
			time[i] = '\0';
			char *time0 = time;
			time = strdup(time0);
			if (time == NULL) {
				easy_ftp_kill(kq, &ke, ftp_pid);
				errx(1, "strdup");
			}
			free(time0);
		}
	}


	if (previous) {
		if (verbose >= 2) {
			printf("showing the previous ");
			printf("release availability!\n\n");
		}
	} else if (next) {
		if (verbose >= 2)
			printf("showing the next release availability!\n\n");
	} else if (generate == 0) {
		const int mib[2] = { CTL_KERN, KERN_VERSION };

		/* retrieve length of results of "sysctl kern.version" */
		if (sysctl(mib, 2, NULL, &len, NULL, 0) == -1) {
			printf("%s ", strerror(errno));
			printf("sysctl, line: %d", __LINE__);
			easy_ftp_kill(kq, &ke, ftp_pid);
			return 1;
		}

		line = calloc(len, sizeof(char));
		if (line == NULL) {
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "calloc");
		}

		/* read results of "sysctl kern.version" into 'line' */
		if (sysctl(mib, 2, line, &len, NULL, 0) == -1) {
			printf("%s ", strerror(errno));
			printf("sysctl, line: %d", __LINE__);
			easy_ftp_kill(kq, &ke, ftp_pid);
			return 1;
		}

		/* Discovers if the kernel is not a release version */
		if (strstr(line, "current") || strstr(line, "beta"))
			current = 1;

		free(line);

		if (override)
			current = !current;

		if (verbose >= 2) {
			if (current)
				printf("showing snapshot mirrors\n\n");
			else
				printf("showing release mirrors\n\n");
		}
	}

	if (generate) {

		tag = strdup("/timestamp");
		if (tag == NULL) {
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "strdup");
		}

		tag_len = strlen(tag);

	} else {

		struct utsname *name = calloc(1, sizeof(struct utsname));

		if (name == NULL) {
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "calloc");
		}


		if (uname(name) == -1) {
			printf("%s ", strerror(errno));
			printf("uname, line: %d", __LINE__);
			easy_ftp_kill(kq, &ke, ftp_pid);
			return 1;
		}

		if (next && !strcmp(name->release, "9.9")) {
			release = strdup("10.0");
			i = 0;
		} else {
			release = strdup(name->release);
			i = 1;
		}

		if (release == NULL) {
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "strdup");
		}

		if (next && i) {

			n = strlen(release) + 1;
			i = snprintf(release, n, "%.1f", atof(release) + .1);

			if (i >= n || i < 0) {
				if (i < 0)
					printf("%s", strerror(errno));
				else
					printf("release: %s,", release);
				printf(" snprintf, line: %d\n", __LINE__);
				easy_ftp_kill(kq, &ke, ftp_pid);
				return 1;
			}
		}

		if (previous) {

			n = strlen(release) + 1;
			i = snprintf(release, n, "%.1f", atof(release) - .1);

			if (i >= n || i < 0) {
				if (i < 0)
					printf("%s", strerror(errno));
				else
					printf("release: %s,", release);
				printf(" snprintf, line: %d\n", __LINE__);
				easy_ftp_kill(kq, &ke, ftp_pid);
				return 1;
			}
		}


		if (current) {
			tag_len = strlen("/snapshots/") +
			    strlen(name->machine) + strlen("/SHA256");
		} else {
			tag_len = strlen("/") + strlen(release) + strlen("/") +
			    strlen(name->machine) + strlen("/SHA256");
		}

		tag = calloc(tag_len + 1, sizeof(char));
		if (tag == NULL) {
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "calloc");
		}

		if (current) {
			i = snprintf(tag, tag_len + 1,
			    "/snapshots/%s/SHA256", name->machine);
		} else {
			i = snprintf(tag, tag_len + 1,
			    "/%s/%s/SHA256", release, name->machine);
		}

		if (i >= tag_len + 1 || i < 0) {
			if (i < 0)
				printf("%s", strerror(errno));
			else
				printf("tag: %s,", tag);
			printf(" snprintf, line: %d\n", __LINE__);
			easy_ftp_kill(kq, &ke, ftp_pid);
			return 1;
		}

		free(name);
	}


	/* if the index for line[] can exceed 254, it will error out */
	line = calloc(255, sizeof(char));
	if (line == NULL) {
		easy_ftp_kill(kq, &ke, ftp_pid);
		errx(1, "calloc");
	}

	array = calloc(array_max, sizeof(MIRROR));
	if (array == NULL) {
		easy_ftp_kill(kq, &ke, ftp_pid);
		errx(1, "calloc");
	}

	atexit(free_array);

	c = ftp_out[STDIN_FILENO];

	/*
	 * I use kevent here, just so I can restart
	 *   the program again if ftp is sluggish
	 */
	EV_SET(&ke, c, EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	i = kevent(kq, &ke, 1, &ke, 1, &timeout0);

	/* (verbose == 0 || verbose == 1) */
	if ((verbose >> 1) == 0) {
		printf("\b \b");
		fflush(stdout);
	}
	
	if (i == -1) {
		printf("%s ", strerror(errno));
		printf("kevent, timeout0 may be too large. ");
		printf("line: %d\n", __LINE__);
		easy_ftp_kill(kq, &ke, ftp_pid);
		return 1;
	}

	if (i != 1) {

		easy_ftp_kill(kq, &ke, ftp_pid);
		close(kq);
		free(line);
		free(time);
		free(release);
		close(ftp_out[STDIN_FILENO]);
		if (dns_cache) {
			close(dns_cache_d_socket[1]);
			waitpid(dns_cache_d_pid, NULL, 0);
		}
		if (to_file) {
			close(write_pipe[STDOUT_FILENO]);
			waitpid(write_pid, NULL, 0);
		}
		restart(argc, argv, loop, verbose);
	}

	while (read(c, &v, 1) == 1) {
		if (pos == 254) {
			line[pos] = '\0';
			printf("'line': %s\n", line);
			printf("pos got too big! line: %d\n", __LINE__);
			easy_ftp_kill(kq, &ke, ftp_pid);
			return 1;
		}

		if (num == 0) {

			if (v != ' ') {
				line[pos++] = v;
				continue;
			}
			line[pos++] = '\0';

			/* safety check */
			if (strncmp(line, "http://", 7)) {
				printf("'line': %s\n", line);
				printf("bad http format, line: %d\n", __LINE__);
				easy_ftp_kill(kq, &ke, ftp_pid);
				return 1;
			}

			if (secure) {

				if (pos_max < ++pos)
					pos_max = pos;

				array[array_length].http =
				    calloc(pos, sizeof(char));

				if (array[array_length].http == NULL) {
					easy_ftp_kill(kq, &ke, ftp_pid);
					errx(1, "calloc");
				}

				memcpy(array[array_length].http, "https", 5);

				/* strlen("http") == 4 */
				memcpy(5 + array[array_length].http,
				    4 + line, pos - 5);

			} else {

				if (pos_max < pos)
					pos_max = pos;

				array[array_length].http = strdup(line);

				if (array[array_length].http == NULL) {
					easy_ftp_kill(kq, &ke, ftp_pid);
					errx(1, "strdup");
				}
			}

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


		/* wipes out spaces at the end of the label */
		while (pos && line[pos - 1] == ' ')
			--pos;

		line[pos++] = '\0';

		if (usa == 0 && strstr(line, "USA")) {
			free(array[array_length].http);
			pos = num = 0;
			continue;
		}

		if (verbose >= 1) {
			/*
			 * safety check for label_cmp_minus_usa():
			 * make sure there is a space after last comma
			 * which would allow the function to make the
			 * assumption that 2 spaces after the comma is
			 * on the array (or at least '\0'). A bad label 
			 * could otherwise be read past the the end of
			 * the buffer.
			 *
			 * I could make label_cmp_minus_usa() safer,
			 * but it costs less checking it here.
			 */
			line_temp = strrchr(line, ',');
			if (line_temp && strncmp(line_temp, ", ", 2)) {
				free(array[array_length].http);
				printf("label malformation: %s ", line);
				printf("line: %d\n", __LINE__);
				easy_ftp_kill(kq, &ke, ftp_pid);
				return 1;
			}

			/* 
			 * Not a fan of "The " in "The Netherlands" in here;
			 *  nor of any other countries starting with "The "
			 *     I think it sticks out when it's sorted.
			 * 
			 *   If the label has a "The " after the last ", "
			 *   or if it has no comma and starts with "The ",
			 *          this will surgically remove it.
			 */
			if (line_temp) {
				if (!strncmp(line_temp + 2, "The ", 4)) {
					memmove(line_temp + 2, line_temp + 6,
					    line + pos - (line_temp + 6));
				}
			} else if (!strncmp(line, "The ", 4))
				memmove(line, line + 4, pos - 4);
		}
		
		array[array_length].label = strdup(line);
		if (array[array_length].label == NULL) {
			free(array[array_length].http);
			easy_ftp_kill(kq, &ke, ftp_pid);
			errx(1, "strdup");
		}


		if (++array_length == array_max) {

			array_max += 50;
			
			if (array_max >= 500) {
				easy_ftp_kill(kq, &ke, ftp_pid);
				errx(1, "array_length got insanely large");
			}
			array = recallocarray(array, array_length, array_max,
			    sizeof(MIRROR));

			if (array == NULL) {
				easy_ftp_kill(kq, &ke, ftp_pid);
				errx(1, "recallocarray");
			}
		}

		pos = num = 0;
	}

	close(ftp_out[STDIN_FILENO]);

	waitpid(ftp_pid, &n, 0);

	/*
	 *            'ftplist' download error:
	 * It's caused by no internet, bad dns resolution;
	 *   Or from a faulty mirror or its bad dns info
	 */
	if (n || array_length == 0) {		

		if (verbose >= 0)
			printf("There was an 'ftplist' download problem.\n");

		close(kq);
		free(line);
		free(time);
		free(release);
		if (dns_cache) {
			close(dns_cache_d_socket[1]);
			waitpid(dns_cache_d_pid, NULL, 0);
		}
		if (to_file) {
			close(write_pipe[STDOUT_FILENO]);
			waitpid(write_pid, NULL, 0);
		}
		restart(argc, argv, loop, verbose);
	}

	/* h = strlen("https://") instead of strlen("http://") if "secure" */
	h += secure;

	pos_max += tag_len;

	if (pos_max > (int)sizeof(line)) {
		free(line);
		line = calloc(pos_max, sizeof(char));
		if (line == NULL)
			errx(1, "calloc");
	}

	/*
	 * if verbose > 1, make mirrors near USA first, then subsort by label.
	 *       otherwise, make mirrors near USA first, then don't care.
	 *
	 *  Searching through mirrors near USA on verbose < 1 is more likely
	 * to find the faster mirrors to shrink 'timeout' earlier to make the
	 *                    runtime as short as possible.
	 */
	if (usa == 0) {
		if (verbose > 1) {
			qsort(array, array_length, sizeof(MIRROR),
			    label_cmp_minus_usa);
		} /* else don't sort */
	} else {
		if (verbose > 1)
			qsort(array, array_length, sizeof(MIRROR), label_cmp);
		else if (verbose < 1)
			qsort(array, array_length, sizeof(MIRROR), usa_cmp);
		/* else don't sort */
	}

	if (six) {
		if (verbose >= 3)
			line0 = "-vim6o-";
		else
			line0 = "-ViM6o-";
	} else {
		if (verbose >= 3)
			line0 = "-vimo-";
		else
			line0 = "-ViMo-";
	}

	timeout.tv_sec = (time_t) s;
	timeout.tv_nsec =
	    (long) ((s -
	    (long double) timeout.tv_sec) *
	    (long double) 1000000000);


	std_err = dup(STDERR_FILENO);
	if (std_err == -1)
		err(1, "dup, line: %d\n", __LINE__);

	if (fcntl(std_err, F_SETFD, FD_CLOEXEC) == -1)
		err(1, "fcntl, line: %d\n", __LINE__);

	MIRROR *ac = NULL;
	int pos_maxl = 0, pos_maxh = 0, pos_maxb = 0, pos1 = 0;
	int8_t num1 = 0, num2 = 0, num3 = 0;
	char *host = NULL;
	char *cut = NULL;

	if (verbose >= 2) {
		
		ac = array + array_length;
		i = (array_length >= 100) + 10;

		while (array != ac--) {
			
			pos = strlen(ac->label);
			if (pos > pos_maxl)
				pos_maxl = pos;

			host = ac->http + h;
			cut = strchr(host, '/');
			if (cut == NULL)
				pos1 = strlen(host);
			else
				pos1 = cut - host;
				
			if (pos1 > pos_maxh)
				pos_maxh = pos1;
				
			pos += pos1;
				
			if (pos > pos_maxb)
				pos_maxb = pos;
		}

		num1 = (w.ws_col >= i + pos_maxl + pos_max);
		num2 = (w.ws_col >= i + pos_maxl + pos_maxh);
		num3 = (w.ws_col >= i + pos_maxb);
	}
				

	host = h + line;
	
	memcpy(line, array->http, h);
	
	pos_max -= h;
	
	for (c = 0; c < array_length; ++c) {

		n = strlcpy(host, array[c].http + h, pos_max);
		memcpy(host + n, tag, tag_len + 1);


		/* strchr always succeeds. 'tag' starts with '/' */
		cut = strchr(host, '/');

		if (verbose >= 2) {
			if (verbose == 4)
				printf("\n\n\n\n");
			else if (verbose == 3)
				printf("\n\n");
			else
				printf("\n");
			
			if (array_length >= 100)
				printf("%3d : ", array_length - c);
			else
				printf("%2d : ", array_length - c);
				
			if (num2) {
				
				i = strlen(array[c].label);
				j = (pos_maxl + 1 - i) / 2;
				n = pos_maxl - (i + j);

				while (j--)
					printf(" ");
				
				printf("%s", array[c].label);
				
				while (n--)
					printf(" ");
				
				if (num1)
					printf("  :  %s\n", line);
				else {
					*cut = '\0';
					printf("  :  %s\n", host);
					*cut = '/';
				}
				
			} else if (num3) {
				*cut = '\0';
				printf("%s  :  %s\n", array[c].label, host);
				*cut = '/';
			} else
				printf("%s\n", array[c].label);
			
		} else if (verbose >= 0) {
			i = array_length - c;
			if (c > 0) {
				if ( i == 9 || i == 99 )
					printf("\b \b");
				n = i;
				do {
					printf("\b");
					n /= 10;
				} while (n);
			}
			printf("%d", i);
			fflush(stdout);
		}



		n = cut - host;

		if (dns_cache) {

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







			/*
			 * I use kevent here, just so I can restart
			 * the program again if DNS daemon is stuck
			 */
			EV_SET(&ke, dns_cache_d_socket[1], EVFILT_READ,
			    EV_ADD | EV_ONESHOT, 0, 0, NULL);
			i = kevent(kq, &ke, 1, &ke, 1, &timeout_d);

			if ((verbose >> 2) == 0) {
				printf("\b \b");
				fflush(stdout);
			}

			if (i == -1) {
				printf("%s ", strerror(errno));
				printf("kevent, timeout_d may be too large. ");
				printf("line: %d\n", __LINE__);
				return 1;
			}

			if (i != 1) {
				kill(dns_cache_d_pid, SIGINT);

				/*
				 * give it time to gracefully abort, play
				 *  nice with the server and reap event
				 */
				i = kevent(kq, NULL, 0, &ke, 1, &timeout_kill);
				if (i == -1)
					err(1, "kevent, line: %d", __LINE__);
						
				if (i == 0) {

					kill(dns_cache_d_pid, SIGKILL);
					if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1)
						err(1, "kevent, line: %d", __LINE__);
				}

				waitpid(dns_cache_d_pid, NULL, 0);
				
				dns_cache = 0;
				
				
				goto restart_dns_err;
			}


			i = read(dns_cache_d_socket[1], &v, 1);

			if (i < 1) {

restart_dns_err:

				close(std_err);
				free(line);

				if (verbose >= 2)
					printf("dns_cache process issues\n\n");
				else if (verbose >= 0) {
					n = array_length - c;
					do {
						printf("\b \b");
						n /= 10;
					} while (n);
				}

				close(kq);
				free(time);
				free(release);
				
				if (dns_cache) {
					close(dns_cache_d_socket[1]);
					waitpid(dns_cache_d_pid, NULL, 0);
				}
				if (to_file) {
					close(write_pipe[STDOUT_FILENO]);
					waitpid(write_pid, NULL, 0);
				}
				
				restart(argc, argv, loop, verbose);
			}
			
			if (six && v == '0') {
				if (verbose >= 2)
					printf("IPv6 DNS record not found.\n");
				array[c].diff = s + 2;
				continue;
			} else if (v == 'f') {
				if (verbose >= 2)
					printf("DNS record not found.\n");
				array[c].diff = s + 3;
				continue;
			} else if (v == 'u') {
				if (verbose >= 2)
					printf("BLOCKED subdomain!\n");
				array[c].diff = s + 4;
				continue;
			}
		}


		if (pipe(block_pipe) == -1)
			err(1, "pipe, line: %d", __LINE__);

		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {

			if (root_user) {
			/*
			 * user _pkgfetch: ftp will regain read pledge
			 *    just to chroot to /var/empty leaving
			 *      read access to an empty directory
			 */
				setuid(57);
			}

			close(STDOUT_FILENO);
			if (verbose <= 2)
				close(STDERR_FILENO);

			/*
			 *     this read() is to ensure that the process
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
			fflush(NULL);
			_exit(1);
		}
		if (ftp_pid == -1)
			err(1, "ftp 2 fork, line: %d", __LINE__);


		close(block_pipe[STDIN_FILENO]);

		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD |
		    EV_ONESHOT, NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			printf("kevent register fail, line: %d", __LINE__);
			return 1;
		}

		close(block_pipe[STDOUT_FILENO]);


		clock_gettime(CLOCK_REALTIME, &start);
		i = kevent(kq, NULL, 0, &ke, 1, &timeout);
		clock_gettime(CLOCK_REALTIME, &end);

		if (i == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			printf("kevent, line: %d", __LINE__);
			return 1;
		}

		/* timeout occurred before ftp() exit was received */
		if (i == 0) {

			kill(ftp_pid, SIGINT);

			/*
			 * give it time to gracefully abort, play
			 *  nice with the server and reap event
			 */
			i = kevent(kq, NULL, 0, &ke, 1, &timeout_kill);
			if (i == -1)
				err(1, "kevent, line: %d", __LINE__);
					
			if (i == 0) {

				kill(ftp_pid, SIGKILL);
				if (verbose >= 2)
					printf("killed\n");
				if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1)
					err(1, "kevent, line: %d", __LINE__);
			}

			waitpid(ftp_pid, NULL, 0);

			if (verbose >= 2)
				printf("Timeout\n");
			array[c].diff = s;
			continue;
		}
		waitpid(ftp_pid, &n, 0);

		if (n) {
			array[c].diff = s + 1;
			if (verbose >= 2)
				printf("Download Error\n");
			continue;
		}

		array[c].diff =
		    (long double) (end.tv_sec  - start.tv_sec ) +
		    (long double) (end.tv_nsec - start.tv_nsec) /
		    (long double) 1000000000;

		if (verbose >= 2) {
			if (array[c].diff >= s) {
				array[c].diff = s;
				printf("Timeout\n");
			} else if (array[c].diff < 1 && array[c].diff > 0) {
				print_sub_one(array[c].diff);
				printf("\n");
			} else {
				printf("%.9Lf\n", array[c].diff);
			}
		} else if (verbose <= 0 && array[c].diff < S) {
			S = array[c].diff;
			timeout.tv_sec = (time_t)(S + .125);
			timeout.tv_nsec =
			    (long) (((S + .125) -
			    (long double) timeout.tv_sec) *
			    (long double) 1000000000);

		} else if (array[c].diff > s)
			array[c].diff = s;
	}

	close(kq);

	if (dns_cache) {
		close(dns_cache_d_socket[1]);
		waitpid(dns_cache_d_pid, NULL, 0);
	}

	if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge, line: %d", __LINE__);

	/* (verbose == 0 || verbose == 1) */
	if ((verbose >> 1) == 0) {
		printf("\b \b");
		fflush(stdout);
	}
	close(std_err);
	free(line);

	if (verbose <= 0) {

		/*
		 * I chose to use a more efficient insertion sort
		 * pass instead of doing a qsort() to load the
		 * fastest mirror data into array[0] since the
		 * rest of the data in the array is not used.
		 */

		MIRROR *fastest = ac = array + array_length - 1;

		while (array <= --ac) {
			if (ac->diff < fastest->diff)
				fastest = ac;
		}

		if (array != fastest) {

			free(array->label);
			free(array->http);

			memcpy(array, fastest, sizeof(MIRROR));

			memset(fastest, 0, sizeof(MIRROR));
		}

	} else {
		if (usa == 0) {
			qsort(array, array_length, sizeof(MIRROR),
			    diff_cmp_minus_usa);
		} else
			qsort(array, array_length, sizeof(MIRROR), diff_cmp);

		int  de = -1, ds = -1,   te = -1, ts = -1,   se = -1;

		c = array_length;
		do {

			if (array[--c].diff < s) {
				se = c;
				break;
			}

			if (array[c].diff > s) {
				if (de == -1)
					de = ds = c;
				else
					ds = c;
			} else {
				if (te == -1)
					te = ts = c;
				else
					ts = c;
			}

		} while (c);


		int first = 0, se0 = se;

		if (se == -1)
			goto no_good;

		if (generate == 0)
			goto generate_jump;

		free(diff_array);
	
		/*
		 * load diff with what will be printed http lengths
		 *          then process http for printing
		 */
		n = 1;
		ac = array + se;
		do {
			cut = ac->http += h;
			j = strlen(cut);

			if (j <= 12) {
				(ac->http -= 1)[0] = '*';
				ac->diff = j + 1;
			} else if (strcmp(cut += j -= 12, "/pub/OpenBSD")) {
				(ac->http -= 1)[0] = '*';
				ac->diff = j + 13;
			} else {
				*cut = '\0';
				ac->diff = j;
			}

			if (n) {

				cut = strchr(ac->http, '/');

				if (cut == NULL)
					cut = ac->http + (int)ac->diff;

				if (cut - ac->http > 12 &&
				    (
				     !strncmp(cut - 12, ".openbsd.org", 12)

				     ||

				     !strncmp(cut - 12, ".OpenBSD.org", 12)
				    )
				   )
					n = 0;
			}
		} while (array != ac--);



		if (n) {

			printf("Couldn't find any openbsd.org mirrors.\n");
			printf("Try again with a larger timeout!\n");

			ac = array + se0;
			do {
				if (ac->http[0] == '*')
					ac->http -= h - 1;
				else
					ac->http -= h;
			} while (array != ac--);

			free(time);

			return 1;
		}

		/*
		 * sort by longest length first, subsort http alphabetically
		 *           It makes it kinda look like a flower.
		 */
		qsort(array, se + 1, sizeof(MIRROR), diff_cmp_g);

		printf("\n\n");
		printf("                        ");
		printf("/* GENERATED CODE BEGINS HERE */\n\n\n");
		printf("        const char *ftp_list[%d] = {\n\n", se + 1);


		/* n = 0; */
		for (c = 0; c < se; ++c) {

			/*
			 *    3 is the size of the printed: "",
			 */

			if (((int)array[c].diff) + 3 > 80)
				printf("\"%s\",\n", array[first++].http);
			else
				break;
		}

		if (c == se)
			goto gen_skip1;
		
		for (; c <= se; ++c) {

			/*
			 *    3 is the size of the printed: "",
			 * if (c == se) it doesn't print the comma
			 */

			n += i = ((int)array[c].diff) + 3 - (c == se);

			/*
			 * overflow:
			 * mirrors printed on each line
			 * will not exceed 80 characters
			 */
			if (n > 80) {

				/* center the printed mirrors. Err to right */
				for (j = (81 - (n - i)) / 2; j > 0; --j)
					printf(" ");
				do {
					printf("\"%s\",", array[first].http);
				} while (++first < c);
				printf("\n");
				n = i;

			}
		}

		/* center the printed mirrors. Err to right */
		for (j = (81 - n) / 2; j > 0; --j)
			printf(" ");
		while (first < se)
			printf("\"%s\",", array[first++].http);
gen_skip1:
		printf("\"%s\"\n\n", array[se].http);

		printf("        };\n\n");
		printf("        const int index = %d;\n\n\n\n", se + 1);


		/*
		 * make non-openbsd.org mirrors: diff == 0
		 *   and stop them from being displayed
		 */
		ac = array + se;
		do {
			cut = strchr(ac->http, '/');
			if (cut == NULL)
				cut = ac->http + (int)ac->diff;
			if (cut - ac->http <= 12 ||
			    (
			     strncmp(cut - 12, ".openbsd.org", 12)

			     &&

			     strncmp(cut - 12, ".OpenBSD.org", 12)
			    )
			   ) {
				ac->diff = 0;
				--se;
			}
		} while (array != ac--);

		/* sort by longest length first,
		 * if diff > 0 then
		 * subsort http alphabetically
		 */
		qsort(array, se0 + 1, sizeof(MIRROR), diff_cmp_g2);

		printf("     /* Trusted OpenBSD.org subdomain ");
		printf("mirrors for generating this section */\n\n");
		printf("        const char *ftp_list_g[%d] = {\n\n", se + 1);


		n = 0;
		first = 0;

		for (c = 0; c < se; ++c) {

			/*
			 *    3 is the size of the printed: "",
			 */

			if (((int)array[c].diff) + 3 > 80)
				printf("\"%s\",\n", array[first++].http);
			else
				break;
		}

		if (c == se)
			goto gen_skip2;
		
		for (; c <= se; ++c) {

			/*
			 *    3 is the size of the printed: "",
			 * if (c == se) it doesn't print the comma
			 */

			n += i = ((int)array[c].diff) + 3 - (c == se);

			/*
			 * overflow:
			 * mirrors printed on each line
			 * will not exceed 80 characters
			 */
			if (n > 80) {

				/* center the printed mirrors. Err to right */
				for (j = (81 - (n - i)) / 2; j > 0; --j)
					printf(" ");
				do {
					printf("\"%s\",", array[first].http);
				} while (++first < c);
				printf("\n");
				n = i;
			}
		}

		/* center the printed mirrors. Err to right */
		for (j = (81 - n) / 2; j > 0; --j)
			printf(" ");
		while (first < se)
			printf("\"%s\",", array[first++].http);
gen_skip2:
		printf("\"%s\"\n\n", array[se].http);

		printf("        };\n\n");
		printf("        const int index_g = %d;\n\n\n", se + 1);
		printf("                         ");
		printf("/* GENERATED CODE ENDS HERE */\n\n\n\n");
		printf("Replace section after line: %d, but ", entry_line);
		printf("before line: %d with the code above.\n\n", exit_line);

		ac = array + se0;
		do {
			if (ac->http[0] == '*')
				ac->http -= h - 1;
			else
				ac->http -= h;
		} while (array != ac--);

		free(time);

		return 0;

generate_jump:

		if (de != -1)
			printf("\n\nDOWNLOAD ERROR MIRRORS:\n\n");
		else if (te != -1)
			printf("\n\nTIMEOUT MIRRORS:\n\n");
		else
			printf("\n\nSUCCESSFUL MIRRORS:\n\n");
			
		int diff_topper = 0;
		i = 1;
		while (array[se].diff >= i) {
			i *= 10;
			if (++diff_topper == 4)
				break;
		}
		
		char *dt_str = strndup("    ", diff_topper);
		if (dt_str == NULL)
			errx(1, "strndup");
		
		ac = array + se;
		pos_maxl = strlen(ac->label);
	
		while (array != ac--) {
			pos = strlen(ac->label);
			if (pos > pos_maxl)
				pos_maxl = pos;
		}
		
		
		int pos_maxt = 0;
		
		if (te != -1) {
			for (c = te; c >= ts; --c) {
				pos = strlen(array[c].label);
				if (pos > pos_maxt)
					pos_maxt = pos;
			}
		}
		
		
		int pos_maxd = 0;

		if (de != -1) {
			for (c = de; c >= ds; --c) {
				pos = strlen(array[c].label);
				if (pos > pos_maxd)
					pos_maxd = pos;
			}
		}
		
		c = array_length;
		ac = array + c;

		while (array != ac--) {

			if (array_length >= 100)
				printf("\n%3d : ", c);
			else
				printf("\n%2d : ", c);

			i = strlen(ac->label);
			
			if (--c <= se) {

				j = (pos_maxl + 1 - i) / 2;
				n = pos_maxl - (i + j);
				while (j--)
					printf(" ");

				printf("%s", ac->label);
				
				while (n--)
					printf(" ");
					
				printf(" : ");

				if (ac->diff < 1 && array[c].diff > 0) {
					printf("%s", dt_str);
					print_sub_one(ac->diff);
				} else {
					switch (diff_topper) {
					case 1:
						printf("%1.9Lf", ac->diff);
						break;
					case 2:
						printf("%2.9Lf", ac->diff);
						break;
					case 3:
						printf("%3.9Lf", ac->diff);
						break;
					default:
						printf("%4.9Lf", ac->diff);
						break;
					}
				}
				printf(" seconds\n        echo \"");
				printf("%s", ac->http);
				printf("\" > /etc/installurl\n");
				continue;
			}
			
			cut = strchr(ac->http + h, '/');
			if (cut)
				*cut = '\0';
			
			if (c <= te) {
				
				j = (pos_maxt + 1 - i) / 2;
				n = pos_maxt - (i + j);
				
				while (j--)
					printf(" ");

				printf("%s", ac->label);
				
				while (n--)
					printf(" ");
				
				printf(" : ");
				printf("Timeout\n        %s\n", ac->http + h);

				if (c == ts && se != -1)
					printf("\n\nSUCCESSFUL MIRRORS:\n\n");
				continue;
			}

			j = (pos_maxd + 1 - i) / 2;
			n = pos_maxd - (i + j);
			
			while (j--)
				printf(" ");

			printf("%s", ac->label);
			
			while (n--)
				printf(" ");
			
			printf(" : ");
			
			if (ac->diff == s + 1)
				printf("Download Error");
			else if (ac->diff == s + 2)
				printf("IPv6 DNS record not found");
			else if (ac->diff == s + 3)
				printf("DNS record not found");
			else
				printf("BLOCKED subdomain!");

			
			printf("\n        %s\n", ac->http + h);


			if (c == ds) {
				if (te != -1)
					printf("\n\nTIMEOUT MIRRORS:\n\n");
				else if (se != -1)
					printf("\n\nSUCCESSFUL MIRRORS:\n\n");
			}
		}
		free(dt_str);
	}
	
	free(diff_array);

	if (array->diff >= s) {

no_good:

		printf("No successful mirrors found.\n\n");

		if (next) {
			printf("Perhaps the next release ");
			printf("(%s) isn't available?\n", release);
		} else if (previous) {
			printf("Perhaps the previous release ");
			printf("(%s) isn't available?\n", release);
		} else if (current == 0 && generate == 0 && override) {
			printf("You are probably seeking to use ");
			printf("the -p flag instead of -O flag ");
			printf("since the %s release ", release);
			printf("doesn't seem to be available.\n");
		} else if (current == 0 && generate == 0) {
			printf("You are probably running a snapshot, but it ");
			printf("is indicating that you are running a release.");
			printf(" You should use the -O flag in that case.\n");
		}
		if (six) {
			printf("If your dns system is not set up ");
			printf("for IPv6 connections, then ");
			printf("lose the -6 flag.\n\n");
		}

		if (s_set == 0) {
			printf("Perhaps try the -s ");
			printf("option to choose a timeout");
			printf(" larger than the default: -s %s\n", time);
		} else
			printf("Perhaps try with a larger -s than %s\n", time);

		free(time);
		free(release);

		return 1;
	}

	free(time);
	free(release);

	if (to_file) {

		n = strlen(array->http);

		i = write(write_pipe[STDOUT_FILENO], array->http, n);

		if (i < n) {
			printf("\nnot all of mirror sent to write_pid\n");
			restart(argc, argv, loop, verbose);
		}

		waitpid(write_pid, &n, 0);

		if (n) {
			printf("\nwrite_pid error.\n");
			restart(argc, argv, loop, verbose);
		}

	} else if ((!root_user && verbose != -1) || (root_user && !verbose)) {
		if (verbose)
			printf("\n");
		printf("As root, type: echo ");
		printf("\"%s\" > /etc/installurl\n", array->http);
	}

	return 0;
}
