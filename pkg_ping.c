/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2016 - 2021, Luke N Small, lukensmall@gmail.com
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
 * 	Originally used this idea from "Dan Mclaughlin" on misc@
 * 	   
 *
 * 	    ftp -o - http://www.openbsd.org/ftp.html | \
 * 	    sed -n \
 * 	     -e 's:</a>$::' \
 * 	         -e 's:  <strong>\([^<]*\)<.*:\1:p' \
 * 	         -e 's:^\(       [hfr].*\):\1:p'
 * 
 * 
 * 	     I still don't know what all of that means.
 */

/*
 *	indent pkg_ping.c -bap -br -ce -ci4 -cli0 -d0 -di0 -i8 \
 *	-ip -l79 -nbc -ncdb -ndj -ei -nfc1 -nlp -npcs -psl -sc -sob
 *
 *	cc pkg_ping.c -o pkg_ping
 * 
 * 	If you want bleeding edge performance, you can try:
 * 
 * 	cc pkg_ping.c -march=native -mtune=native -O3 -pipe -o pkg_ping
 * 
 * 	You probably won't see an appreciable performance gain between
 * 	the getaddrinfo(3) and the ftp(1) calls which fetch data over the 
 * 	network. I parallelize somewhat.
 * 
 * 	program designed to be viewed with width 8 tabs
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

int8_t h = 0;

struct mirror_st {
	char *label;
	char *http;
	long double diff;
};

int array_length = 0;
struct mirror_st *array = NULL;

static void
free_array()
{
	while (--array_length >= 0) {
		free(array[array_length].label);
		free(array[array_length].http);
	}
	free(array);
	array = NULL;
}

static int
usa_cmp(const void *a, const void *b)
{
	/* list the USA mirrors first */
	int8_t temp = (strstr(((struct mirror_st *) a)->label, "USA") != NULL);
	if (temp != (strstr(((struct mirror_st *) b)->label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}
	return 0;
}

static int
diff_cmp0(const void *a, const void *b)
{
	long double one_diff = ((struct mirror_st *) a)->diff;
	long double two_diff = ((struct mirror_st *) b)->diff;

	if (one_diff < two_diff)
		return -1;
	if (one_diff > two_diff)
		return 1;
	return 0;
}

static int
label_cmp_minus_usa(const void *a, const void *b)
{
	
	char *one_label = ((struct mirror_st *) a)->label;
	char *two_label = ((struct mirror_st *) b)->label;
	int8_t i = 3;
		
	/* 
	 * compare the labels alphabetically by proper decreasing
	 * hierarchy which are in reverse order between commas.
	 */
	 
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
		 * search for a comma before the
		 * one found in the previous iteration
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
		/* 
		 * if (i):
		 * One of red or blue has no more comma
		 * separated entries while remaining, equal.
		 * The one with fewer commas is preferred.
		 * If red: i == 1, if blue: i == 2
		 */
		if (i == 1)
			return -1;
		if (i == 2)
			return 1;
		
		
		/* 
		 * exactly equal labels:
		 * The price of checking for this initially,
		 * (although its a simple strcmp())
		 * likely isn't worth it because of its rarity.
		 */
		return strcmp(
			      ((struct mirror_st *) a)->http + h,
			      ((struct mirror_st *) b)->http + h
			     );
	}
	return ret;
}

static int
diff_cmp_minus_usa(const void *a, const void *b)
{
	long double one_diff = ((struct mirror_st *) a)->diff;
	long double two_diff = ((struct mirror_st *) b)->diff;

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
	long double one_diff = ((struct mirror_st *) a)->diff;
	long double two_diff = ((struct mirror_st *) b)->diff;

	if (one_diff < two_diff)
		return -1;
	if (one_diff > two_diff)
		return 1;

	/* list the USA mirrors first */
	int8_t temp = (strstr(((struct mirror_st *) a)->label, "USA") != NULL);
	if (temp != (strstr(((struct mirror_st *) b)->label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}

	/* reverse subsort label_cmp_minus_usa */
	return label_cmp_minus_usa(b, a);
}

static int
diff_cmp_g(const void *a, const void *b)
{
	long double one_diff = ((struct mirror_st *) a)->diff;
	long double two_diff = ((struct mirror_st *) b)->diff;

	/* sort the biggest diff values first */
	if (one_diff > two_diff)
		return -1;
	if (one_diff < two_diff)
		return 1;
		
	return strcmp(
		      ((struct mirror_st *) a)->http,
		      ((struct mirror_st *) b)->http
		     );
}

static int
diff_cmp_g2(const void *a, const void *b)
{
	long double one_diff = ((struct mirror_st *) a)->diff;
	long double two_diff = ((struct mirror_st *) b)->diff;

	/* sort the biggest diff values first */
	if (one_diff > two_diff)
		return -1;
	if (one_diff < two_diff)
		return 1;
	
	/* 
	 * both diffs will be equal here and most of
	 *      the time will be equal to zero.
	 *        if they are zero, the http
	 *       comparison isn't interesting.
	 */
	if (one_diff) {
		return strcmp(
			      ((struct mirror_st *) a)->http,
			      ((struct mirror_st *) b)->http
			     );
	}
	return 0;
}

static int
label_cmp(const void *a, const void *b)
{
	/* list the USA mirrors first */
	int8_t temp = (strstr(((struct mirror_st *) a)->label, "USA") != NULL);
	if (temp != (strstr(((struct mirror_st *) b)->label, "USA") != NULL)) {
		if (temp)
			return -1;
		return 1;
	}
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

	printf("[-l (ell) quantity of Loop attempts");
	printf(" for an 'ftplist' download error\n");
	printf("\t(If left unspecified it will permit 20 restarts)]\n");

	printf("[-O (if your OS is a snapshot, it will Override it and\n");
	printf("\tsearch for release mirrors. if your OS is a release,\n");
	printf("\tit will Override it and search for snapshot mirrors.)\n");

	printf("[-n (search for mirrors with the next release!)]\n");

	printf("[-s timeout in Seconds (eg. -s 2.3)]\n");

	printf("[-S (converts http mirrors into Secure https mirrors\n");
	printf("\thttp mirrors still preserve file integrity!)]\n");

	printf("[-u (no USA mirrors to comply ");
	printf("with USA encryption export laws)]\n");

	printf("[-v (increase Verbosity. It recognizes up to 4 of these)]\n");

	printf("[-V (no Verbose output. No output but error messages)]\n\n");
	
	
	printf("More information at: ");
	printf("https://github.com/lukensmall/pkg_ping\n\n");
	
}

static int
dns_cache_d(const int dns_cache_d_socket[], const int8_t secure,
	    const int8_t six, const int8_t verbose)
{
	if (pledge("stdio dns", NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("dns_cache_d pledge, line: %d\n", __LINE__);
		_exit(1);
	}
	
	close(dns_cache_d_socket[1]);
	
	
	int i = 0, c = 0, dns_socket = dns_cache_d_socket[0];
				  
	uint8_t dns_line_max = 0;
	struct addrinfo *res0 = NULL, *res = NULL;
	
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	
	struct sockaddr_in *sa4 = NULL;
	uint32_t sui4 = 0;

	struct sockaddr_in6 *sa6 = NULL;
	unsigned char *suc6 = NULL;

	int8_t max = 0, i_temp = 0, i_max = 0;
	char six_available = '0';
	
	char *dns_line0 = NULL, *dns_line = NULL;


	char hexadec[16] = { '0','1','2','3',
			     '4','5','6','7',
			     '8','9','a','b',
			     'c','d','e','f' };
	
	if (secure)
		dns_line0 = "https";
	else
		dns_line0 = "http";

	i = read(dns_socket, &dns_line_max, 1);
	if (i < 1) {
		_exit(1);
	}

	dns_line = calloc(dns_line_max + 1, sizeof(char));
	if (dns_line == NULL) {
		printf("calloc\n");
		_exit(1);
	}
	
	if (0) {
dns_loop:
		memset(&hints, 0, sizeof(struct addrinfo));
	}
	
	i = read(dns_socket, dns_line, dns_line_max + 1);
	if (i == 0) {
		free(dns_line);
		_exit(0);
	}

	if (i > dns_line_max) {
		printf("i > dns_line_max, line: %d\n", __LINE__);
		goto dns_exit1;
	}
	
	if (i < 0) {
		printf("%s ", strerror(errno));
		printf("read error line: %d\n", __LINE__);
		goto dns_exit1;
	}
	dns_line[i] = '\0';

	if (verbose == 4)
		printf("DNS caching: %s\n", dns_line);


	hints.ai_flags = AI_FQDN;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	c = getaddrinfo(dns_line, dns_line0, &hints, &res0);
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

	if (verbose < 4 && !six) {
		for (res = res0; res; res = res->ai_next) {
			if (res->ai_family == AF_INET ||
			    res->ai_family == AF_INET6)
				break;
		}
		if (res == NULL)
			i = write(dns_socket, "f", 1);
		else
			i = write(dns_socket, "1", 1);
			
		if (i < 1) {
			printf("%s ", strerror(errno));
			printf("write error line: %d\n", __LINE__);
			goto dns_exit1;
		}
		freeaddrinfo(res0);
		goto dns_loop;
	}

	six_available = 'f';

	for (res = res0; res; res = res->ai_next) {

		if (res->ai_family == AF_INET) {
			if (six_available == 'f')
				six_available = '0';
			if (six)
				continue;
			sa4 = (struct sockaddr_in *) res->ai_addr;
			sui4 = sa4->sin_addr.s_addr;
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

		/* load largest >1 gap beginning into i_max */
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
		 *                  ">> 4" == "/ 16"
		 *              "max << 1" == "2 * max"
		 *            "& 15" == "& 0x0f" == "% 16"
		 *  'i' is even so I can use "i|1" instead of "i+1",
		 * which may be more efficient. I think it's prettier
		 */
		for (i = 0; i < 16; i += 2) {

			if (i == i_max) {
				if (i == 0)
					printf("::");
				else
					printf(":");
				i += max << 1;
				if (i >= 16)
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
			
			if (i < 14)
				printf(":");
		}
		printf("\n");
	}
	freeaddrinfo(res0);

	i = write(dns_socket, &six_available, 1);

	if (i < 1) {
		printf("%s ", strerror(errno));
		printf("write error line: %d\n", __LINE__);
		goto dns_exit1;
	}

	goto dns_loop;
	
dns_exit1:

	free(dns_line);
	_exit(1);
}

/*
 * I considered keeping this functionality in main(), but
 * if there's a possibility of the main() getting overrun,
 * this process performs some sanity checks to, among
 * other things, prevent /etc/installurl from becoming a
 * massive file which fills up the partition.
 */
static int
file_d(const int write_pipe[], const int dns_socket,
       const int8_t secure, const int8_t verbose)
{

	if (pledge("stdio cpath wpath", NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("pledge, line: %d\n", __LINE__);
		_exit(1);
	}
	
	int i = 0;
	int kq = kqueue();
	if (kq == -1) {
		printf("%s ", strerror(errno));
		printf("kq! line: %d\n", __LINE__);
		_exit(1);
	}
	
	char *file_w = NULL;
	FILE *pkg_write = NULL;
	
	struct kevent ke;
	memset(&ke, 0, sizeof(ke));
	
	close(write_pipe[STDOUT_FILENO]);

	close(dns_socket);


	
	
	/* 
	 * It probably seems like overkill to use a kqueue for
	 * a single file descriptor with no timeout, but I 
	 * don't have to guess about how much data will
	 * be sent down the pipe. I can allocate the perfect
	 * amount of buffer space AFTER the pipe receives it.
	 */
	EV_SET(&ke, write_pipe[STDIN_FILENO], EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	if (kevent(kq, &ke, 1, &ke, 1, NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("write_pid kevent register fail");
		printf(" line: %d\n", __LINE__);
		close(kq);
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
	
	if (verbose >= 1)
		printf("\n");

	/* unlink() to prevent possible symlinks by...root? */
	unlink("/etc/installurl");
	pkg_write = fopen("/etc/installurl", "w");

	if (pkg_write == NULL) {
		printf("%s ", strerror(errno));
		printf("/etc/installurl not opened.\n");
		_exit(1);
	}

	if (pledge("stdio", NULL) == -1) {
		printf("%s ", strerror(errno));
		printf("pledge, line: %d\n", __LINE__);
		fclose(pkg_write);
		_exit(1);
	}
	
	file_w = calloc(received + 1 + 1, sizeof(char));
	if (file_w == NULL) {
		printf("calloc\n");
		fclose(pkg_write);
		_exit(1);
	}
		
	i = read(write_pipe[STDIN_FILENO], file_w, received);
	close(write_pipe[STDIN_FILENO]);

	if (i < 0) {
		printf("%s ", strerror(errno));
		printf("read error occurred, line: %d\n", __LINE__);
		free(file_w);
		fclose(pkg_write);
		_exit(1);
	}

	if (i < received) {
		printf("didn't fully read from pipe, ");
		printf("line: %d\n", __LINE__);
		free(file_w);
		fclose(pkg_write);
		_exit(1);
	}
	
	memcpy(file_w + received, "\n", 1 + 1);

	if (secure == 1) {
		if (strncmp(file_w, "https://", 8) != 0) {
			printf("file_w does't begin with ");
			printf("\"https://\", line: %d\n", __LINE__);
			free(file_w);
			fclose(pkg_write);
			_exit(1);
		}
	} else {
		if (strncmp(file_w, "http://", 7) != 0) {
			printf("file_w does't begin with ");
			printf("\"http://\", line: %d\n", __LINE__);
			free(file_w);
			fclose(pkg_write);
			_exit(1);
		}
	}

	i = fwrite(file_w, 1, received + 1, pkg_write);
	if (i < received + 1) {
		printf("%s ", strerror(errno));
		printf("write error occurred, line: %d\n", __LINE__);
		free(file_w);
		fclose(pkg_write);
		_exit(1);
	}
	
	fclose(pkg_write);

	if (verbose >= 0)
		printf("/etc/installurl: %s", file_w);
	
	free(file_w);

	_exit(0);
}


int
main(int argc, char *argv[])
{
	int8_t root_user = (getuid() == 0);
	int8_t to_file = root_user;
	int8_t num = 0, current = 0, secure = 0, verbose = 0;
	int8_t generate = 0, override = 0, six = 0, next = 0, s_set = 0;
	int8_t dns_cache = 1, usa = 1;
	int16_t loop = 20;
	long double S = 0;
	pid_t ftp_pid = 0, write_pid = 0, dns_cache_d_pid = 0;
	int kq = 0, i = 0, pos = 0, c = 0, n = 0;
	int array_max = 0, tag_len = 0;
	int pos_max = 0, std_err = 0, entry_line = 0, exit_line = 0;
	
	int dns_cache_d_socket[2] = { -1, -1 };
	int         write_pipe[2] = { -1, -1 };
	int            ftp_out[2] = { -1, -1 };
	int         block_pipe[2] = { -1, -1 };
	
	struct timespec start = { 0, 0 }, end = { 0, 0 }, timeout = { 0, 0 };
	char *line_t = NULL, *line0 = NULL, *line = NULL, *release = NULL;
	char *tag = NULL, *time = NULL;
	size_t len = 0;
	char v = '\0';
	
	struct kevent ke;
	memset(&ke, 0, sizeof(ke));

	/* 5 second default mirror timeout */
	long double s = 5;

	/* 10 seconds and 0 nanoseconds to download ftplist */
	struct timespec timeout0 = { 10, 0 };
	
	/* .05 seconds for an ftp SIGINT to turn into a SIGKILL */
	const struct timespec timeout_kill = { 0, 50000000 };
		    
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
		if (strlen(argv[i]) >= 25)
			errx(1, "keep argument length under 25");
	}


	while ((c = getopt(argc, argv, "6dfghl:OnSs:uvV")) != -1) {
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
				printf("-l value should be less ");
				printf("than 5 digits long.\n");
				return 1;
			}
			
			c = loop = 0;
			do {
				if (optarg[c] < '0' || optarg[c] > '9') {
					printf("-l value should only have ");
					printf("numeric characters\n");
					return 1;
				}
				loop = loop * 10 + optarg[c] - '0';
			} while (optarg[++c] != '\0');
			break;
		case 'O':
			override = 1;
			break;
		case 'n':
			next = 1;
			break;
		case 'S':
			secure = 1;
			break;
		case 's':
			if (!strcmp(optarg, "."))
				errx(1, "-s should not be: \".\"");
			
			c = i = 0;
			do {
				if (optarg[c] >= '0' && optarg[c] <= '9')
					continue;
				if (optarg[c] == '.' && ++i == 1)
					continue;

				printf("-s value should have only numeric ");
				printf("characters and a maximum ");
				printf("of one decimal point\n");
				return 1;
			} while (optarg[++c] != '\0');

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
		dns_cache = 1;
		next = 0;
		override = 0;
		to_file = 0;
		if (pledge("stdio exec proc dns id", NULL) == -1)
			err(1, "pledge, line: %d", __LINE__);
			
		/* change default 's' value if not specified */
		if (time == NULL)
			s = 10;
	}
	
	if (s > 1000)
		errx(1, "try an -s less than or equal to 1000");
	if (s < 0.015625)
		errx(1, "try an -s greater than or equal to 0.015625 (1/64)");
	

		
	if (dns_cache == 0 && verbose == 4)
		verbose = 3;


	if (dns_cache == 1) {

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, dns_cache_d_socket) == -1)
			err(1, "socketpair, line: %d\n", __LINE__);

		dns_cache_d_pid = fork();
		switch(dns_cache_d_pid) {
			case -1:
				err(1, "dns_cache_d fork, line: %d\n",
				    __LINE__);
			case 0:
				dns_cache_d(dns_cache_d_socket, secure,
				    six, verbose);
				errx(1, "dns_cache_d returned! line: %d\n",
				    __LINE__);
		}
		
		close(dns_cache_d_socket[0]);
	}

	if (to_file == 1) {

		if (pipe2(write_pipe, O_CLOEXEC) == -1)
			err(1, "pipe2, line: %d", __LINE__);

		write_pid = fork();
		switch(write_pid) {
			case -1:
				err(1, "file_d fork, line: %d\n", __LINE__);
			case 0:
				file_d(write_pipe, dns_cache_d_socket[1],
				    secure, verbose);
				errx(1, "file_d returned! line: %d\n",
				    __LINE__);
		}
		
		close(write_pipe[STDIN_FILENO]);
	}


	if (root_user == 1) {
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

	
		
		if (root_user == 1) {
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
		line = calloc(n, sizeof(char));
		if (line == NULL) {
			printf("calloc\n");
			_exit(1);
		}
		
		entry_line = __LINE__;


		/* GENERATED CODE BEGINS HERE */


		const char *ftp_list[55] = {

         "openbsd.mirror.netelligent.ca","mirrors.syringanetworks.net",
          "openbsd.mirror.constant.com","plug-mirror.rcac.purdue.edu",
           "cloudflare.cdn.openbsd.org","ftp.halifax.rwth-aachen.de",
           "ftp.rnl.tecnico.ulisboa.pt","mirror.csclub.uwaterloo.ca",
   "mirror.hs-esslingen.de","mirrors.pidginhost.com","openbsd.cs.toronto.edu",
    "*artfiles.org/openbsd","mirror.bytemark.co.uk","mirror.planetunix.net",
     "www.mirrorservice.org","ftp4.usa.openbsd.org","mirror.aarnet.edu.au",
      "mirror.exonetric.net","openbsd.c3sl.ufpr.br","ftp.usa.openbsd.org",
       "ftp2.eu.openbsd.org","mirror.leaseweb.com","mirrors.gigenet.com",
         "ftp.eu.openbsd.org","ftp.fr.openbsd.org","mirror.fsmg.org.nz",
         "mirror.ungleich.ch","mirrors.dotsrc.org","openbsd.ipacct.com",
"ftp.hostserver.de","ftp.man.poznan.pl","mirrors.sonic.net","mirrors.ucr.ac.cr",
   "mirror.labkom.id","mirror.litnet.lt","mirror.yandex.ru","cdn.openbsd.org",
    "ftp.OpenBSD.org","ftp.jaist.ac.jp","mirror.esc7.net","mirror.vdms.com",
      "mirrors.mit.edu","ftp.icm.edu.pl","mirror.one.com","ftp.cc.uoc.gr",
 "ftp.heanet.ie","ftp.spline.de","www.ftp.ne.jp","ftp.eenet.ee","ftp.nluug.nl",
       "ftp.riken.jp","ftp.bit.nl","ftp.fau.de","ftp.fsn.hu","openbsd.hk"

		};

		const uint16_t index = 55;



		/* Trusted OpenBSD.org domain mirrors */

		const char *ftp_list_g[8] = {

   "cloudflare.cdn.openbsd.org","ftp4.usa.openbsd.org","ftp.usa.openbsd.org",
        "ftp2.eu.openbsd.org","ftp.eu.openbsd.org","ftp.fr.openbsd.org",
                       "cdn.openbsd.org","ftp.OpenBSD.org"

		};

		const uint16_t index_g = 8;


		/* GENERATED CODE ENDS HERE */


		exit_line = __LINE__;


		c = ftp_out[STDOUT_FILENO];
		
		if (generate) {		

		/*
		 * I can't think of a better way to retrieve these two values.
		 * I refuse to change it every time I edit the code.
		 * It probably preserves some memory in the parent process
		 * by having *ftp_list[] here in the fork()ed ftp declaration
		 */
		
			errno = 0;
			i = write(c, &entry_line, sizeof(int));
			if (i < (int)sizeof(int)) {
				if (errno)
					printf("%s ", strerror(errno));
				printf("ftp write, line: %d\n", __LINE__);
				_exit(1);
			}
			i = write(c, &exit_line, sizeof(int));
			if (i < (int)sizeof(int)) {
				if (errno)
					printf("%s ", strerror(errno));
				printf("ftp write, line: %d\n", __LINE__);
				_exit(1);
			}
			
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
				printf("snprintf error ");
			printf("'line' length >= %d, line: %d\n", i, __LINE__);
			_exit(1);
		}
		
		if (verbose >= 2)
			printf("%s\n", line);
		else if (verbose >= 0) {
			printf("$");
			fflush(stdout);
		}


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
	
	
	S = (long double) timeout0.tv_sec +
	    (long double) timeout0.tv_nsec /
	    (long double) 1000000000;

	if (s > S) {
		timeout0.tv_sec = (time_t) s;
		timeout0.tv_nsec =
		    (long) ((s - (long double) timeout0.tv_sec) *
		    (long double) 1000000000);
	}
	
	S = s;
	
	if (time == NULL) {
		n = 20;
		time = calloc(n, sizeof(char));
		if (time == NULL) {
			kill(ftp_pid, SIGINT);
			errx(1, "calloc");
		}
		i = snprintf(time, n, "%Lf", s);
		if (i >= n || i < 0) {
			kill(ftp_pid, SIGINT);
			errx(1, "snprintf, line: %d", __LINE__);
		}
	} else
		s_set = 1;
	
	/* eliminate extra zeroes after decimal point in 'time' */
	if (strchr(time, '.') != NULL) {
		i = 0;
		n = strlen(time);
		while (time[--n] == '0')
			i = n;
			
		if (time[n] == '.')
			i = n;
			
		if (i > 0) {
			char *time0 = time;
			time[i] = '\0';
			time = strdup(time0);
			if (time == NULL) {
				kill(ftp_pid, SIGINT);
				errx(1, "strdup");
			}
			free(time0);
		}
	}

	c = ftp_out[STDIN_FILENO];

	if (next == 1) {
		if (verbose >= 2)
			printf("showing the next release availability!\n\n");
	} else if (generate == 0) {
		const int mib[2] = { CTL_KERN, KERN_VERSION };
	
		/* retrieve length of results of "sysctl kern.version" */
		if (sysctl(mib, 2, NULL, &len, NULL, 0) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);		
			printf("sysctl, line: %d", __LINE__);
			return 1;
		}
		
		line = calloc(len, sizeof(char));
		if (line == NULL) {
			kill(ftp_pid, SIGINT);		
			errx(1, "calloc");
		}
			
		/* read results of "sysctl kern.version" into 'line' */
		if (sysctl(mib, 2, line, &len, NULL, 0) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);		
			printf("sysctl, line: %d", __LINE__);
			return 1;
		}

		/* Discovers if the kernel is not a release version */
		if (strstr(line, "current") || strstr(line, "beta"))
			current = 1;
		
		free(line);

		if (override == 1)
			current = !current;
			
		if (verbose >= 2) {
			if (current == 1) 
				printf("showing snapshot mirrors\n\n");
			else
				printf("showing release mirrors\n\n");
		}
	}
	
	if (generate == 1) {
		
		tag = strdup("/timestamp");
		if (tag == NULL) {
			kill(ftp_pid, SIGINT);
			errx(1, "strdup");
		}

		tag_len = strlen(tag);

		i = read(c, &entry_line, sizeof(int));
		if ((ulong)i < sizeof(int)) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);
			printf("read, line: %d", __LINE__);
			return 1;
		}
			
		i = read(c, &exit_line, sizeof(int));
		if ((ulong)i < sizeof(int)) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);
			printf("read, line: %d", __LINE__);
			return 1;
		}
		
	} else {
		
		struct utsname *name = calloc(1, sizeof(struct utsname));
		    
		if (name == NULL) {
			kill(ftp_pid, SIGINT);
			errx(1, "calloc");
		}
		
		
		if (uname(name) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);
			printf("uname, line: %d", __LINE__);
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
			kill(ftp_pid, SIGINT);
			errx(1, "strdup");
		}
		
		if (next && i) {
			
			n = strlen(release) + 1;
			i = snprintf(release, n, "%.1f", atof(release) + .1);
			    
			if (i >= n || i < 0) {
				kill(ftp_pid, SIGINT);
				printf("release: %s, ", release);
				printf("snprintf, line: %d\n", __LINE__);
				return 1;
			}
		}


		if (current == 1) {
			tag_len = strlen("/snapshots/") +
			    strlen(name->machine) + strlen("/SHA256");
		} else {
			tag_len = strlen("/") + strlen(release) + strlen("/") +
			    strlen(name->machine) + strlen("/SHA256");
		}
		
		tag = calloc(tag_len + 1, sizeof(char));
		if (tag == NULL) {
			kill(ftp_pid, SIGINT);
			errx(1, "calloc");
		}

		if (current == 1)
			sprintf(tag, "/snapshots/%s/SHA256", name->machine);
		else
			sprintf(tag, "/%s/%s/SHA256", release, name->machine);

		free(name);
	}
	
	
	/* if the index for line[] can exceed 254, it will error out */
	line = calloc(255, sizeof(char));
	if (line == NULL) {
		kill(ftp_pid, SIGINT);
		errx(1, "calloc");
	}

	array_max = 100;
	array = calloc(array_max, sizeof(struct mirror_st));
	if (array == NULL) {
		kill(ftp_pid, SIGINT);
		errx(1, "calloc");
	}
	
	atexit(free_array);


	h = strlen("http://");


	kq = kqueue();
	if (kq == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGINT);
		printf("kq! line: %d", __LINE__);
		return 1;
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
		kill(ftp_pid, SIGINT);
		printf("kevent, timeout0 may be too large. ");
		printf("line: %d\n", __LINE__);
		return 1;
	}
	
	if (i == 0) {
		kill(ftp_pid, SIGINT);
		free(line);
		
		/* (verbose == 0 || verbose == 1) */
		if ((verbose >> 1) == 0)
			printf("\b");
	
		goto restart_program;
	}

	while (read(c, &v, 1) == 1) {
		if (pos >= 253) {
			kill(ftp_pid, SIGINT);
			line[pos] = '\0';
			printf("'line': %s\n", line);
			printf("pos got too big! line: %d\n", __LINE__);
			return 1;
		}
		
		if (num == 0) {

			if (v != ' ') {
				line[pos++] = v;
				continue;
			}
			line[pos++] = '\0';
			
			/* safety check */
			if (strncmp(line, "http://", h)) {
				kill(ftp_pid, SIGINT);
				printf("'line': %s\n", line);
				printf("bad http format, line: %d\n", __LINE__);
				return 1;
			}				

			if (secure)
				++pos;

			if (pos_max < pos)
				pos_max = pos;

			array[array_length].http = calloc(pos, sizeof(char));
			if (array[array_length].http == NULL) {
				kill(ftp_pid, SIGINT);
				errx(1, "calloc");
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
		
		/* 
		 * safety check for label_cmp_minus_usa():
		 * make sure there is a space after last comma
		 * which would allow the function to make the
		 * assumption that 2 spaces after the comma is
		 * on the array. Otherwise, an abberrant
		 * label could crash the program.
		 * 
		 * I could make the label function safer,
		 * but it would eat up more computing resources
		 * being redundantly and repeatedly checked.
		 */
		if (verbose >= 1) {
			line_t = strrchr(line, ',');
			if (line_t != NULL && line_t[1] != ' ') {
				kill(ftp_pid, SIGINT);
				printf("label malformation: ");
				printf("%s\n", line);
				free(array[array_length].http);
				return 1;
			}
		}
		
		array[array_length].label = strdup(line);
		if (array[array_length].label == NULL) {
			kill(ftp_pid, SIGINT);
			free(array[array_length].http);
			errx(1, "strdup");
		}


		if (++array_length >= array_max) {
			array_max += 20;
			array = reallocarray(array, array_max,
			    sizeof(struct mirror_st));

			if (array == NULL) {
				kill(ftp_pid, SIGINT);
				errx(1, "reallocarray");
			}
		}

		pos = num = 0;
	}

	free(line);

	close(ftp_out[STDIN_FILENO]);

	waitpid(ftp_pid, &n, 0);

	/* (verbose == 0 || verbose == 1) */
	if ((verbose >> 1) == 0) {
		printf("\b \b");
		fflush(stdout);
	}

	/* 
	 *             'ftplist' download error:
	 * It's caused by no internet, bad dns resolution;
	 *   Or from a faulty mirror or its bad dns info
	 */
	if (n != 0 || array_length == 0) {
			
		
		if (verbose >= 0)
			printf("There was an 'ftplist' download error.\n");

restart_program:

		if (loop-- == 0) {
			if (verbose >= 0)
				printf("Looping exhausted: Try again.\n");
			return 2;
		}
		
		close(kq);
		free(time);
		free(release);
		if (verbose >= 0)
			printf("restarting...\n");
			
		free_array();
			
		n = argc - (argc > 1 && !strncmp(argv[argc - 1], "-l", 2));
		
		char **arg_v = calloc(n + 1 + 1, sizeof(char *));
		if (arg_v == NULL)
			errx(1, "calloc");
			
		for (i = 0; i < n; ++i)
			arg_v[i] = argv[i];
		
		int n_len = 10;
		arg_v[n] = calloc(n_len, sizeof(char));
		if (arg_v[n] == NULL)
			errx(1, "calloc");
		c = snprintf(arg_v[n], n_len, "-l%d", loop);
		if (c >= n_len || c < 0)
			errx(1, "snprintf, line: %d", __LINE__);
			
			
		execv(arg_v[0], arg_v);

		err(1, "execv failed, line: %d", __LINE__);
	}

	if (secure == 1)
		h = strlen("https://");


	if (dns_cache) {
		uint8_t length = pos_max - h;
		i = write(dns_cache_d_socket[1], &length, 1);
		if (i < 1) {
			if (errno == EPIPE)
				printf("dns_cache_d died prematurely\n");
			else
				printf("'length' not sent to dns_cache_d\n");
			goto restart_program;
		}
	}
	
	pos_max += tag_len;

	line = calloc(pos_max, sizeof(char));
	if (line == NULL)
		errx(1, "calloc");


	array = reallocarray(array, array_length, sizeof(struct mirror_st));
	    
	if (array == NULL)
		errx(1, "reallocarray");

	/* 
	 *   if verbose >= 2, make USA mirrors first, then subsort by label.
	 *         otherwise, make USA mirrors first, then don't care.
	 * 
	 * if searching through USA mirrors on verbose <= 0 it is more likely
	 * to find the faster mirrors to shrink 'timeout' earlier to make your
	 *                    runtime as short as possible.
	 */
	if (usa == 0) {
		if (verbose >= 2) {
			qsort(array, array_length, sizeof(struct mirror_st),
			    label_cmp_minus_usa);
		} /* else don't sort */
	} else {
		if (verbose >= 2) {
			qsort(array, array_length, sizeof(struct mirror_st),
			    label_cmp);
		} else {
			qsort(array, array_length, sizeof(struct mirror_st),
			    usa_cmp);
		}
	}

	if (six == 1) {
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
			if (verbose == 4)
				printf("\n\n\n");
			else if (verbose == 3)
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
				if ( i == 9 || i == 99 )
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



		if (dns_cache) {
		
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

				close(std_err);
				free(line);

				if (verbose >= 2)
					printf("dns_cache process issues\n\n");
				else if (verbose >= 0) {
					n = array_length - c;
					do {
						printf("\b \b");
						n /= 10;
					} while (n > 0);
				}

				goto restart_program;
			}
			
			if (six && v == '0') {
				if (verbose >= 2)
					printf("IPv6 DNS record not found.\n");
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

			if (root_user == 1) {
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
			fflush(NULL);
			_exit(1);
		}
		if (ftp_pid == -1)
			err(1, "ftp 2 fork, line: %d", __LINE__);


		close(block_pipe[STDIN_FILENO]);

		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
		    NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);
			printf("kevent register fail, line: %d", __LINE__);
			return 1;
		}
		
		close(block_pipe[STDOUT_FILENO]);


		clock_gettime(CLOCK_REALTIME, &start);
		i = kevent(kq, NULL, 0, &ke, 1, &timeout);
		clock_gettime(CLOCK_REALTIME, &end);
		
		if (i == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGINT);
			printf("kevent, line: %d", __LINE__);
			return 1;
		}
		
		/* timeout occurred before ftp() exit was received */
		if (i == 0) {
			
			kill(ftp_pid, SIGINT);

			/* 
			 * give it time to gracefully abort, play
			 * nice with the server, then reap event
			 */
			i = kevent(kq, NULL, 0, &ke, 1, &timeout_kill);
			if (i == -1) {
				printf("%s ", strerror(errno));
				printf("kevent, line: %d", __LINE__);
				return 1;
			}
			if (i == 0) {
				
				kill(ftp_pid, SIGKILL);
				if (verbose >= 2)
					printf("killed\n");
				if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1) {
					printf("%s ", strerror(errno));
					printf("kevent, line: %d", __LINE__);
					return 1;
				}
			}
			
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
			    (long) ((S - (long double) timeout.tv_sec) * 
			    (long double) 1000000000);
		} else if (array[c].diff > s)
			array[c].diff = s;
	}

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
	
	if (verbose < 1)
		qsort(array, array_length, sizeof(struct mirror_st), diff_cmp0);
	else {
		if (usa == 0) {
			qsort(array, array_length, sizeof(struct mirror_st),
			    diff_cmp_minus_usa);
		} else {
			qsort(array, array_length, sizeof(struct mirror_st),
			    diff_cmp);
		}

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


		char *cut = NULL;

		int16_t j = 0, first = 0, se0 = se;
		
		if (!generate)
			goto generate_jump;

		if (se < 0)
			goto no_good;

		/* 
		 * load diff with what will be printed http lengths
		 *          then process http for printing
		 */
		n = 1;
		for (c = 0; c <= se; ++c) {
			cut = strstr(array[c].http += h, "/pub/OpenBSD");
			if (cut == NULL) {
				(array[c].http -= 1)[0] = '*';
				array[c].diff = strlen(array[c].http);
			} else {
				*cut = '\0';
				array[c].diff = cut - array[c].http;
			}
			
			if (n == 1) {
				if (strstr(array[c].http, "openbsd.org") ||
				    strstr(array[c].http, "OpenBSD.org"))
					n = 0;
			}
		}
		
		if (n == 1) {
			
			printf("Couldn't find any openbsd.org mirrors.\n");
			printf("Try again with a larger timeout!\n");
			
			for (i = 0; i <= se0; ++i) {
				if (array[i].http[0] == '*')
					array[i].http -= h - 1;
				else
					array[i].http -= h;
			}
			
			free(time);

			return 1;
		}

		/* 
		 * sort by longest length first, subsort http alphabetically 
		 *           It makes it kinda look like a flower.
		 */
		qsort(array, se + 1, sizeof(struct mirror_st), diff_cmp_g);

		printf("\n\n");
		printf("\t\t/* GENERATED CODE BEGINS HERE */\n\n\n");
		printf("\t\tconst char *ftp_list[%d] = {\n\n", se + 1);

				
		// n = 0;
		for (c = 0; c <= se; ++c) {

			/* 
			 *    3 is the size of the printed: "",
			 * if (c == se) it doesn't print the comma
			 */
			 
			n += i = array[c].diff + 3 - (c == se);

			/* 
			 * overflow:
			 * mirrors printed on each line
			 * will not exceed 80 characters
			 */
			if (n > 80) {
				
				/* center the printed mirrors. Err to right */
				for (j = (80 + 1 - (n - i)) / 2; j > 0; --j)
					printf(" ");
				for (j = first; j < c; ++j)
					printf("\"%s\",", array[j].http);
				printf("\n");
				first = c;
				n = i;
				
			}
		}
		
		/* center the printed mirrors. Err to right */
		for (j = (80 + 1 - n) / 2; j > 0; --j)
			printf(" ");
		for (j = first; j < se; ++j)
			printf("\"%s\",", array[j].http);
		printf("\"%s\"\n\n", array[se].http);
		
		printf("\t\t};\n\n");
		printf("\t\tconst uint16_t index = %d;\n\n\n\n", se + 1);


		/* 
		 * make non-openbsd.org mirrors: diff == 0
		 */
		for (c = 0; c <= se; ++c) {
			if (strstr(array[c].http, "openbsd.org") == NULL &&
			    strstr(array[c].http, "OpenBSD.org") == NULL)
				array[c].diff = 0;
		}

		/* sort by longest length first, subsort http alphabetically */
		qsort(array, se + 1, sizeof(struct mirror_st), diff_cmp_g2);

		/* stop non-openbsd.org mirrors from being displayed */
		for (c = 0; c <= se; ++c) {
			if (array[c].diff == 0)
				break;
		}
		
		se = c - 1;
		
		printf("\t\t/* Trusted OpenBSD.org domain mirrors */\n\n");
		printf("\t\tconst char *ftp_list_g[%d] = {\n\n", c);
		
		
		first = 0;
		
		n = 0;
		for (c = 0; c <= se; ++c) {

			/* 
			 *    3 is the size of the printed: "",
			 * if (c == se) it doesn't print the comma
			 */
			 
			n += i = array[c].diff + 3 - (c == se);

			/* 
			 * overflow:
			 * mirrors printed on each line
			 * will not exceed 80 characters
			 */
			if (n > 80) {
				
				/* center the printed mirrors. Err to right */
				for (j = (80 + 1 - (n - i)) / 2; j > 0; --j)
					printf(" ");
				for (j = first; j < c; ++j)
					printf("\"%s\",", array[j].http);
				printf("\n");
				first = c;
				n = i;
				
			}
		}
		
		/* center the printed mirrors. Err to right */
		for (j = (80 + 1 - n) / 2; j > 0; --j)
			printf(" ");
		for (j = first; j < se; ++j)
			printf("\"%s\",", array[j].http);
		printf("\"%s\"\n\n", array[se].http);
		
		printf("\t\t};\n\n");
		printf("\t\tconst uint16_t index_g = %d;\n\n\n", se + 1);

		printf("\t\t/* GENERATED CODE ENDS HERE */\n\n\n\n");
		printf("Replace section after line: %d, but ", entry_line);
		printf("before line: %d with the code above.\n\n", exit_line);

		for (i = 0; i <= se0; ++i) {
			if (array[i].http[0] == '*')
				array[i].http -= h - 1;
			else
				array[i].http -= h;
		}
		
		free(time);

		return 0;

generate_jump:

		c = array_length - 1;

		if (de == c)
			printf("\n\nDOWNLOAD ERROR MIRRORS:\n\n\n");
		else if (te == c)
			printf("\n\nTIMEOUT MIRRORS:\n\n\n");
		else
			printf("\n\nSUCCESSFUL MIRRORS:\n\n\n");

		struct mirror_st *ac = array + c;
		
		for (; c >= 0; --c, --ac) {

			if (array_length >= 100)
				printf("%3d", c + 1);
			else
				printf("%2d", c + 1);

			printf(" : %s\n\t", ac->label);
			
			if (c <= se) {
				printf("echo \"%s\" > /etc/installurl",
				    ac->http);
				printf(" : %.9Lf\n\n", ac->diff);
				continue;
			}
			
			cut = strchr(ac->http + h, '/');
			if (cut)
				*cut = '\0';
			
			printf("%s : ", ac->http + h);
			
			if (c <= te) {
				printf("Timeout\n\n");
				if (c == ts && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
				continue;
			}
			
			if (ac->diff == s + 1)
				printf("Download Error\n\n");
			else if (ac->diff == s + 2)
				printf("IPv6 DNS record not found\n\n");
			else
				printf("DNS record not found\n\n");
				
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

		if (next == 1) {
			printf("Perhaps the next release ");
			printf("(%s) isn't present yet?\n", release);
		} else if (current == 0 && override == 0 && generate == 0) {
			printf("Perhaps the %s release ", release);
			printf("isn't present yet?\n");
			printf("The OpenBSD team tests prereleases ");
			printf("by marking them as release kernels before\n");
			printf("the appropriate release mirrors are ");
			printf("available to hash out any issues.\n");
			printf("This is solved by using the -O option ");
			printf("to retrieve snapshot mirrors.\n\n");
		}
		if (six) {
			printf("Try losing the -6 option?\n\n");
			
			if (array[0].diff == s + 2 &&
			    (
			     array[array_length - 1].diff == s + 2 ||
			     array[array_length - 1].diff == s + 3
			    )
			   ) {
				printf("I have a strong suspicicion that ");
				printf("your dns system isn't set up ");
				printf("for IPv6 at all!!!\n\n");
			}
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
	
	
	if (to_file) {
		
		n = strlen(array[0].http);

		i = write(write_pipe[STDOUT_FILENO], array[0].http, n);

		if (i < n) {
			printf("not all of mirror sent to write_pid\n");
			goto restart_program;
		}
		
		waitpid(write_pid, &n, 0);

		if (n != 0) {
			printf("write_pid error.\n");
			goto restart_program;
		}

	}  else if (verbose >= 0) {
		printf("As root, type: echo \"%s\" > /etc/installurl\n",
		    array[0].http);
	}
	
	free(time);
	free(release);
	
	return 0;
}
