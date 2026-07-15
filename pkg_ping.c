/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2016 - 2026, Luke N Small, thinkitdoitdone@gmail.com
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
 *	As root:
 *	cc pkg_ping.c -Wno-extern-initializer -o /usr/local/bin/pkg_ping
 *
 * 	If you want bleeding edge performance, you can try:
 *
 *  As root:

cc pkg_ping.c -march=native -mtune=native -flto -static -O3 \
-Wno-extern-initializer -o /usr/local/bin/pkg_ping

 *	run with: /usr/local/bin/pkg_ping
 *
 *	if there are no other pkg_ping files in your execution path:
 *	you can run with: pkg_ping
 *
 * 	You won't see ANY appreciable performance gain between the
 * 	getaddrinfo(3) and ftp(1) calls which fetch data over the network.
 * 	Everything else happens in likely less than third of a second
 * 	after the first ftp call starts to return its results.
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
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * OpenBSD seems to enforce a single declaration of this, now.
 */
extern char *malloc_options = "CFGJJU";

/*
 * Wipe out environment variables:
 * which conceivably could be bad to keep.
 * 
 * We don't need environment variables at all.
 * I'm going to disable them
 */
extern char **environ = NULL;

/*
 * I figured that I'd clean up some of the magic numbers.
 */
#define PARENT_SOCK 0
#define  CHILD_SOCK 1

static int entry_line = __LINE__;


                        /* GENERATED CODE BEGINS HERE */


static const char *ftp_list[51] = {

          "openbsd.mirror.constant.com","plug-mirror.rcac.purdue.edu",
           "cloudflare.cdn.openbsd.org","ftp.halifax.rwth-aachen.de",
            "ftp.rnl.tecnico.ulisboa.pt","mirrors.ocf.berkeley.edu",
   "mirrors.pidginhost.com","openbsd.cs.toronto.edu","*artfiles.org/openbsd",
     "mirror.planetunix.net","www.mirrorservice.org","mirror.aarnet.edu.au",
       "openbsd.c3sl.ufpr.br","ftp.usa.openbsd.org","ftp2.fr.openbsd.org",
       "mirror.leaseweb.com","mirror.telepoint.bg","mirrors.gigenet.com",
         "ftp.eu.openbsd.org","ftp.fr.openbsd.org","ftp.lysator.liu.se",
         "mirror.freedif.org","mirror.fsmg.org.nz","mirror.ungleich.ch",
         "mirrors.aliyun.com","mirrors.dotsrc.org","openbsd.ipacct.com",
"ftp.hostserver.de","mirrors.chroot.ro","mirrors.sonic.net","mirrors.ucr.ac.cr",
  "openbsd.as250.net","mirror.group.one","mirror.litnet.lt","mirror.yandex.ru",
    "cdn.openbsd.org","ftp.OpenBSD.org","ftp.jaist.ac.jp","mirror.ihost.md",
    "mirror.junda.nl","mirror.mephi.ru","mirror.ox.ac.uk","mirrors.mit.edu",
       "ftp.icm.edu.pl","mirror.rise.ph","ftp.cc.uoc.gr","ftp.spline.de",
             "ftp.nluug.nl","ftp.psnc.pl","ftp.bit.nl","ftp.fau.de"

};

static const int ftp_list_index = 51;



     /* Trusted OpenBSD.org subdomain mirrors for generating this section */

static const char *ftp_list_g[7] = {

    "cloudflare.cdn.openbsd.org","ftp.usa.openbsd.org","ftp2.fr.openbsd.org",
  "ftp.eu.openbsd.org","ftp.fr.openbsd.org","cdn.openbsd.org","ftp.OpenBSD.org"

};

static const int ftp_list_index_g = 7;


                         /* GENERATED CODE ENDS HERE */


static int exit_line = __LINE__;

typedef struct {

	long double diff;         // usually the time it took to download
                                  // can also be the string length of the MIRROR
                                  // if generating a MIRROR list
                                  
	long double speed;        // the scraped download speed from ftp(1)
	long double diff_rating;  // rating of the diff amongst other MIRRORs
	long double speed_rating; // rating of speed amongst other MIRRORs
	
	char *label;              // indicating the city, country, or location
	char *http;               // URL of the MIRROR
	
	int diff_rank;            // rank of the diff amongst other MIRRORs
	int speed_rank;           // rank of speed amongst other MIRRORs

} MIRROR;

/*
 * strlen("http://") == 7
 */
static int h = 7;
static int array_length = 0;
static MIRROR *array = NULL;

/* 
 * 1 second for an ftp SIGINT to turn into a SIGKILL
 */
static const struct timespec timeout_kill = { 1, 0 };

static int kq = -1;

static char *current_time = NULL;
static char  *diff_string = NULL;
static char         *line = NULL;
static char          *tag = NULL;

static const size_t dns_socket_len = 1256;

/* 
 * Called once with atexit. It's the only function called with atexit
 * and free_array isn't called elsewhere
 */
static void
free_array(void)
{
	MIRROR *ac = array + array_length;

	while (array < ac) {
		--ac;
		(void)free(ac->label);
		(void)free(ac->http);
	}
	array_length = 0;
	
	(void)free(array);
	array = NULL;

	(void)free(diff_string);
	diff_string = NULL;

	(void)free(line);
	line = NULL;

	(void)free(tag);
	tag = NULL;

	(void)free(current_time);
	current_time = NULL;

}

static long double almost_zero = 0.0L;

/*
 * print long double which is <1 and >0, without the leading '0'
 * eg. 0.25 is printed: .25
 * it doesn't get here unless diff <1 and >= 0
 */
static void
sub_one_print(long double diff)
{
	int i = 0;
	if ((diff < almost_zero) && (diff >= 0.0L)) {
		(void)printf("0");
		return;
	}
	if ((diff >= 1.0L) || (diff < 0.0L)) {
		errx(1, "Shouldn't ever get here line: %d", __LINE__);
	}

	i = snprintf(diff_string, 12, "%.9Lf", diff);
	if (i != 11) {
		if (i < 0) {
			err(1, "snprintf, line: %d", __LINE__);
		} else {
			err(1, "'line': %s, snprintf, line: %d",
			    diff_string, __LINE__);
		}
	}
	(void)printf("%s", 1 + diff_string);
}

/*
 * comparison between two MIRRORs. 
 * Prioritize MIRRORs which are likely closer to the USA,
 * otherwise...don't care.
 */
static int
usa_cmp(const void *a, const void *b)
{
	const char *one_label = ((const MIRROR *) a)->label;
	const char *two_label = ((const MIRROR *) b)->label;

	/* 
	 * prioritize the USA mirrors first
	 */
	int temp  = (int)(strstr(one_label, "USA") != NULL);
	if (temp != (int)(strstr(two_label, "USA") != NULL)) {
		if (temp) {
			return (-1);
		}
		return 1;
	}

	if (temp) {
		return 0;
	}

        /* 
         * prioritize Content Delivery Network "CDN" mirrors next
         */
        temp      = (int)(strstr(one_label, "CDN") != NULL);
        if (temp != (int)(strstr(two_label, "CDN") != NULL)) {
                if (temp) {
                        return (-1);
		}
                return 1;
        }

	if (temp) {
		return 0;
	}

	/*
	 * prioritize Canada mirrors last
	 */
	temp      = (int)(strstr(one_label, "Canada") != NULL);
	if (temp != (int)(strstr(two_label, "Canada") != NULL)) {
		if (temp) {
			return (-1);
		}
		return 1;
	}
	return 0;
}

/*
 * compare the labels alphabetically by proper decreasing
 * hierarchy which are in reverse order between commas.
 * 
 * checks to make sure these procedures are safe, are performed in main
 * It can assume all commas in the labels are followed by a space,
 * there is no leading comma, and there are no double spaces.
 */
static int
label_cmp_minus_usa(const void *a, const void *b)
{
	const char *one_label = ((const MIRROR *) a)->label;
	const char *two_label = ((const MIRROR *) b)->label;

	int ret = 0;
	
	/*
	 *  strlen(", ") == 2
	 */
	int rc = 2;
	int bc = 2;

	/*
	 * start with the last comma
	 */

	const char *red = strrchr(one_label, ',');
	const char *blu = strrchr(two_label, ',');
	
	if (red == NULL) {
		red = one_label;
		rc = 0;
	}
	if (blu == NULL) {
		blu = two_label;
		bc = 0;
	}
	
	ret = strcmp(
			red + rc,
			blu + bc
		    );

	while ((ret == 0) && rc && bc) {

		/*
		 * search for a comma before the one
		 * found in the previous iteration
		 */
		 
		/*
		 * no leading comma is enforced in main()
		 */
		for (;;) {
			if (one_label == red) {
				rc = 0;
				break;
			}
			--red;
			if (*red == ',') {
				break;
			}
		}

		for (;;) {
			if (two_label == blu) {
				bc = 0;
				break;
			}
			--blu;
			if (*blu == ',') {
				break;
			}
		}

		ret = strcmp(
			     red + rc,
			     blu + bc
		            );
	}

	if (ret == 0) {

		/*
		 * rc and bc are NOT both non-zero here:
		 * it had to escape the "while ((ret == 0) && rc && bc)"
		 * 
		 * if (rc || bc):
		 * Either red or blu has no more comma
		 * separated entries while remaining, equal.
		 * The one with fewer commas is preferred first.
		 */
		if (bc) {
			return (-1);
		}
		if (rc) {
			return 1;
		}


		/*
		 * exactly equal labels (rc == bc == 0):
		 * Checking for this condition initially
		 * with a label strcmp() doesn't
		 * provide useful information unless
		 * the labels are exactly equal.
		 * It isn't worth wasting time testing
		 * for it initially because of its rarity.
		 */
		return strcmp(
			      ((const MIRROR *) a)->http + h,
			      ((const MIRROR *) b)->http + h
			     );
	}
	return ret;
}

/*
 * comparison between two MIRRORs.
 * It doesn't test speed.
 * 
 * First determine whether the diff is different, then
 * Prioritize MIRRORs which are likely close to the USA, otherwise if zero,
 * return the reverse result of label_cmp_minus_usa().
 */
static int
diff_cmp_pure(const void *a, const void *b)
{
	int ret = 0;
	const long double one_diff = ((const MIRROR *) a)->diff;
	const long double two_diff = ((const MIRROR *) b)->diff;

	if (one_diff < two_diff) {
		return (-1);
	}
	if (one_diff > two_diff) {
		return 1;
	}

	/*
	 *    Prioritize mirrors near to USA next.
	 * They most likely didn't succeed past here.
	 */
	ret = usa_cmp(a, b);
	if (ret) {
		return ret;
	}

	/*
	 * reverse subsort label_cmp_minus_usa
	 */
	return label_cmp_minus_usa(b, a);
}

/*
 * comparison between two MIRRORs.
 * First determine whether the speed is different, then if the diff is
 * different, then
 * Prioritize MIRRORs which are likely close to the USA, otherwise if zero,
 * return the reverse result of label_cmp_minus_usa().
 */
static int
diff_cmp(const void *a, const void *b)
{
	int ret = 0;
	const long double one_speed = ((const MIRROR *) a)->speed;
	const long double two_speed = ((const MIRROR *) b)->speed;

	const long double one_diff  = ((const MIRROR *) a)->diff;
	const long double two_diff  = ((const MIRROR *) b)->diff;

	if (one_speed > two_speed) {
		return (-1);
	}
	if (one_speed < two_speed) {
		return 1;
	}


	if (one_diff < two_diff) {
		return (-1);
	}
	if (one_diff > two_diff) {
		return 1;
	}

	/*
	 *    Prioritize mirrors near to USA next.
	 * They most likely didn't succeed past here.
	 */
	ret = usa_cmp(a, b);
	if (ret) {
		return ret;
	}

	/*
	 * reverse subsort label_cmp_minus_usa
	 */
	return label_cmp_minus_usa(b, a);
}

/*
 * at this time, diff values represent the length of their http char*
 * stripped of the leading "http://" or "https://" and if it exists,
 * stripped of the trailing "/pub/OpenBSD".
 */
static int
diff_cmp_g(const void *a, const void *b)
{
	/*
	 * sort those with greater diff values first
	 * if no difference, compare http strings
	 */
	const int diff = (
		    (const int) ((const MIRROR *) b)->diff
		                      -
		    (const int) ((const MIRROR *) a)->diff
		   );

	if (!diff) {

		return strcmp(
			      ((const MIRROR *) a)->http,
			      ((const MIRROR *) b)->http
			     );

	}
	return diff;
}

/*
 * diff_cmp_g can be used in the place of this function, but it is
 * far more efficient to avoid the many unnecessary strcmp() for mirrors
 * which have been turned to diff == 0; to be excised from the output.
 * if no difference and both are non-zero diff, compare http strings
 */
static int
diff_cmp_g2(const void *a, const void *b)
{
	const int one_len = (const int) ((const MIRROR *) a)->diff;
	const int two_len = (const int) ((const MIRROR *) b)->diff;

	/*
	 * If either are an OpenBSD.org mirror...
	 *    (which means a non-zero diff)
	 *
	 *  Vast majority of the time both will be zero
	 *         if so, dont process further.
	 *
	 * Otherwise, process like diff_cmp_g
	 */
	if (one_len || two_len) {

		/*
		 * sort those with greater len values first
		 */

		if (one_len == two_len) {

			return strcmp(
				      ((const MIRROR *) a)->http,
				      ((const MIRROR *) b)->http
				     );

		}
		return (two_len - one_len);
	}
	return 0;
}

/*
 * add a usa_cmp to label_cmp_minus_usa()
 */
static int
label_cmp(const void *a, const void *b)
{
	/*
	 * prioritize mirrors near to USA first
	 */
	const int ret = usa_cmp(a, b);
	if (ret) {
		return ret;
	}

	return label_cmp_minus_usa(a, b);
}

/*
 * unify diff and speed ratings into a single comparison
 */
static int
unified_cmp(const void *a, const void *b)
{
	const long double one_unified_rating =
	    (((const MIRROR *) a)->diff_rating  + 1.0L)
                                *
	    (((const MIRROR *) a)->speed_rating + 1.0L);


	const long double two_unified_rating =
	    (((const MIRROR *) b)->diff_rating  + 1.0L)
                                *
	    (((const MIRROR *) b)->speed_rating + 1.0L);


	if (one_unified_rating > two_unified_rating) {
		return (-1);
	} else if (one_unified_rating < two_unified_rating) {
		return 1;
	} else {
		return 0;
	}
}

static void
manpage(void)
{
	(void)printf("[-6 (only return IPv6 compatible mirrors)]\n");

	(void)printf(
	    "[-a (rate by an Average of responsiveness and bandwidth!\n");
	(void)printf("        This is the default when -v's");
	(void)printf(" and no -V are chosen.)]\n");

	(void)printf("[-b (rate by the Bandwidth of the download!)]\n");

	(void)printf(
	    "[-D (Debug mode. Short circuit mirror downloads.\n        ");
	(void)printf("Show elapsed time since ftplist starts downloading.)]\n");

	(void)printf("[-d (don't cache DNS)]\n");

	(void)printf(
	    "[-f (don't automatically write to File if run as root)]\n");

	(void)printf("[-G (Generate all current sources of the ftp list)]\n");

	(void)printf("[-g (Generate source ftp list: only accessible ones)]\n");

	(void)printf("[-h (print this Help message and exit)]\n");

	(void)printf(
	    "[-l (ell) quantity of attempts the program will restart\n");
	(void)printf(
	    "        in a Loop for recoverable errors (default 20)]\n");

	(void)printf("[-n (search for mirrors with the Next release!)]\n");

	(void)printf(
	    "[-O (if you're running a snapshot, it will Override it and\n");
	(void)printf("        search for release mirrors. ");
	(void)printf("If you're running a release,\n");
	(void)printf("        it will Override it and ");
	(void)printf("search for snapshot mirrors.)\n");

	(void)printf("[-p (search for mirrors with the Previous release!)]\n");

	(void)printf(
	    "[-r (rate by how quickly it Responds to the download!)]\n");

	(void)printf("[-S (converts http mirrors into Secure https mirrors\n");
	(void)printf("        http mirrors still preserve file integrity!)]\n");

	(void)printf("[-s timeout in Seconds (eg. -s 2.3) (default 10 if -g\n");
	(void)printf("        is specified. Otherwise default 5)]\n");

	(void)printf("[-U (USA, CDN and Canada mirrors Only.");
	(void)printf("\n        ");
	(void)printf("This will likely be faster if you are in these areas.");
	(void)printf("\n        ");
	(void)printf("The program will absolutely take less runtime.)]");
	(void)printf("\n");

	(void)printf("[-u (no USA mirrors to comply ");
	(void)printf("with USA encryption export laws.)]\n");

	(void)printf(
	    "[-V (no Verbose output. No output except error messages)]\n");

	(void)printf(
	    "[-v (increase Verbosity. It recognizes up to 5 of these)]\n\n");


	(void)printf("More information at: ");
	(void)printf("https://github.com/lukensmall/pkg_ping\n\n");
}

/*
 * I created this DNS caching daemon which when supplied a URL, it will print
 * out DNS records, but it also pre-caches any ftp(1) call where ftp(1) issues a
 * DNS call using the same mechanism so, fetching it precaches whatever dns
 * server you're using, so it's fetched very quickly to let the ftp(1) call
 * timings not need to wait for DNS calls to fetch the DNS records across the
 * internet in an undetermined time; thereby eliminating the biggest problem in
 * determining the raw responsiveness of a server to a request in a single
 * request to limit the annoying file downloads on their networks to an
 * absolute minimum.
 */
static __attribute__((noreturn)) void
dns_cache_d(const int dns_socket, const int secure,
	       const int six, const int verbose)
{
	int i = 0;
	int g = 0;
	int c = 0;
	struct addrinfo *res0 = NULL;
	struct addrinfo *res  = NULL;
	int ret = 1;

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
	u_char *suc6 = NULL;

	int    max = 0;
	int i_temp = 0;
	int  i_max = 0;
	
	char six_available = '0';

	const char *dns_line0     = (secure) ? "https" : "http";
	const char *dns_line0_alt = (secure) ?  "443"  :  "80";

	const char hexadec[16] = { '0','1','2','3',
	                           '4','5','6','7',
	                           '8','9','a','b',
	                           'c','d','e','f' };

	char *dns_line = (char*)calloc(dns_socket_len, sizeof(char));
	if (dns_line == NULL) {
		(void)printf("calloc\n");
		goto dns_exit;
	}

	if (pledge("stdio dns", NULL) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("dns_cache_d pledge, line: %d\n", __LINE__);
		goto dns_exit;
	}
	
dns_loop:

	i = (int)read(dns_socket, dns_line, dns_socket_len);
	if (i == 0) {
		ret = 0;
		goto dns_exit;
	}

	if (i == dns_socket_len) {
		(void)printf("i == dns_socket_len, line: %d\n", __LINE__);
		goto dns_exit;
	}

	if (i == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("read error line: %d\n", __LINE__);
		goto dns_exit;
	}
	dns_line[i] = '\0';

	if (verbose >= 4) {
		(void)printf("DNS caching: %s\n", dns_line);
	}


	if (getaddrinfo(dns_line, dns_line0, &hints, &res0)) {

		c = getaddrinfo(dns_line, dns_line0_alt, &hints, &res0);

		if (c) {
			if (verbose >= 4) {
				(void)printf("%s\n", gai_strerror((int)c));
			}
			i = (int)write(dns_socket, "f", sizeof(char));
			if (i != sizeof(char)) {
				if (i == -1) {
					(void)printf("%s ", strerror(errno));
				}
				(void)printf("write error line: %d\n",
				                    __LINE__);
				goto dns_exit;
			}
			goto dns_loop;
		}
	}

	if ((verbose < 4) && (six == 0)) {
		for (res = res0; res; res = res->ai_next) {

			if (res->ai_family == AF_INET) {

				/*
				 * compiler complains of potential misalignment
				 * 
				 * sa4 = (struct sockaddr_in *) res->ai_addr;
				 */

				(void)memcpy(&sa4, &res->ai_addr,
				    sizeof(struct sockaddr_in *));

				sui4 = sa4->sin_addr.s_addr;

				/*
				 * I have an unbound dns blocklist where I
				 * force unwanted domains to resolve to
				 * 0.0.0.0 which translates to sui4 == 0
				 * This shouldn't impact functionality
				 * for others.
				 */
				if (sui4 == 0U) {
					continue;
				}
				break;
			}

			if (res->ai_family == AF_INET6) {
				break;
			}
		}

		if (res == NULL) {
			i = (int)write(dns_socket, "u", sizeof(char));
		} else {
			i = (int)write(dns_socket, "1", sizeof(char));
		}

		
		if (i != sizeof(char)) {
			if (i == -1) {
				(void)printf("%s ", strerror(errno));
			}
			(void)printf("write error line: %d\n", __LINE__);
			freeaddrinfo(res0);
			goto dns_exit;
		}
		freeaddrinfo(res0);
		goto dns_loop;
	}

	six_available = 'u';

	for (res = res0; res; res = res->ai_next) {

		if (res->ai_family == AF_INET) {

			/*
			 * compiler complains of potential misalignment
			 * 
			 * sa4 = (struct sockaddr_in *) res->ai_addr;
			 */

			(void)memcpy(&sa4, &res->ai_addr,
			    sizeof(struct sockaddr_in *));

			sui4 = sa4->sin_addr.s_addr;

			/*
			 * I have an unbound dns blocklist where I
			 * force unwanted domains to resolve to
			 * 0.0.0.0 which translates to sui4 == 0
			 * I don't expect a negative impact
			 * to functionality for others.
			 */
			if ((six_available == 'u') && sui4) {
				six_available = '0';
			}

			if (six) {
				continue;
			}

			(void)printf("       %hhu.%hhu.%hhu.%hhu\n",
			    (uint8_t) sui4,
			    (uint8_t)(sui4 >>  8),
			    (uint8_t)(sui4 >> 16),
			    (uint8_t)(sui4 >> 24));
			continue;
		}

		if (res->ai_family != AF_INET6) {
			continue;
		}

		six_available = '1';

		if (verbose < 4) {
			break;
		}

		(void)printf("       ");

		/*
		 * compiler complains of potential misalignment
		 *
		 * sa6 = (struct sockaddr_in6 *) res->ai_addr;
		 */

		(void)memcpy(&sa6, &res->ai_addr,
		    sizeof(struct sockaddr_in6 *));

		suc6 = sa6->sin6_addr.s6_addr;

		c     = 0;
		max   = 0;
		i_max = -1;

		/*
		 * load largest >1 gap beginning into i_max
		 *    and the length of the gap into max
		 */
		for (i = 0; i < 16; i += 2) {

			if ( suc6[i] || suc6[i + 1] ) {
				c = 0;
				continue;
			}

			if (c == 0) {
				i_temp = i;
				c = 1;
				continue;
			}
			
			++c;

			if (max < c) {
				max = c;
				i_max = i_temp;
			}
		}

		for (i = 0; i < 16; i += 2) {

			if (i) {
				(void)printf(":");
			}

			if (i == i_max) {
				if (i == 0) {
					(void)printf("::");
				} else {
					(void)printf(":");
				}
				i += 2 * max;
				if (i >= 16) {
					break;
				}
			}

			g = i + 1;

			if (suc6[i] / (u_char)16) {
				(void)printf("%c%c%c%c",
				    hexadec[suc6[i] / (u_char)16],
				    hexadec[suc6[i] % (u_char)16],
				    hexadec[suc6[g] / (u_char)16],
				    hexadec[suc6[g] % (u_char)16]);

			} else if (suc6[i]) {
				/*
				 *  Here: suc6[i] == suc6[i] % 16
				 */
				(void)printf("%c%c%c",
				    hexadec[suc6[i]             ],
				    hexadec[suc6[g] / (u_char)16],
				    hexadec[suc6[g] % (u_char)16]);

			} else if (suc6[g] / (u_char)16) {
				(void)printf("%c%c",
				    hexadec[suc6[g] / (u_char)16],
				    hexadec[suc6[g] % (u_char)16]);
			} else {
					/*
					 *  Here: suc6[g] == suc6[g] % 16
					 */
				(void)printf("%c",	
				    hexadec[suc6[g]             ]);
			}
		}
		(void)printf("\n");
	}
	freeaddrinfo(res0);

	i = (int)write(dns_socket, &six_available, sizeof(char));

	if (i != sizeof(char)) {
		if (i == -1) {
			(void)printf("%s ", strerror(errno));
		}
		(void)printf("write error line: %d\n", __LINE__);
		goto dns_exit;
	}

	goto dns_loop;

dns_exit:

	if (pledge("stdio", NULL) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("dns_cache_d pledge, line: %d\n", __LINE__);
		ret = 1;
	}
	(void)free(dns_line);
	(void)close(dns_socket);
	_exit(ret);
}

/*
 * Writes the determined installurl when main() supplies it.
 * 
 * I considered keeping this functionality in main(), but
 * if there's a possibility of the main() getting overrun,
 * this process performs some sanity checks to, among
 * other things, prevent /etc/installurl from becoming a
 * massive file which fills up the partition.
 * It makes user changes more seamless as well, since
 * I want to change the effective user to _pkgfetch
 * for everything but file writing, having a separate
 * process for it, makes great sense.
 */
static __attribute__((noreturn)) void
file_d(const int write_pipe, const int secure,
         const int debug, const int verbose)
{

	int   i = 0;
	int ret = 1;

	char *file_w    = NULL;
	FILE *pkg_write = NULL;
	
	const size_t max_file_length = dns_socket_len + 51;
	const size_t    received_max = 1 + max_file_length - 2;
	ssize_t             received = 0;

	/*
	 * It needs to be root to operate on the root-owned /etc/installurl
	 */
	if (seteuid(0) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("seteuid root, line: %d\n", __LINE__);
		_exit(1);
	}
	
	if (debug) {
		if (pledge("stdio", NULL) == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("pledge, line: %d\n", __LINE__);
			_exit(1);;
		}
	} else if (pledge("stdio cpath wpath", NULL) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("pledge, line: %d\n", __LINE__);
		_exit(1);
	}

	if (max_file_length <= 7 + (const size_t)secure + 2 + 1) {
		(void)printf("max_file_length is too short\n");
		_exit(1);
	}

	file_w = (char*)malloc(max_file_length);
	if (file_w == NULL) {
		(void)printf("malloc\n");
		_exit(1);
	}

	received = read(write_pipe, file_w, received_max);

	if (received == -1) {
		(void)printf("%s ", strerror(errno));
		(void)close(write_pipe);
		(void)printf("read error occurred, line: %d\n", __LINE__);
		(void)printf("/etc/installurl not written.\n");
		goto file_cleanup;
	}

	(void)close(write_pipe);

	if (received == 0) {
		(void)printf("program exited without writing: ");
		(void)printf("/etc/installurl not written.\n");
		goto file_cleanup;
	}

	if (received == (ssize_t)received_max) {
		(void)printf("received mirror is too large: ");
		(void)printf("/etc/installurl not written.\n");
		goto file_cleanup;
	}

	(void)memcpy(file_w + received, "\n", 1 + 1);

	if (secure) {
		if (strncmp(file_w, "https://", 8)) {
			(void)printf("file_w does't begin with ");
			(void)printf("\"https://\", line: %d\n", __LINE__);
			(void)printf("/etc/installurl not written.\n");
			goto file_cleanup;
		}
	} else {
		if (strncmp(file_w, "http://", 7)) {
			(void)printf("file_w does't begin with ");
			(void)printf("\"http://\", line: %d\n", __LINE__);
			(void)printf("/etc/installurl not written.\n");
			goto file_cleanup;
		}
	}

	if (debug) {
		if (verbose > 0) {
			(void)printf("\nDebug mode: file not written.\n");
		} else {
			(void)printf("Debug mode: file not written.\n");
		}
	} else {

		if (verbose > 0) {
			(void)printf("\n");
		}

		/*
		 *  unlink() to prevent possible symlinks by...root?
		 */
		(void)unlink("/etc/installurl");
		pkg_write = fopen("/etc/installurl", "w");

		if (pkg_write == NULL) {
			(void)printf("errno: %d %s ", errno, strerror(errno));
			(void)printf("/etc/installurl not opened.\n");
			goto file_cleanup;
		}

		if (pledge("stdio wpath", NULL) == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("pledge, line: %d\n", __LINE__);
			goto file_cleanup;
		}
	
		i = (int)fwrite(file_w, 1, (size_t)received + 1, pkg_write);
		(void)fclose(pkg_write);
		if (i < (int)received + 1) {
			(void)printf("write error occurred, line: %d\n",
						  __LINE__);
			goto file_cleanup;
		}
		
		if (verbose >= 0) {
			(void)printf("/etc/installurl: %s", file_w);
		}
	}

	ret = 0;

file_cleanup:

	if (pledge("stdio", NULL) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("pledge, line: %d\n", __LINE__);
		ret = 1;
	}

	(void)free(file_w);
	_exit(ret);
}

/*
 *             restarting the application needs to happen.
 *              Decrement 'loop' if above zero else quit.
 * append the new 'loop' while erasing any trailing one and restart().
 *           A new random mirror is selected in the next run.
 */
static __attribute__((noreturn)) void
restart(int argc, char *argv[], const int loop, const int verbose,
        const int call_line, const pid_t dns_cache_d_pid)
{
	int c;
	const int len = 10;
	
	/* 
	 * if an appended 'loop' is already the last variable: excise the value.
	 */
	const int n
	    = argc - (int)((argc > 1) && (!strncmp(argv[argc - 1], "-l", 2)));

	char **new_args = (char **)calloc((size_t)n + 1 + 1, sizeof(char *));
	if (new_args == NULL) {
		errx(1, "calloc");
	}
	
	if (dns_cache_d_pid != 0) {
		if (pledge("stdio proc exec", NULL) == -1) {
			err(1, "pledge, line: %d", __LINE__);
		}
		(void)kill(dns_cache_d_pid, SIGKILL);
		(void)waitpid(dns_cache_d_pid, NULL, 0);
	}

	if (pledge("stdio exec", NULL) == -1) {
		err(1, "pledge, line: %d", __LINE__);
	}

	if (verbose != -1) {
		(void)printf("restart called from line: %d\n", call_line);
	}

	if (loop == 0) {
		(void)free(new_args);
		errx(2, "Looping exhausted: Try again.");
	}

	if (verbose != -1) {
		(void)printf("restarting...loop: %d\n", loop);
	}

	(void)memcpy(new_args, argv, (size_t)n * sizeof(char *));

	new_args[n] = (char*)calloc(len, sizeof(char));
	if (new_args[n] == NULL) {
		errx(1, "calloc");
	}
	
	c = snprintf(new_args[n], len, "-l%d", loop - 1);
	if ((c >= len) || (c < 0)) {
		if (c < 0) {
			err(1, "snprintf, line: %d", __LINE__);
		} else {
			err(1, "new_args[n]: %s, snprintf, line: %d",
			    new_args[n], __LINE__);
		}
	}

	/*
	 * hard-code to /usr/local/bin/pkg_ping
	 */
	(void)execv("/usr/local/bin/pkg_ping", new_args);
	err(1, "execv failed, line: %d", __LINE__);
}

/*
 * gracefully kill off the ftp(1) call: I specifically kill off ftp(1) zombies
 * 		to be considerate to the mirror maintainers.
 */
static void
easy_ftp_kill(const pid_t ftp_pid)
{
	struct kevent ke;
	EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD |
	    EV_ONESHOT, NOTE_EXIT, 0, NULL);

	/* kevent registration returns -1, if ftp_pid is already dead */
    	if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
		if (errno != ESRCH) {
			(void)printf("%s ", strerror(errno));
			(void)printf("kevent, line: %d\n", __LINE__);
			/* Don't exit. Already dying. */
		}
    	} else {

		(void)kill(ftp_pid, SIGINT);

		/*
		 * give it time to gracefully abort, and play nice
		 * with the server before killing it with prejudice
		 */
		if (!kevent(kq, NULL, 0, &ke, 1, &timeout_kill)) {
			(void)kill(ftp_pid, SIGKILL);
		}
	}
 	(void)waitpid(ftp_pid, NULL, 0);
}

/*
 * scrapes the speed from the ftp(1) call output and returns it to main()
 */
static __attribute__((noreturn)) void
ftp_test_help(const int ftp_helper_out_pipe, const int ftp_2_ftp_helper_socket,
              const int verbose)
{

	int ret = 1;
	int num = 0;
	int pos = 0;
	int   n = 200;
	
	ssize_t i = 0;

	char v = '0';

	char *g = NULL;
	long double t = 0.0L;
	char *endptr = NULL;
	
	if (pledge("stdio", NULL) == -1) {
		(void)printf("pledge, line: %d\n", __LINE__);
		_exit(1);
	}

	(void)free(line);
	line = (char*)calloc((size_t)n, sizeof(char));
	if (line == NULL) {
		(void)printf("calloc\n");
		_exit(1);
	}

	/*
	 * Signal that it is ready
	 */
	if (write(ftp_2_ftp_helper_socket, &v, sizeof(char)) != sizeof(char)) {
		(void)printf("write error, line: %d\n", __LINE__);
		goto ftp_help_cleanup;
	}

	/*
	 * read ftp output and search for a '(' then read what is between there
	 * and a ')' and if successful, determine the sent bandwidth and return.
	 */
	while (read(ftp_2_ftp_helper_socket, &v, sizeof(char))
	    == sizeof(char)) {
		if (pos >= (n - 2)) {
			line[pos] = '\0';
			(void)printf("'line': %s\n", line);
			(void)printf("pos got too big! line: %d\n", __LINE__);
			break;
		}

		if (verbose >= 2) {
			(void)printf("%c", v);
			(void)fflush(stdout);
		}

		if (num == 0) {
			if (v == '(') {
				num = 1;
			}
			continue;
		}

		if (v != ')') {
			line[pos] = v;
			++pos;
			continue;
		}

		line[pos] = '\0';
/*
 * excerpt of ptransfer() in
 * /usr/src/usr.bin/ftp/util.c
 *
 *	meg = 0;
 *	if (bs > (1024 * 1024))
 *		meg = 1;
 *
 *	pace = bs / (1024.0 * (meg ? 1024.0 : 1.0));
 *	(void)snprintf(buf, sizeof(buf),
 *	    "%lld byte%s %s in %lld.%02d seconds (%lld.%02d %sB/s)\n",
 *	    (long long)bytes, bytes == 1 ? "" : "s", direction,
 *	    (long long)elapsed, (int)(elapsed * 100.0) % 100,
 *	    (long long)pace, (int)(pace * 100.0) % 100,
 *	    meg ? "M" : "K");
 */
		g = strchr(line, ' ');
		if (g == NULL) {
			break;
		}

		*g = '\0';

		errno = 0;
		t = strtold(line, &endptr);
		if (
		    errno ||
		    (t <= 0) ||
		    (endptr != g)
		   ) 
		{
			if (endptr != g) {
				(void)printf("endptr  != g\n");
			}
			break;
		}

		/*
		 * skip the printed space which was turned into a '\0'
		 */
		++g;
		if (*g == 'M') {
			t *= 1024.0L * 1024.0L;
		} else if (*g == 'K') {
			t *= 1024.0L;
		} else {
			(void)printf("bad read, line %d\n", __LINE__);
			break;
		}

		i = write(ftp_helper_out_pipe, &t, sizeof(long double));

		if (i != (ssize_t)sizeof(long double)) {
			(void)printf("bad write, line %d", __LINE__);
			break;
		}

		if (verbose >= 2) {
			while (read(ftp_2_ftp_helper_socket, &v, sizeof(char))
			    == sizeof(char)) {
				(void)printf("%c", v);
				(void)fflush(stdout);
			}
		}
		ret = 0;
		break;
	}
	
ftp_help_cleanup:

	(void)close(ftp_2_ftp_helper_socket);
	(void)close(ftp_helper_out_pipe);
	(void)free(line);
	line = NULL;
	_exit(ret);
}

/*
 * tests a mirror setting up a ftp_test_help process first,
 * then it execs into an ftp call itself
 */ 
static __attribute__((noreturn)) void
ftp_test(const int block_socket, const int ftp_helper_out_pipe,
         const int verbose, const int bail, const int std_err,
         const int print, const int six)
{
	char v = '0';

	int ftp_2_ftp_helper_socket[2] = { -1, -1 };

	if (socketpair(AF_UNIX, SOCK_STREAM,
	    PF_UNSPEC, ftp_2_ftp_helper_socket) == -1) {
		(void)printf("socketpair, line: %d\n",
			    __LINE__);
		_exit(1);
	}

	/*
	 * This process processes the output of ftp(1)
	 *      which shows the download rate
	 */
	switch(fork()) {
		case -1:
			(void)printf("ftp test help, line: %d\n", __LINE__);
			_exit(1);
			break;
		case 0:
			(void)close(block_socket);
			(void)close(ftp_2_ftp_helper_socket[PARENT_SOCK]);
			
			ftp_test_help(
				      ftp_helper_out_pipe,
			              ftp_2_ftp_helper_socket[CHILD_SOCK],
			              verbose
			             );
			/* function cannot return */
			break;
		default:
			break;
	}
	
	if (pledge("stdio exec", NULL) == -1) {
		(void)printf("pledge, line: %d\n", __LINE__);
		_exit(1);
	}
	
	(void)close(ftp_helper_out_pipe);
	(void)close(ftp_2_ftp_helper_socket[CHILD_SOCK]);

	/*
	 *           this read() is to ensure
	 *      that the helper process is alive for
	 *           the parent kevent call.
	 *   It standardizes the timing of the ftp calling
	 *   process, and it is written as an efficient way
	 * to signal the process to resume without ugly code.
	 */
	if (read(ftp_2_ftp_helper_socket[PARENT_SOCK], &v, sizeof(char))
	     != sizeof(char)) {
		(void)printf("read error, line: %d\n", __LINE__);
		_exit(1);
	}

	if (dup2(ftp_2_ftp_helper_socket[PARENT_SOCK], STDERR_FILENO) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("ftp STDERR dup2,");
		(void)printf(" line: %d\n", __LINE__);
		_exit(1);
	}
	(void)close(ftp_2_ftp_helper_socket[PARENT_SOCK]);
	
	/*
	 *     the read() for this write() is to ensure
	 *            that the process is alive for
	 *               the parent kevent call.
	 *   It standardizes the timing of the ftp calling
	 *   process, and it is written as an efficient way
	 * to signal the process to resume without ugly code.
	 */
	if (write(block_socket, &v, sizeof(char)) != sizeof(char)) {
		(void)printf("write error, line: %d", __LINE__);
		_exit(1);
	}

	/* 
	 * intended to short-circuit with a close()
	 * from the parent.
	 */
	(void)read(block_socket, &v, sizeof(char));
	(void)close(block_socket);

	if (bail) {
		_exit(0);
	}

	if ((verbose < 5) || (!print)) {
		(void)close(STDOUT_FILENO);
	}

	if (six) {
		if (verbose >= 3) {
			(void)execl("/usr/bin/ftp", "/usr/bin/ftp", "-vim6o-",
			            line, NULL);
		} else {
			(void)execl("/usr/bin/ftp", "/usr/bin/ftp", "-viM6o-",
			            line, NULL);
		}
	} else {
		if (verbose >= 3) {
			(void)execl("/usr/bin/ftp", "/usr/bin/ftp", "-vimo-",
			            line, NULL);
		} else {
			(void)execl("/usr/bin/ftp", "/usr/bin/ftp", "-viMo-",
			            line, NULL);
		}
	}

	/*
	 *  I possibly nullified stdout, so printf won't work
	 */
	(void)dprintf(std_err, "%s ", strerror(errno));
	(void)dprintf(std_err, "ftp 2 (void)execl() failed, ");
	(void)dprintf(std_err, "line: %d\n", __LINE__);
	_exit(1);
}

/*
 * download a fresh copy of the mirror list from a stale list of MIRRORS.
 */ 
static __attribute__((noreturn)) void
ftp_first(const int ftp_out_pipe, const int generate, const int verbose)
{
	int n = dns_socket_len + 44;
	
	ssize_t i = 0;
	
	if (pledge("stdio exec", NULL) == -1) {
		(void)printf("pledge, line: %d", __LINE__);
		_exit(1);
	}
	
	line = (char*)malloc((size_t)n);
	if (line == NULL) {
		(void)printf("malloc\n");
		_exit(1);
	}
	
	if (generate) {

		i = (int)arc4random_uniform(ftp_list_index_g);

		if (ftp_list_g[i][0] == '*') {
			i = snprintf(line, (ulong)n,
			   "https://%s/ftplist",
			   1 + ftp_list_g[i]);
		} else {
			i = snprintf(line, (ulong)n,
			    "https://%s/pub/OpenBSD/ftplist",
			    ftp_list_g[i]);
		}

	} else {

		i = (int)arc4random_uniform(ftp_list_index);

		if (ftp_list[i][0] == '*') {
			i = snprintf(line, (ulong)n,
			    "https://%s/ftplist",
			    1 + ftp_list[i]);
		} else {
			i = snprintf(line, (ulong)n,
			    "https://%s/pub/OpenBSD/ftplist",
			    ftp_list[i]);
		}
	}

	if ((i >= n) || (i < 0)) {
		if (i < 0) {
			(void)printf("%s", strerror(errno));
		} else {
			(void)printf("'line': %s,", line);
		}
		(void)printf(" snprintf, line: %d\n", __LINE__);
		_exit(1);
	}

	if (verbose >= 2) {
		(void)printf("%s\n", line);
	} else if (verbose >= 0) {
		(void)printf("$");
		(void)fflush(stdout);
	}


	if (dup2(ftp_out_pipe, STDOUT_FILENO) == -1) {
		(void)printf("%s ", strerror(errno));
		(void)printf("ftp STDOUT dup2, line: %d\n", __LINE__);
		_exit(1);
	}
	(void)close(ftp_out_pipe);


	if (verbose >= 2) {
		(void)execl("/usr/bin/ftp", "/usr/bin/ftp", "-vimo-",
		            line, NULL);
	} else {
		(void)execl("/usr/bin/ftp", "/usr/bin/ftp", "-ViMo-",
		            line, NULL);
	}

	(void)fprintf(stderr, "%s ", strerror(errno));
	(void)fprintf(stderr, "ftp first execl failed, line: %d\n", __LINE__);
	_exit(1);
}

/*
 * perform functions defined for the -g and -G flags
 */
static int
generate_function(int se)
{
	int     c = 0;
	int     i = 0;
	int     j = 0;
	int     n = 0;
	int first = 0;

	const int se0 = se;

	MIRROR *ac = NULL;

	char *cut = NULL;

	/*
	 * load diff with what will be printed http lengths
	 *          then process http for printing
	 */
	n = 1;
	ac = array + se + 1;
	while (array < ac) {
		--ac;
		cut = ac->http + h;
		j = (int)strlen(cut);

		if (j <= 12) {
			ac->diff = (long double)j + 1;
			(void)memmove(ac->http, ac->http + h - 1,
			              (size_t)j + 1 + 1);
			ac->http[0] = '*';
		} else if (strcmp(cut += j -= 12, "/pub/OpenBSD")) {
			ac->diff = (long double)j + 13;
			(void)memmove(ac->http, ac->http + h - 1,
			              (size_t)j + 13 + 1);
			(ac->http)[0] = '*';
		} else {
			ac->diff = (long double)j;
			*cut = '\0';
			(void)memmove(ac->http, ac->http + h, (size_t)j + 1);
		}

		if (n) {

			cut = strchr(ac->http, '/');

			if (cut == NULL) {
				cut = ac->http + (int)ac->diff;
			}

			if (((cut - ac->http) > 12) &&
			    (
			     !strncmp(cut - 12, ".openbsd.org", 12)

					      ||

			     !strncmp(cut - 12, ".OpenBSD.org", 12)
			    )
			   ) {
				n = 0;
			}
		}
	}



	if (n) {
		(void)printf("Couldn't find any openbsd.org mirrors.\n");
		(void)printf("Try again with a larger timeout!\n");
		return 1;
	}

	/*
	 * sort by longest length first, subsort http alphabetically
	 *           It makes it kinda look like a flower.
	 */
	if (
		heapsort(array, (size_t)se + 1, sizeof(MIRROR),
		    diff_cmp_g)
	   ) {
		(void)printf("sort failed, line %d\n", __LINE__);
		return 1;
	}

	(void)printf("\n\n");
	(void)printf("                        ");
	(void)printf("/* GENERATED CODE BEGINS HERE */\n\n\n");
	(void)printf("static const char *ftp_list[%d] = {\n\n",
	    se + 1);


	/*
	 * n = 0; 
	 */
	for (c = 0; c < se; ++c) {

		/*
		 *    3 is the size of the printed: "",
		 */

		if ((((int)array[c].diff) + 3) > 80) {
			(void)printf("\"%s\",\n", array[first].http);
			++first;
		} else {
			break;
		}
	}

	if (c == se) {
		goto gen_skip1;
	}

	for (; c <= se; ++c) {

		/*
		 *    3 is the size of the printed: "",
		 * if (c == se) it doesn't print the comma
		 */

		i = ((int)array[c].diff) + 3 - (c == se);
		n += i;

		/*
		 * overflow:
		 * mirrors printed on each line
		 * will not exceed 80 characters
		 */
		if (n > 80) {

			/* 
			 * center the printed mirrors. Err to right
			 */
			for (j = (80+1 - (n - i)) / 2; j > 0; --j) {
				(void)printf(" ");
			}
			do {
				(void)printf("\"%s\",",
					     array[first].http);
				++first;
			} while (first < c);
			(void)printf("\n");
			n = i;

		}
	}

	/* 
	 * center the printed mirrors. Err to right
	 */
	for (j = (80+1 - n) / 2; j > 0; --j) {
		(void)printf(" ");
	}
	while (first < se) {
		(void)printf("\"%s\",", array[first].http);
		++first;
	}
gen_skip1:
	(void)printf("\"%s\"\n\n", array[se].http);

	(void)printf("};\n\n");
	(void)printf("static const int ftp_list_index = %d;\n\n\n\n",
					  se + 1);


	/*
	 * make non-openbsd.org mirrors: diff == 0
	 *   and stop them from being displayed
	 */
	ac = array + se + 1;
	while (array < ac) {
		--ac;
		cut = strchr(ac->http, '/');
		if (cut == NULL) {
			cut = ac->http + (int)ac->diff;
		}
		if (((cut - ac->http) <= 12) ||
		    (
		     strncmp(cut - 12, ".openbsd.org", 12)
                                     &&
		     strncmp(cut - 12, ".OpenBSD.org", 12)
		    )
		   ) {
			ac->diff = 0;
			--se;
		}
	}

	/*
	 * sort by longest length first,
	 * if diff > 0 then
	 * subsort http alphabetically
	 */
	if (
		heapsort(array, (size_t)se0 + 1, sizeof(MIRROR),
				diff_cmp_g2)
	   ) {
		(void)printf("sort failed, line %d\n", __LINE__);
		return 1;
	}

	(void)printf("     /* Trusted OpenBSD.org subdomain ");
	(void)printf("mirrors for generating this section */\n\n");
	(void)printf("static const char *ftp_list_g[%d] = {\n\n", se + 1);


	n = 0;
	first = 0;

	for (c = 0; c < se; ++c) {

		/*
		 *    3 is the size of the printed: "",
		 */

		if ((((int)array[c].diff) + 3) > 80) {
			(void)printf("\"%s\",\n", array[first].http);
			++first;
		} else {
			break;
		}
	}

	if (c == se) {
		goto gen_skip2;
	}

	for (; c <= se; ++c) {

		/*
		 *    3 is the size of the printed: "",
		 * if (c == se) it doesn't print the comma
		 */

		i = ((int)array[c].diff) + 3 - (c == se);
		n += i;

		/*
		 * overflow:
		 * mirrors printed on each line
		 * will not exceed 80 characters
		 */
		if (n > 80) {

			/* 
			 * center the printed mirrors. Err to right
			 */
			for (j = (80+1 - (n - i)) / 2; j > 0; --j) {
				(void)printf(" ");
			}
			do {
				(void)printf("\"%s\",",
					     array[first].http);
				++first;
			} while (first < c);
			(void)printf("\n");
			n = i;
		}
	}

	/* 
	 * center the printed mirrors. Err to right
	 */
	for (j = (80+1 - n) / 2; j > 0; --j) {
		(void)printf(" ");
	}
	while (first < se) {
		(void)printf("\"%s\",", array[first].http);
		++first;
	}
gen_skip2:
	(void)printf("\"%s\"\n\n", array[se].http);

	(void)printf("};\n\n");
	(void)printf("static const int ftp_list_index_g = %d;\n\n\n",
		     se + 1);
	(void)printf("                         ");
	(void)printf("/* GENERATED CODE ENDS HERE */\n\n\n\n");
	(void)printf("Replace section after line: %d,", entry_line);
	(void)printf(" but before line: %d with the", exit_line);
	(void)printf(" code above.\n\n");
	
	return 0;
}
int
main(int argc, char *argv[])
{

#ifndef __OpenBSD__
	#error Only run on OpenBSD
#endif


	size_t tag_len = 0;
	
	int sort_ret = 0;
	int ret = 0;

	const int root_user = (int)(getuid() == 0);
	
	int        average = 1;
	
	int        to_file = root_user;
	
	int responsiveness = 0;
	int      bandwidth = 0;
	int        current = 0;
	int       override = 0;
	int       generate = 0;
	int         secure = 0;
	int            all = generate;
	int            num = 0;
	int            six = 0;
	int       previous = 0;
	int           next = 0;
	int          s_set = 0;
	int          debug = 0;
	int     test_print = 0;
	
	int array_max = 200;

	int dns_cache = 1;
	int       usa = 1;
	
	int       USA = 0;

	long double S = 0.0L;
	long double t = 0.0L;

	pid_t dns_cache_d_pid = 0;
	pid_t       write_pid = 0;
	pid_t         ftp_pid = 0;

	int std_err = 0;
	int       c = 0;
	int       i = 0;
	int       j = 0;
	int       n = 0;
	int       z = 0;

	int verbose = 0;
	int pos_max = 0;
	int    loop = 20;
	int     pos = 0;

	size_t len = 0;

	int ftp_helper_out_pipe[2] = { -1, -1 };
	int  dns_cache_d_socket[2] = { -1, -1 };
	int        block_socket[2] = { -1, -1 };
	int        ftp_out_pipe[2] = { -1, -1 };
	int          write_pipe[2] = { -1, -1 };

	struct timespec start = { 0, 0 };
	struct timespec   end = { 0, 0 };

	struct timespec timeout = { 0, 0 };
	struct timespec  startD = { 0, 0 };
	struct timespec    endD = { 0, 0 };

	char *line_temp = NULL;
	char   *release = NULL;

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
	long double s = 5.0L;

	/* 10 seconds and 0 nanoseconds to download ftplist */
	struct timespec timeout_ftp_list = { 10, 0 };

/*
from: /usr/src/sys/sys/ttycom.h
struct winsize {
	unsigned short  ws_row;          rows, in characters
	unsigned short  ws_col;          columns, in characters
	unsigned short  ws_xpixel;       horizontal size, pixels
	unsigned short  ws_ypixel;       vertical size, pixels
};
*/
	struct winsize w = { 0, 0, 0, 0 };

	MIRROR *ac = NULL;
	int pos_maxl = 0;
	int pos_maxh = 0;
	int pos_maxb = 0;
	int pos1 = 0;

	int num1 = 0;
	int num2 = 0;
	int num3 = 0;
	
	char *host = NULL;
	char  *cut = NULL;

	errno = 0;
	almost_zero = strtold(".000000001", NULL);
	if (errno) {
		err(1, "almost_zero == 0, line: %d", __LINE__);
	}

	if (root_user) {
		
		struct passwd *pw = NULL;
		
		i = pledge(
		          "stdio exec proc dns cpath wpath id unveil tty getpw",
		          NULL
			  );
		if (i == -1) {
			err(1, "pledge, line: %d", __LINE__);
		}
		
		pw = getpwnam("_pkgfetch");
		if (pw == NULL) {
			err(1, "getpwnam _pkg_fetch failed, line %d", __LINE__);
		}
	
		/*
		 * user _pkgfetch: ftp(1) will regain read pledge
		 *    just to chroot to /var/empty leaving
		 *      read access to an empty directory
		 * 
		 *   for all the other processes except file_d, 
		 *       why not make them unprivileged.
		 */
		if (seteuid(pw->pw_uid)) {
			err(1, "seteuid error, line: %d", __LINE__);
		}
		
		/*
		 *  why not wipe the reference from the stack.
		 */
		explicit_bzero(&pw, sizeof(struct passwd *));
	}
	
	i = pledge("stdio exec proc dns cpath wpath id unveil tty", NULL);
	if (i == -1) {
		err(1, "pledge, line: %d", __LINE__);
	}


	if (ioctl(0, TIOCGWINSZ, &w) == -1) {
		err(1, "ioctl, line: %d", __LINE__);
	}


	if (pledge("stdio exec proc dns cpath wpath id unveil", NULL) == -1) {
		err(1, "pledge, line: %d", __LINE__);
	}
	
	if (unveil("/usr/bin/ftp", "x") == -1) {
		err(1, "unveil /usr/bin/ftp, line: %d", __LINE__);
	}

	if (unveil("/usr/local/bin/pkg_ping", "x") == -1) {
		err(1, "unveil /usr/local/bin/pkg_ping, line: %d", __LINE__);
	}

	/*
	 * This is always equal to root_user before the flags get processed.
	 * It can get nullified later. If there's a way for option flags to
	 * corrupt something, I prefer to have this performed before
	 * user input needs to happen.
	 */
	if (to_file) {
		if (unveil("/etc/installurl", "cw") == -1) {
			err(1, "unveil /etc/installurl, line: %d", __LINE__);
		}

		if (unveil(NULL, NULL) == -1) {
			err(1, "unveil end1, line: %d", __LINE__);
		}

		i = pledge("stdio exec proc dns cpath wpath id", NULL);
		if (i == -1) {
			err(1, "pledge, line: %d", __LINE__);
		}
	} else {
		if (unveil(NULL, NULL) == -1) {
			err(1, "unveil end2 line: %d", __LINE__);
		}

		if (pledge("stdio exec proc dns id ", NULL) == -1) {
			err(1, "pledge, line: %d", __LINE__);
		}
	}

	diff_string = (char*)calloc(11 + 1, sizeof(char));
	if (diff_string == NULL) {
		errx(1, "calloc");
	}

	if (argc < 1) {
		errx(1, "argc cannot be less than 1!");
	}

	if (argc >= 30) {
		i = (int)(!strncmp(argv[argc - 1], "-l", 2));
		if ((argc - i) >= 30) {
			errx(1, "keep argument count under 30");
		}
	}

	for(c = 1; c < argc; ++c) {
		if (strnlen(argv[c], 35) == 35) {
			errx(1, "keep argument lengths under 35");
		}
	}


	for(;;) {
		c = getopt(argc, argv, "6abDdfGghl:nOprSs:uUVv");
		if (c == -1) {
			break;
		}
		switch (c) {
		case '6':
			six = 1;
			break;
		case 'a':
			average = 2;
			bandwidth = 0;
			responsiveness = 0;
			break;
		case 'b':
			average = 0;
			bandwidth = 1;
			responsiveness = 0;
			break;
		case 'D':
			debug = 1;
			break;
		case 'd':
			dns_cache = 0;
			break;
		case 'f':
			to_file = 0;
			if (pledge("stdio exec proc dns id", NULL) == -1) {
				err(1, "pledge, line: %d", __LINE__);
			}
			break;
		case 'G':
			all = 1;
			generate = 1;
			break;
		case 'g':
			generate = 1;
			break;
		case 'h':
			manpage();
			return 0;
		case 'l':
			if (strlen(optarg) >= 3) {
				(void)printf("keep -l argument under ");
				(void)printf("3 characters long.\n");
				return 1;
			}

			c = 0;
			loop = 0;
			do {
				if ((optarg[c] < '0') || (optarg[c] > '9')) {
					(void)printf("-l argument ");
					(void)printf("only accepts ");
					(void)printf("numeric characters\n");
					return 1;
				}
				loop = (loop * 10) + (int)(optarg[c] - '0');
				++c;
			} while (optarg[c] != '\0');
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
		case 'r':
			average = 0;
			bandwidth = 0;
			responsiveness = 1;
			break;
		case 'S':
			secure = 1;
			break;
		case 's':

			if (!strcmp(optarg, ".")) {
				errx(1, "-s argument should not be: \".\"");
			}

			if (strlen(optarg) >= 15) {
				errx(1,
				"keep -s argument under 15 characters long");
			}

			/*
			 * let's force my own validation on top of strtold()
			 */
			i = 0;
			c = 0;
			do {
				if ((optarg[c] >= '0') && (optarg[c] <= '9')) {
					++c;
					continue;
				}
				++i;
				if ((optarg[c] == '.') && (i == 1)) {
					++c;
					continue;
				}

				(void)printf("-s argument should only ");
				(void)printf("have numeric ");
				(void)printf("characters and a maximum ");
				(void)printf("of one decimal point\n");
				return 1;

			} while (optarg[c] != '\0');

			errno = 0;
			s = strtold(optarg, &line_temp);

			if (errno || (optarg == line_temp)) {
				(void)printf("\"%s\" is an invalid ", optarg);
				(void)printf("argument for -s\n");
				return 1;
			}

			(void)free(current_time);
			current_time = strdup(optarg);
			if (current_time == NULL) {
				errx(1, "strdup");
			}

			break;
		case 'u':
			usa = 0;
			break;
		case 'U':
			USA = 1;
			break;
		case 'V':
			verbose = -1;
			break;
		case 'v':
			if (verbose == -1) {
				break;
			}
			++verbose;
			if (verbose > 5) {
				verbose = 5;
			}
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
		
		if (all) {
			dns_cache = 0;
			if (verbose < 2) {
				verbose = 2;
			}
		}
		else if (verbose < 1) {
			verbose = 1;
		}
		
		secure   = 1;
		next     = 0;
		previous = 0;
		override = 0;
		to_file  = 0;
		if (pledge("stdio exec proc dns id", NULL) == -1) {
			err(1, "pledge, line: %d", __LINE__);
		}

		/* change default 's' value if not specified */
		if (current_time == NULL) {
			s = 10.0L;
		}
	}

	if (s > 1000.0L) {
		errx(1, "try an -s less than, equal to 1000");
	}

	/*
	 * 1/64th is represented exactly within
	 * binary datatype long double
	 */
	if (s < 0.015625L) {
		errx(1, "try an -s greater than or equal to 0.015625 (1/64)");
	}

	if (to_file) {

		if (pipe2(write_pipe, O_CLOEXEC) == -1) {
			err(1, "pipe2, line: %d", __LINE__);
		}

		write_pid = fork();
		switch(write_pid) {
			case -1:
				err(1, "file_d fork, line: %d", __LINE__);
				break;
			case 0:
				(void)close(write_pipe[STDOUT_FILENO]);
				file_d(write_pipe[STDIN_FILENO],
				       secure, debug, verbose);
				/* function cannot return */
				break;
			default:
				break;
		}
		(void)close(write_pipe[STDIN_FILENO]);
	}

	i = pledge("stdio exec proc dns", NULL);
	if (i == -1) {
		err(1, "pledge, line: %d", __LINE__);
	}

	if (dns_cache) {

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, dns_cache_d_socket) == -1) {
			err(1, "socketpair, line: %d", __LINE__);
		}

		dns_cache_d_pid = fork();
		switch(dns_cache_d_pid) {
			case -1:
				err(1, "dns_cache_d fork, line: %d",
				    __LINE__);
				break;
			case 0:
				(void)close(write_pipe[STDOUT_FILENO]);
				(void)close(dns_cache_d_socket[PARENT_SOCK]);
				dns_cache_d(dns_cache_d_socket[CHILD_SOCK],
				            secure, six, verbose);
				/* function cannot return */
				break;
			default:
				break;
		}
		(void)close(dns_cache_d_socket[CHILD_SOCK]);
	}

	if (pledge("stdio exec proc", NULL) == -1) {
			err(1, "pledge, line: %d", __LINE__);
	}
	
	if (pipe2(ftp_out_pipe, O_CLOEXEC) == -1) {
		err(1, "pipe, line: %d", __LINE__);
	}

	ftp_pid = fork();
	switch(ftp_pid) {
		case -1:
			err(1, "first ftp, line: %d", __LINE__);
			break;
		case 0:
			(void)close(ftp_out_pipe[STDIN_FILENO]);
			ftp_first(ftp_out_pipe[STDOUT_FILENO],
			          generate, verbose);
			/* function cannot return */
			break;
		default:
			break;
	}
	(void)close(ftp_out_pipe[STDOUT_FILENO]);

	/* 
	 * Let's do some work while ftp(1) is downloading ftplist
	 */

	kq = kqueue1(O_CLOEXEC);
	if (kq == -1) {
		(void)kill(ftp_pid, SIGKILL);
		(void)waitpid(ftp_pid, NULL, 0);
		(void)printf("kqueue1() error, line :%d\n", __LINE__);
		restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
	}

	S = ((long double) timeout_ftp_list.tv_sec) +
	    ((long double) timeout_ftp_list.tv_nsec) / 1000000000.0L;

	if (s > S) {
		timeout_ftp_list.tv_sec  = (time_t) s;
		timeout_ftp_list.tv_nsec =
		    (long) (
			       (
		                  s - (long double) timeout_ftp_list.tv_sec
		               ) * 1000000000.0L
		           );
	}

	S = s;

	if (current_time == NULL) {
		n = 20;
		current_time = (char*)malloc((size_t)n);
		if (current_time == NULL) {
			easy_ftp_kill(ftp_pid);
			errx(1, "malloc");
		}
		i = snprintf(current_time, (ulong)n, "%Lf", s);
		if ((i >= n) || (i < 0)) {
			if (i < 0) {
				(void)printf("%s", strerror(errno));
			} else {
				(void)printf("current_time: %s,", current_time);
			}
			(void)printf(" snprintf, line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			return 1;
		}
	} else {
		s_set = 1;
	}

	/*
	 * trim extra zeroes after decimal point in 'current_time'
	 */
	if (strchr(current_time, '.') != NULL) {
		i = 0;
		n = (int)strlen(current_time) - 1;
		while (current_time[n] == '0') {
			i = n;
			--n;
		}

		/* 
		 * if they are all zeroes after '.' then remove '.'
		 */
		if (current_time[n] == '.') {
			i = n;
		}

		if (i) {
			char *time0;
			
			current_time[i] = '\0';
			time0 = current_time;
			current_time = strdup(time0);
			if (current_time == NULL) {
				easy_ftp_kill(ftp_pid);
				(void)free(time0);
				errx(1, "strdup");
			}
			(void)free(time0);
		}
	}


	if (previous) {
		if (verbose >= 2) {
			(void)printf("showing the previous ");
			(void)printf("release availability!\n\n");
		}
	} else if (next) {
		if (verbose >= 2) {
			(void)printf("showing the next ");
			(void)printf("release availability!\n\n");
		}
	} else if (generate == 0) {
		const int mib[2] = { CTL_KERN, KERN_VERSION };

		/*
		 * retrieve length of results of "sysctl kern.version"
		 */
		if (sysctl(mib, 2, NULL, &len, NULL, 0) == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("sysctl, line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			return 1;
		}

		line = (char*)malloc(len);
		if (line == NULL) {
			easy_ftp_kill(ftp_pid);
			errx(1, "malloc");
		}

		/* 
		 * read results of "sysctl kern.version" into 'line'
		 */
		if (sysctl(mib, 2, line, &len, NULL, 0) == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("sysctl, line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			freezero(line, len);
			line = NULL;
			return 1;
		}

		/* 
		 * Discovers if the kernel is not a release version
		 */
		if (strstr(line, "current") || strstr(line, "beta")) {
			current = 1;
		}

		freezero(line, len);
		line = NULL;

		if (override) {
			current = !current;
		}

		if (verbose >= 2) {
			if (current) {
				(void)printf("showing snapshot mirrors\n\n");
			} else {
				(void)printf("showing release mirrors\n\n");
			}
		}
	}

	if (generate) {

		tag = strdup("/timestamp");
		if (tag == NULL) {
			easy_ftp_kill(ftp_pid);
			errx(1, "strdup");
		}

		tag_len = strlen(tag);

	} else {

		struct utsname name;
		size_t s_temp = 0;

		if (uname(&name) == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("uname, line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			return 1;
		}

		if (next && !strcmp(name.release, "9.9")) {
			release = strdup("10.0");
			i = 0;
		} else if (previous && !strcmp(name.release, "10.0")) {
			release = strdup("9.9");
			i = 0;
		} else {
			release = strdup(name.release);
			i = 1;
		}

		if (release == NULL) {
			easy_ftp_kill(ftp_pid);
			explicit_bzero(&name, sizeof(struct utsname));
			errx(1, "strdup");
		}

		/*
		 * flags are written to prevent both next and previous
		 * being declared.
		 */
		if (i && (next || previous)) {

			long double f_temp;
			n = (int)strlen(release) + 1;

			if (n == (3 + 1)) {
				if (
					(release[0] < '0') ||
					(release[0] > '9')
					||
					(release[1] != '.')
					||
					(release[2] < '0') ||
					(release[2] > '9')
				   ) {
					easy_ftp_kill(ftp_pid);
					explicit_bzero(&name,
					    sizeof(struct utsname));
					errx(1, "%s%s%d",
					"release is somehow ",
					"a bad format, line: ",
					__LINE__);
				}
				/*
				 *  eg. 7.7
				 */
				f_temp = (release[0] - '0')
				      + ((release[2] - '0') / 10.0L);

			} else if (n == (4 + 1))  {

				if (
					(release[0] < '0') ||
					(release[0] > '9')
					||
					(release[1] < '0') ||
					(release[1] > '9')
					||
					(release[2] != '.')
					||
					(release[3] < '0') ||
					(release[3] > '9')
				) {
					easy_ftp_kill(ftp_pid);
					explicit_bzero(&name,
					    sizeof(struct utsname));
					errx(1, "%s%s%d",
					"release is somehow ",
					"a bad format, line: ",
					__LINE__);
				}
				/*
				 *  eg. 10.0
				 */
				f_temp = ((release[0] - '0') * 10.0L) +
				         (long double) (release[1] - '0') +
				         ((release[3] - '0') / 10.0L);

			} else {
				easy_ftp_kill(ftp_pid);
				explicit_bzero(&name, sizeof(struct utsname));
				errx(1, "release got huge! line: %d", __LINE__);
			}

			if (previous) {
				f_temp -= 0.1L;
			} else /* if (next) */ {
				f_temp += 0.1L;
			}

			i = snprintf(release, (ulong)n, "%.1Lf", f_temp);

			if ((i >= n) || (i < 0)) {
				if (i < 0) {
					(void)printf("%s", strerror(errno));
				} else {
					(void)printf("release: %s,", release);
				}
				(void)printf(" snprintf, line: %d\n", __LINE__);
				easy_ftp_kill(ftp_pid);
				explicit_bzero(&name, sizeof(struct utsname));
				return 1;
			}
		}

		if (current) {
			tag_len = strlen("/snapshots/") +
			    strlen(name.machine) + strlen("/SHA256");

			tag = (char*)malloc(tag_len + 1);
			if (tag == NULL) {
				easy_ftp_kill(ftp_pid);
				explicit_bzero(&name, sizeof(struct utsname));
				errx(1, "malloc");
			}

			i = snprintf(tag, tag_len + 1,
			    "/snapshots/%s/SHA256", name.machine);
		} else {
			tag_len = strlen("/") + strlen(release) +
			    strlen("/") + strlen(name.machine) +
			    strlen("/SHA256");

			tag = (char*)malloc(tag_len + 1);
			if (tag == NULL) {
				easy_ftp_kill(ftp_pid);
				explicit_bzero(&name, sizeof(struct utsname));
				errx(1, "malloc");
			}

			i = snprintf(tag, tag_len + 1,
			    "/%s/%s/SHA256", release, name.machine);
		}

		explicit_bzero(&name, sizeof(struct utsname));
		
		s_temp = (size_t)i;

		if ((s_temp >= (tag_len + 1)) || (i < 0)) {
			if (i < 0) {
				(void)printf("%s", strerror(errno));
			} else {
				(void)printf("tag: %s,", tag);
			}
			(void)printf(" snprintf, line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			return 1;
		}
	}


	/* 
	 * if the index for line[] can exceed dns_socket_len, it will error
	 */
	line = (char*)calloc(dns_socket_len, sizeof(char));
	if (line == NULL) {
		easy_ftp_kill(ftp_pid);
		errx(1, "calloc");
	}

	array = (MIRROR*)calloc((size_t)array_max, sizeof(MIRROR));
	if (array == NULL) {
		easy_ftp_kill(ftp_pid);
		errx(1, "calloc");
	}

	(void)atexit(free_array);

	z = ftp_out_pipe[STDIN_FILENO];

	/*
	 * I use kevent here, just so I can restart
	 *   the program again if ftp is sluggish
	 */
	EV_SET(&ke, z, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, NULL);
	i = kevent(kq, &ke, 1, &ke, 1, &timeout_ftp_list);

	if (i == -1) {
		if ( (verbose == 0) || (verbose == 1) ) {
			(void)printf("\b \b%s ", strerror(errno));
			(void)fflush(stdout);
		} else {
			(void)printf("%s ", strerror(errno));
		}

		(void)printf("kevent, timeout_ftp_list may be too large. ");
		(void)printf("line: %d\n", __LINE__);
		easy_ftp_kill(ftp_pid);
		return 1;
	}

	if ( (verbose == 0) || (verbose == 1) ) {
		(void)printf("\b \b");
		(void)fflush(stdout);
	}

	if (i != 1) {
		easy_ftp_kill(ftp_pid);
		(void)close(z);
		restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
	}


	if (debug) {
		(void)clock_gettime(CLOCK_REALTIME, &startD);
	}

	while (read(z, &v, sizeof(char)) == sizeof(char)) {
		
		if (verbose == 5) {
			(void)printf("%c", v);
			(void)fflush(stdout);
		}

		if ((pos) >= ((int)(dns_socket_len - 2))) {
			line[pos] = '\0';
			(void)printf("'line': %s\n", line);
			(void)printf("pos got too big! line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			return 1;
		}

		if (num == 0) {

			if (v != ' ') {
				line[pos] = v;
				++pos;
				continue;
			}
			line[pos] = '\0';
			++pos;

			/*
			 * safety check
			 */
			if (strncmp(line, "http://", 7)) {
				(void)printf("'line': %s\n", line);
				(void)printf("bad http format, line: %d\n",
				             __LINE__);
				easy_ftp_kill(ftp_pid);
				return 1;
			}

			/*
			 * an http mirror becomes an https mirror.
			 */
			if (secure) {
				(void)memmove(line + 5, line + 4,
				    (size_t)pos - 4);
				line[4] = 's';
				++pos;
			}

			if (pos_max < pos) {
				pos_max = pos;
			}

			array[array_length].http = strdup(line);

			if (array[array_length].http == NULL) {
				easy_ftp_kill(ftp_pid);
				errx(1, "strdup");
			}

			pos = 0;
			num = 1;
			continue;
		}

		if ((pos == 0) && (v == ' ')) {
			continue;
		}

		if (v != '\n') {
			line[pos] = v;
			++pos;
			continue;
		}


		/*
		 * wipes out spaces at the end of the label
		 */
		while ((pos > 0) && (line[pos - 1] == ' ')) {
			--pos;
		}

		line[pos] = '\0';
		++pos;


		/*
		 * having a possible ", " or ',' at the beginning is
		 * problematic later. it's an error we can clean up cheaply now
		 * if it ever could occur.
		 */
		do {
			if (!strncmp(line, ", ", 2)) {
				pos -= 2;
				(void)memmove(line, line + 2,
				    (size_t)pos);
			} else if (line[0] == ',') {
				--pos;
				(void)memmove(line, line + 1,
				    (size_t)pos);
			} else {
				break;
			}
		} while (pos > 1);
		
		if (pos <= 1) {
			(void)free(array[array_length].http);
			num = 0;
			pos = 0;
			continue;
		}

		if ((usa == 0) && strstr(line, "USA")) {
			(void)free(array[array_length].http);
			num = 0;
			pos = 0;
			continue;
		}
		
		if ((USA == 1) &&
		
		    (
		      (strstr(line, "USA"   ) == NULL) &&
		      (strstr(line, "CDN"   ) == NULL) &&
		      (strstr(line, "Canada") == NULL)
		    )
		    
		) {
			(void)free(array[array_length].http);
			num = 0;
			pos = 0;
			continue;
		}
		
		/*
		 * I decided to aggressively deduplicate spaces,
		 * even if they may not ever need them,
		 * rewrite commas with a trailing space if needed
		 * This more cleanly enforces what I want without ever
		 * hard-failing on tests for label_cmp_minus_usa()
		 * when it doesn't need to be so.
		 */

		/* 
		 * rewrites 'line' (label) to not have back-to-back spaces.
		 * Will likely never find any.
		 */
		line_temp = strstr(line, "  ");
		while (line_temp != NULL) {
			(void)memmove(line_temp + 1, line_temp + 2,
			    (size_t)((line + pos) - (line_temp + 2)));
			--pos;
			line_temp = strstr(line_temp, "  ");
		}
		
		line_temp = strchr(line, ',');
		while (line_temp != NULL) {
			if (line_temp[1] != ' ') {
				/*
				 * will likely never get here
				 */
				if (pos >= ((int)dns_socket_len) - 2) {
					easy_ftp_kill(ftp_pid);
					(void)free(array[array_length].http);
					errx(1,
					    "too many unladen commas, line: %d",
					    __LINE__
					    );
				}
				/*
				 * make room for a space after the comma
				 */
				(void)memmove(line_temp + 2, line_temp + 1,
				    (size_t)((line + pos) - (line_temp + 1)));
				++pos;
				line_temp[1] = ' ';
			}
			
			/* Either a space is added or line_temp[1] is a space */
			line_temp = strchr(line_temp + 2, ',');
		}

		/*
		 * Not a fan of "The " in "The Netherlands" in here
		 *     I think it sticks out when it's sorted.
		 *       and I don't want to sort on "The".
		 *
		 *   If the label has a "The " after the last ", "
		 *   or if it has no comma and starts with "The ",
		 *          this will surgically remove it.
		 */
		line_temp = strrchr(line, ',');
		if (line_temp) {
			if (!strncmp(line_temp + 2, "The ", 4)) {
				(void)memmove(line_temp + 2, line_temp + 6,
				    (size_t)((line + pos) - (line_temp + 6)));
			}			
		} else if (!strncmp(line, "The ", 4)) {
			(void)memmove(line, line + 4,
				      (size_t)pos - 4
				     );
		}

		array[array_length].label = strdup(line);
		if (array[array_length].label == NULL) {
			(void)free(array[array_length].http);
			easy_ftp_kill(ftp_pid);
			errx(1, "strdup");
		}

		++array_length;

		if (array_length >= array_max) {

			MIRROR *array_temp = array;
			
			array_max += 100;

			if (array_max >= 5000) {
				easy_ftp_kill(ftp_pid);
				errx(1, "array_max got insanely large");
			}
			
			array = (MIRROR*)recallocarray(array_temp,
				                       (size_t)array_length,
				                       (size_t)array_max,
			                               sizeof(MIRROR)
			                              );

			if (array == NULL) {
				array = array_temp;
				easy_ftp_kill(ftp_pid);
				errx(1, "recallocarray");
			}
		}

		pos = 0;
		num = 0;
	}

	(void)close(z);

	(void)waitpid(ftp_pid, &z, 0);

	/*
	 *            'ftplist' download error:
	 * It's caused by no internet, bad dns resolution;
	 *   Or from a faulty mirror or its bad dns info
	 */
	if (WEXITSTATUS(z) || (array_length == 0)) {

		if (verbose >= 0) {
			(void)printf("There was an 'ftplist' ");
			(void)printf("download problem.\n");
		}

		restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
	}
	
	if (all) {
		verbose = 1;
	}

	/* 
	 * if "secure", h = strlen("https://") instead of strlen("http://")
	 */
	h += (secure) ? 1 : 0;

	pos_max += tag_len;

	if (pos_max > (int)sizeof(dns_socket_len /* length of line */)) {
		(void)free(line);
		line = (char*)calloc((size_t)pos_max, sizeof(char));
		if (line == NULL) {
			errx(1, "calloc");
		}
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
			sort_ret = heapsort(array, (ulong)array_length,
			    sizeof(MIRROR), label_cmp_minus_usa);
		} else {
			/*
			 * else don't sort
			 */
			sort_ret = 0;
		}
	} else {
		if (verbose > 1) {
			sort_ret = heapsort(array, (ulong)array_length,
			    sizeof(MIRROR), label_cmp);
		} else if (verbose < 1) {
			sort_ret = heapsort(array, (ulong)array_length,
			    sizeof(MIRROR), usa_cmp);
		} else  {
			/* 
			 * else don't sort
			 */
			sort_ret = 0;
		}
	}
	
	if (sort_ret) {
		err(1, "sort failed, line %d", __LINE__);
	}

	timeout.tv_sec = (time_t) (s + 0.125L);
	timeout.tv_nsec =
	    (long) (
			((s + 0.125L) - (long double) timeout.tv_sec) *
			1000000000.0L
		   );

	std_err = dup(STDERR_FILENO);
	if (std_err == -1) {
		err(1, "dup, line: %d", __LINE__);
	}

	if (fcntl(std_err, F_SETFD, FD_CLOEXEC) == -1) {
		err(1, "fcntl, line: %d", __LINE__);
	}

	/*
	pos_maxl = 0;
	pos_maxh = 0;
	pos_maxb = 0;
	pos1 = 0;

	num1 = 0;
	num2 = 0;
	num3 = 0;
	*/

	/* 
	 * calculations for preventing ugly line wraps in realtime output
	 */
	if (verbose >= 2 && !all) {

		ac = array + array_length;
		i = (array_length >= 100) + 10;

		while (array < ac) {
			--ac;
			pos = (int)strlen(ac->label);
			if (pos > pos_maxl) {
				pos_maxl = pos;
			}

			host = ac->http + h;
			cut = strchr(host, '/');
			if (cut == NULL) {
				pos1 = (int)strlen(host);
			} else {
				pos1 = (int)(cut - host);
			}

			if (pos1 > pos_maxh) {
				pos_maxh = pos1;
			}

			pos += pos1;

			if (pos > pos_maxb) {
				pos_maxb = pos;
			}
		}

		num1 = ((w.ws_col - i) >= (pos_maxl + pos_max));
		num2 = ((w.ws_col - i) >= (pos_maxl + pos_maxh));
		num3 = ((w.ws_col - i) >= pos_maxb);
	}


	host = h + line;

	(void)memcpy(line, array[0].http, (ulong)h);

	pos_max -= h;
	
	/*
	 *  if (all) skip
	 */
	for (c = (all) ? (int)array_length : 0; c < (int)array_length; ++c) {

		n = (int)strlcpy(host, array[c].http + h, (ulong)pos_max);
		(void)memcpy(host + n, tag, (ulong)tag_len + 1);


		/*
		 * strchr always succeeds. 'tag' starts with '/'
		 */
		cut = strchr(host, '/');

		if (verbose >= 2) {
			if ( (verbose >= 4) && (dns_cache != 0) ) {
				(void)printf("\n\n\n\n");
			} else if (verbose >= 3) {
				(void)printf("\n\n");
			} else if (verbose >= 0) {
				(void)printf("\n");
			}

			if (array_length >= 100) {
				(void)printf("%3d : ", (int)array_length - c);
			} else {
				(void)printf("%2d : ", (int)array_length - c);
			}

			if (num2) {

				i =  (int)strlen(array[c].label);
				j = ((int)pos_maxl + 1 - i) / 2;
				n =  (int)pos_maxl - (i + j);

				for (; j > 0; --j) {
					(void)printf(" ");
				}

				(void)printf("%s", array[c].label);

				for (; n > 0; --n) {
					(void)printf(" ");
				}

				if (num1) {
					(void)printf("  :  %s\n", line);
				} else {
					*cut = '\0';
					(void)printf("  :  %s\n", host);
					*cut = '/';
				}

			} else if (num3) {
				*cut = '\0';
				(void)printf("%s  :  ", array[c].label);
				(void)printf("%s\n", host);
				*cut = '/';
			} else {
				(void)printf("%s\n", array[c].label);
			}

		} else if ((verbose >= 0)) {
			i = (int)array_length - c;
			if (c) {
				if ( (i == 9) || (i == 99) ) {
					(void)printf("\b \b");
				}
				n = i;
				do {
					(void)printf("\b");
					n /= 10;
				} while (n);
			}
			(void)printf("%d", i);
			(void)fflush(stdout);
		}



		n = (int)(cut - host);

		if (dns_cache) {
			
			/* 
			 * 2 minutes for dns_cache_d to respond
			 */
			const struct timespec timeout_d = { 120, 0 };


			i = (int)write(dns_cache_d_socket[PARENT_SOCK],
			                      host, (size_t)n);
			if (i != n) {
				goto restart_dns_err;
			}

			if ((verbose >= 0) && (verbose <= 3)) {
				(void)printf("*");
				(void)fflush(stdout);
			}



			/*
			 * I use kevent here, just so I can restart
			 * the program again if DNS daemon is stuck
			 */
			EV_SET(&ke, dns_cache_d_socket[PARENT_SOCK],
			    EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, NULL);
			i = kevent(kq, &ke, 1, &ke, 1, &timeout_d);

			if ((verbose >= 0) && (verbose <= 3)) {
				(void)printf("\b \b");
				(void)fflush(stdout);
			}

			if (i == -1) {
				(void)printf("%s ", strerror(errno));
				(void)printf("kevent, timeout_d may ");
				(void)printf("be too large. ");
				(void)printf("line: %d\n", __LINE__);
				    
				return 1;
			}

			if (i != 1) {
				(void)kill(dns_cache_d_pid, SIGKILL);
				goto restart_dns_err;
			}


			i = (int)read(
				      dns_cache_d_socket[PARENT_SOCK],
				      &v,
			              sizeof(char)
			             );

			if (i != sizeof(char)) {

restart_dns_err:

				if (verbose >= 2) {
					(void)printf("dns_cache ");
					(void)printf("process issues\n\n");
				}
				else if (verbose >= 0) {
					n = (int)array_length - c;
					do {
						(void)printf("\b \b");
						n /= 10;
					} while (n);
				}

				restart(argc, argv, loop, verbose, __LINE__,
					dns_cache_d_pid);
			}

			if (six && (v == '0')) {
				if (verbose >= 2) {
					(void)printf("IPv6 DNS record ");
					(void)printf("not found.\n");
				}
				array[c].diff = s + 2;
				continue;
			} else if (v == 'f') {
				if (verbose >= 2) {
					(void)printf("DNS record not found.\n");
				}
				array[c].diff = s + 3;
				continue;
			} else if (v == 'u') {
				if (verbose >= 2) {
					(void)printf("BLOCKED ");
					(void)printf("subdomain!\n");
				}
				array[c].diff = s + 4;
				continue;
			}
		}


		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC,
		    PF_UNSPEC, block_socket) == -1) {
			err(1, "socketpair, line %d", __LINE__);
		}

		if (pipe2(ftp_helper_out_pipe, O_CLOEXEC) == -1) {
			err(1, "pipe2, line: %d", __LINE__);
		}

		ftp_pid = fork();
		switch(ftp_pid) {
			case -1:
				err(1, "ftp 2 fork, line: %d", __LINE__);
				break;
			case 0:
				ac = array + array_length;

				while (array < ac) {
					--ac;
					(void)free(ac->label);
					(void)free(ac->http);
				}
				array_length = 0;
				
				(void)free(array);
				array = NULL;

				(void)free(diff_string);
				diff_string = NULL;

				(void)free(tag);
				tag = NULL;
				
				(void)close(kq);
				(void)close(dns_cache_d_socket[PARENT_SOCK]);
				(void)close(write_pipe[STDOUT_FILENO]);
				
				(void)close(block_socket[PARENT_SOCK]);
				(void)close(ftp_helper_out_pipe[STDIN_FILENO]);

				ftp_test(block_socket[CHILD_SOCK],
				           ftp_helper_out_pipe[STDOUT_FILENO],
					   verbose, debug, std_err,
					   test_print == 0, six);
				/* function cannot return */
				break;
			default:
				break;
		}

		(void)close(block_socket[CHILD_SOCK]);
		(void)close(ftp_helper_out_pipe[STDOUT_FILENO]);
		
		/*
		 * receive a response from the ftp_test processes
		 *               that they are ready
		 */
		if (read(block_socket[PARENT_SOCK], &v, sizeof(char))
		    != sizeof(char)) {
			(void)printf("%s ", strerror(errno));
			(void)printf("read error,");
			(void)printf(" line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
		}

		/*
		 * this separate kevent call and block-socketing ensures
		 * that ftp_test and ftp_test_help are created and prepared to
		 * immediately execute to eliminate as many timing variables
		 * as possible which can be done in a single ftp download.
		 * Hopefully after the dust settles, mirror responsiveness is
		 * is judged fairly.
		 */
		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD |
		    EV_ONESHOT, NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("kevent register fail,");
			(void)printf(" line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
		}
		
		/*
		 * send last response to ftp_test to resume.
		 */
		(void)close(block_socket[PARENT_SOCK]);

		(void)clock_gettime(CLOCK_REALTIME, &start);
		i = kevent(kq, NULL, 0, &ke, 1, &timeout);
		(void)clock_gettime(CLOCK_REALTIME, &end);

		if (i == -1) {
			(void)printf("%s ", strerror(errno));
			(void)printf("kevent, line: %d\n", __LINE__);
			easy_ftp_kill(ftp_pid);
			return 1;
		}

		/* 
		 * timeout occurred before ftp(1) exit was received
		 */
		if (i == 0) {

			(void)kill(ftp_pid, SIGINT);

			/*
			 * give it time to gracefully abort, play
			 *  nice with the server and reap event
			 */
			i = kevent(kq, NULL, 0, &ke, 1, &timeout_kill);
			if (i == -1) {
				easy_ftp_kill(ftp_pid);
				err(1, "kevent, line: %d", __LINE__);
			
			}

			/*
			 * It didn't reap the event
			 */
			if (i == 0) {

				(void)kill(ftp_pid, SIGKILL);
				if (verbose >= 2) {
					(void)printf("killed\n");
				}

				/*
				 * reap event
				 */
				(void)kevent(kq, NULL, 0, &ke, 1, NULL);
			}

			(void)waitpid(ftp_pid, NULL, 0);
			(void)close(ftp_helper_out_pipe[STDIN_FILENO]);

			if (verbose >= 2) {
				(void)printf("Timeout\n");
			}
			array[c].diff = s;
			continue;
		}
		(void)waitpid(ftp_pid, &z, 0);

		if (WEXITSTATUS(z) != 0) {
			array[c].diff = s + 1;
			if (verbose >= 2) {
				(void)printf("Download Error\n");
			}

			(void)close(ftp_helper_out_pipe[STDIN_FILENO]);
			continue;
		}

		z = ftp_helper_out_pipe[STDIN_FILENO];
		if (!debug) {
			if (read(z, &array[c].speed, sizeof(long double))
			    != (ssize_t)sizeof(long double)) {
				(void)printf(
				           "ftp_helper_out_pipe[STDIN_FILENO]");
				(void)printf(
				           " read failed. line %d\n", __LINE__);
				(void)close(z);
				restart(argc, argv, loop, verbose, __LINE__,
					dns_cache_d_pid);
			}
		}
		(void)close(z);

		array[c].diff =
		    (long double) (end.tv_sec  - start.tv_sec )
                                        +
		    (long double) (end.tv_nsec - start.tv_nsec) / 1000000000.0L;
		
		if ((test_print == 0) && (array[c].diff < s)) {
			test_print = 1;
			if (verbose == 5) {
				(void)printf("\n<Print output one time>\n");
			}
		}

		if (verbose >= 2) {
			if (array[c].diff >= s) {
				array[c].diff = s;
				(void)printf("Timeout\n");
			} else if (
				   (array[c].diff < 1) &&
			           (array[c].diff >= 0)
			          ) {
				sub_one_print(array[c].diff);
				(void)printf("\n");
			} else {
				(void)printf("%.9Lf\n", array[c].diff);
			}
		} else if ((average != 2) && !bandwidth && (verbose <= 0)
		    && (array[c].diff < S)) {
			S = array[c].diff;
			timeout.tv_sec = (time_t)(S + 0.125L);
			timeout.tv_nsec =
			    (long) (
				(
					(S + 0.125L) -
					(long double) timeout.tv_sec
				) * 1000000000.0L
			    );

		} else if (array[c].diff > s) {
			array[c].diff = s;
		}
	}

	if (dns_cache) {
		(void)close(dns_cache_d_socket[PARENT_SOCK]);
		(void)waitpid(dns_cache_d_pid, NULL, 0);
		
		/*
		 * this is used in restart() to stop attempting to kill
		 *           dns_cache_d() upon restart()ing.
		 */
		dns_cache_d_pid = 0;
	}

	if (pledge("stdio exec", NULL) == -1) {
		err(1, "pledge, line: %d", __LINE__);
	}

	if ((verbose == 0) || (verbose == 1)) {
		(void)printf("\b \b");
		(void)fflush(stdout);
	}
	(void)free(line);
	line = NULL;
	(void)close(kq);

	if (verbose <= 0) {

		if (average == 2) {

			int se = -1;

			if (
				heapsort(array, (size_t)array_length,
				    sizeof(MIRROR), diff_cmp_pure)
			   ) {
				err(1, "sort failed, line %d", __LINE__);
			}

			c = (int)array_length;
			do {
				--c;
				if (array[c].diff < s) {
					se = c;
					break;
				}
			} while (c);

			if (se == -1) {
				goto no_good;
			}

			if (
				heapsort(array, (size_t)se + 1, sizeof(MIRROR),
				    diff_cmp)
			   ) {
				err(1, "sort failed, line %d", __LINE__);
			}

			for (c = 0; c <= se; ++c) {
				array[c].speed_rank = 1 + se - c;

				/*
				 * translate speed values into a linear
				 * equation (y == speed) with minimum
				 * and maximum y values and determine an
				 * x value from 0 to 100. This makes very
				 * good speeds stand out from the rest
				 * and evaluated accordingly.
				 */
				if (array[0].speed != array[se].speed) {
					t  = array[c].speed - array[se].speed;
					t *= 100.0L;
					t /= array[0].speed - array[se].speed;

					array[c].speed_rating = t;
				} else {
					array[c].speed_rating = 100.0L;
				}
			}

			if (
				heapsort(array, (size_t)se + 1,
				    sizeof(MIRROR), diff_cmp_pure)
			   ) {
				err(1, "sort failed, line %d", __LINE__);
			}

			for (c = 0; c <= se; ++c) {
				array[c].diff_rank = 1 + se - c;

				/*
				 * translate speed values into a linear
				 * equation (y == speed) with minimum
				 * and maximum y values and determine an
				 * x value from 0 to 100. This makes very
				 * good speeds stand out from the rest
				 * and evaluated accordingly.
				 */
				if (array[se].diff != array[0].diff) {
					t = array[c].diff - array[0].diff;
					t *= 100.0L;
					t /= array[se].diff - array[0].diff;

					array[c].diff_rating = 100.0L - t;
				} else {
					array[c].diff_rating = 100.0L;
				}
			}

			if (
				heapsort(array, (size_t)se + 1,
				    sizeof(MIRROR), unified_cmp)
			   ) {
				err(1, "sort failed, line %d", __LINE__);
			}

		} else {

			if (responsiveness || average) {
				/* 
				 * perform sort for responsiveness 
				 * ignore passive 'average' with a
				 * passive verbose
				 */
				sort_ret = heapsort(array, (size_t)array_length,
						sizeof(MIRROR), diff_cmp_pure);
			} else /* if (bandwidth) */ {
				sort_ret = heapsort(array, (size_t)array_length,
						sizeof(MIRROR), diff_cmp);
			}
			
			if (sort_ret) {
				err(1, "sort failed, line %d", __LINE__);
			}
		}

	} else {
		int  ds = -1;
		int  de = -1;

		int  ts = -1;
		int  te = -1;

		int  se = -1;


		MIRROR *slowest;
		
		int diff_topper = 0;
		
		int speed_shift = 0;
		int    pos_maxd = 0;
		int    pos_maxt = 0;

		size_t bbuf_size = 50;
		char *bbuf = NULL;

		sort_ret = heapsort(array, (size_t)array_length, sizeof(MIRROR),
		           diff_cmp_pure);
			
		if (sort_ret) {
			err(1, "sort failed, line %d", __LINE__);
		}

		c = (int)array_length;
		do {
			--c;
			if (array[c].diff < s) {
				se = c;
				break;
			}

			if (array[c].diff > s) {
				if (de == -1) {
					ds = c;
					de = c;
				} else {
					ds = c;
				}
			} else {
				if (te == -1) {
					ts = c;
					te = c;
				} else {
					ts = c;
				}
			}

		} while (c);

		if (se == -1) {
			goto no_good;
		}

		if (generate) {
	
			if (all) {
				se = array_length - 1;
			}
			
			ret = generate_function(se);

			if (debug) {
				goto debug_display;
			}

			return ret;
		}


		sort_ret = heapsort(array, (size_t)se + 1, sizeof(MIRROR),
		           diff_cmp);
			
		if (sort_ret) {
			err(1, "sort failed, line %d", __LINE__);
		}

		for (c = 0; c <= se; ++c) {
			array[c].speed_rank = 1 + se - c;

			/*
			 * translate speed values into a linear
			 * equation (y == speed) with minimum
			 * and maximum y values and determine an
			 * x value from 0 to 100. This makes very
			 * good speeds stand out from the rest
			 * and evaluated accordingly.
			 */
			if (array[0].speed != array[se].speed) {
				t  = array[c].speed - array[se].speed;
				t *= 100.0L;
				t /= array[0].speed - array[se].speed;

				array[c].speed_rating = t;
			} else {
				array[c].speed_rating = 100.0L;
			}
		}

		if (
			heapsort(array, (size_t)se + 1, sizeof(MIRROR),
		               diff_cmp_pure)
		   ) {
			err(1, "sort failed, line %d", __LINE__);
		}

		for (c = 0; c <= se; ++c) {
			array[c].diff_rank = 1 + se - c;

			/*
			 * translate speed values into a linear
			 * equation (y == speed) with minimum
			 * and maximum y values and determine an
			 * x value from 0 to 100. This makes very
			 * good speeds stand out from the rest
			 * and evaluated accordingly.
			 */
			if (array[se].diff != array[0].diff) {
				t = array[c].diff - array[0].diff;
				t *= 100.0L;
				t /= array[se].diff - array[0].diff;

				array[c].diff_rating = 100.0L - t;
			} else {
				array[c].diff_rating = 100.0L;
			}
		}



		if (average) {
			sort_ret = heapsort(array, (size_t)(se + 1),
			    sizeof(MIRROR), unified_cmp);
		} else if (bandwidth) {
			sort_ret = heapsort(array, (size_t)(se + 1),
			    sizeof(MIRROR), diff_cmp);
		} else {
			sort_ret = 0;
		}
		
		if (sort_ret) {
			err(1, "sort failed, line %d", __LINE__);
		}

		if (de != -1) {
			(void)printf("\n\nDOWNLOAD ERROR MIRRORS:\n\n");
		} else if (te != -1) {
			(void)printf("\n\nTIMEOUT MIRRORS:\n\n");
		} else {
			(void)printf("\n\nSUCCESSFUL MIRRORS:\n\n");
		}

		slowest = array + se;
		ac = slowest;

		while (array < ac) {
			--ac;
			if (diff_cmp_pure(ac, slowest) > 0) {
				slowest = ac;
			}
		}

		diff_topper = 0;
		i = 1;
		while (slowest->diff >= i) {
			i *= 10;
			++diff_topper;
			if (diff_topper == 4) {
				break;
			}
		}

		ac = array + se;
		pos_maxl = (int)strlen(ac->label);

		while (array < ac) {
			--ac;
			pos = (int)strlen(ac->label);
			if (pos > pos_maxl) {
				pos_maxl = pos;
			}
		}


		pos_maxt = 0;

		if (te != -1) {
			for (c = te; c >= ts; --c) {
				pos = (int)strlen(array[c].label);
				if (pos > pos_maxt) {
					pos_maxt = pos;
				}
			}
		}


		pos_maxd = 0;

		if (de != -1) {
			for (c = de; c >= ds; --c) {
				pos = (int)strlen(array[c].label);
				if (pos > pos_maxd) {
					pos_maxd = pos;
				}
			}
		}

		bbuf_size = 50;
		bbuf = (char*)malloc(bbuf_size);
		if (bbuf == NULL) {
			errx(1, "malloc");
		}

		speed_shift = 0;

		ac = array + se + 1;

		while (array < ac) {
			--ac;

			t = ac->speed;

			if (t >= (1024.0L * 1024.0L)) {
				j = snprintf(bbuf, bbuf_size, "%.2Lf",
				    t / (1024.0L * 1024.0L));
			} else {
				j = snprintf(bbuf, bbuf_size, "%.2Lf",
				    t / 1024.0L);
			}

			if (j > speed_shift) {
				speed_shift = j;
			}
		}





		c = (int)array_length;
		ac = array + c;

		while (array < ac) {
			--ac;

			if (array_length >= 100) {
				(void)printf("\n%3d : ", c);
			} else {
				(void)printf("\n%2d : ", c);
			}

			i = (int)strlen(ac->label);

			--c;
			if (c <= se) {

				j = ((int)pos_maxl + 1 - i) / 2;
				n = (int)pos_maxl - (i + j);
				for (; j > 0; --j) {
					(void)printf(" ");
				}

				(void)printf("%s", ac->label);

				for (; n > 0; --n) {
					(void)printf(" ");
				}

				(void)printf(" : ");

				if ((ac->diff < 1) && (ac->diff >= 0)) {
					switch (diff_topper) {
					case 1:
						(void)printf(" ");
						break;
					case 2:
						(void)printf("  ");
						break;
					case 3:
						(void)printf("   ");
						break;
					default:
						(void)printf("    ");
						break;
					}
					sub_one_print(ac->diff);
				} else {
					switch (diff_topper) {
					case 1:
						(void)printf("%1.9Lf",
							     ac->diff);
						break;
					case 2:
						(void)printf("%2.9Lf",
						             ac->diff);
						break;
					case 3:
						(void)printf("%3.9Lf",
							     ac->diff);
						break;
					default:
						(void)printf("%4.9Lf",
							     ac->diff);
						break;
					}
				}
				(void)printf(" seconds : ");

				t = (long double)ac->speed;


				if (t >= (1024.0L * 1024.0L)) {
					j = snprintf(bbuf, bbuf_size, "%.2Lf",
					    t / (1024.0L * 1024.0L));
				} else {
					j = snprintf(bbuf, bbuf_size, "%.2Lf",
					    t / 1024.0L);
				}

				n = speed_shift - j;

				while(n-- > 0) {
					(void)printf(" ");
				}

				if (t >= (1024.0L * 1024.0L)) {
					(void)printf("%.2Lf MB/s\n",
					    t / (1024.0L * 1024.0L));
				} else {
					(void)printf("%.2Lf KB/s\n",
					    t / 1024.0L);
				}



				i = 2 + (array_length >= 100);

				i += 3 + pos_maxl;

				for (; i > 0; --i) {
					(void)printf(" ");
				}

				(void)printf(" : ");


				if (se >= 99) {

					/*
					 * j = snprintf(bbuf, bbuf_size,
					 *     "time rank: %3d",
					 *     1 + se - (ac->diff_rank  - 1));
					 */

					j = 14;

					i = (diff_topper + 18 + 1 - j) / 2;
					n = i;

					for (; i > 0; --i) {
						(void)printf(" ");
					}

					(void)printf("time rank: %3d",
					    1 + se - (ac->diff_rank  - 1));

					n = diff_topper + 18 - (n + j);

					for (; n > 0; --n) {
						(void)printf(" ");
					}

					(void)printf(" : speed rank: %3d",
					    1 + se - (ac->speed_rank - 1));
				} else if (se >= 9) {

					/*
					 * j = snprintf(bbuf, bbuf_size,
					 *     "time rank: %2d",
					 *     1 + se - (ac->diff_rank  - 1));
					 */

					j = 13;

					i = (diff_topper + 18 + 1 - j) / 2;
					n = i;

					for (; i > 0; --i) {
						(void)printf(" ");
					}

					(void)printf("time rank: %2d",
					    1 + se - (ac->diff_rank  - 1));

					n = diff_topper + 18 - (n + j);

					for (; n > 0; --n) {
						(void)printf(" ");
					}

					(void)printf(" : speed rank: %2d",
					    1 + se - (ac->speed_rank - 1));
				} else {

					/*
					 * j = snprintf(bbuf, bbuf_size,
					 *     "time rank: %d",
					 *     1 + se - (ac->diff_rank  - 1));
					 */

					j = 12;

					i = (diff_topper + 18 + 1 - j) / 2;
					n = i;

					for (; i > 0; --i) {
						(void)printf(" ");
					}

					(void)printf("time rank: %d",
					    1 + se - (ac->diff_rank  - 1));

					n = diff_topper + 18 - (n + j);

					for (; n > 0; --n) {
						(void)printf(" ");
					}

					(void)printf(" : speed rank: %d",
					    1 + se - (ac->speed_rank - 1));
				}

				(void)printf("\n");

				if (array_length >= 100) {
					i = 3;
				}
				else {
					i = 2;
				}

				i += 3 + pos_maxl;

				for (; i > 0; --i) {
					(void)printf(" ");
				}

				(void)printf(" : ");




				j = snprintf(bbuf, bbuf_size,
				    "t rating: %.3LF",
				    ac->diff_rating);

				i = (diff_topper + 18 + 1 - j) / 2;
				n = i;

				for (; i > 0; --i) {
					(void)printf(" ");
				}

				(void)printf("t rating: %.3LF",
				    ac->diff_rating);

				n = diff_topper + 18 - (n + j);

				for (; n > 0; --n) {
					(void)printf(" ");
				}

				(void)printf(" : speed rating: %.3LF",
				    ac->speed_rating);

				(void)printf("\n\n        echo \"");
				(void)printf("%s", ac->http);
				(void)printf("\" > /etc/installurl\n\n\n");
				continue;
			}

			cut = strchr(ac->http + h, '/');
			if (cut) {
				*cut = '\0';
			}

			if (c <= te) {

				j = ((int)pos_maxt + 1 - i) / 2;
				n = (int)pos_maxt - (i + j);

				for (; j > 0; --j) {
					(void)printf(" ");
				}

				(void)printf("%s", ac->label);

				for (; n > 0; --n) {
					(void)printf(" ");
				}

				(void)printf(" : ");
				(void)printf("Timeout\n        %s\n",
					           ac->http + h);

				if ((c == ts) && (se != -1)) {
					(void)printf("\n\nSUCCESSFUL ");
					(void)printf("MIRRORS:\n\n");
				}

				continue;
			}

			j = ((int)pos_maxd + 1 - i) / 2;
			n = (int)pos_maxd - (i + j);

			for (; j > 0; --j) {
				(void)printf(" ");
			}

			(void)printf("%s", ac->label);

			for (; n > 0; --n) {
				(void)printf(" ");
			}

			(void)printf(" : ");

	/*
	 * If assigned this value.... If -Wfloat-equal warnings, ignore it.
	 */
			if (ac->diff == (s + 1)) {
				(void)printf("Download Error");
			} else if (ac->diff == (s + 2)) {
				(void)printf("IPv6 DNS record not found");
			} else if (ac->diff == (s + 3)) {
				(void)printf("DNS record not found");
			} else {
				(void)printf("BLOCKED subdomain!");
			}


			(void)printf("\n        %s\n", ac->http + h);


			if (c == ds) {
				if (te != -1) {
					(void)printf("\n\nTIMEOUT");
					(void)printf(" MIRRORS:\n\n");
				} else if (se != -1) {
					(void)printf("\n\nSUCCESSFUL");
					(void)printf(" MIRRORS:\n\n");
				}
			}
		}
		(void)free(bbuf);
	}

	if (array[0].diff >= s) {

no_good:

		if (to_file) {
			(void)close(write_pipe[STDOUT_FILENO]);
			(void)waitpid(write_pid, NULL, 0);
		}
		
		(void)printf("No successful mirrors found.\n\n");

		if (next) {
			(void)printf("Perhaps the next release ");
			(void)printf("(%s) isn't available?\n", release);
		} else if (previous) {
			(void)printf("Perhaps the previous release ");
			(void)printf("(%s) isn't available?\n", release);
		} else if (!current && !generate && override) {
			(void)printf("You are probably seeking to use ");
			(void)printf("the -p flag instead of -O flag ");
			(void)printf("since the %s release ", release);
			(void)printf("doesn't seem to be available.\n");
		} else if (!current && !generate) {
			(void)printf("You are probably running a snapshot, ");
			(void)printf("but it is indicating that you are");
			(void)printf(" running a release. ");
			(void)printf("You should use the -O flag in that");
			(void)printf(" case.\n");
		}
		if (six) {
			(void)printf("If your dns system is not set up ");
			(void)printf("for IPv6 connections, then ");
			(void)printf("lose the -6 flag.\n\n");
		}

		if (s_set == 0) {
			(void)printf("Perhaps try the -s ");
			(void)printf("option to choose a timeout");
			(void)printf(" larger than the default: -s %s\n",
			             current_time);
		} else {
			(void)printf("Perhaps try with a larger -s than %s\n",
			             current_time);
		}

		(void)free(release);

		return 1;
	}

	(void)free(release);

	if (to_file) {

		n = (int)strlen(array[0].http);

		i = (int)write(write_pipe[STDOUT_FILENO],
		    array[0].http, (size_t)n);

		if (i != n) {
			(void)printf("\nnot all of mirror sent to write_pid\n");
			(void)close(write_pipe[STDOUT_FILENO]);
			restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
		}

		(void)close(write_pipe[STDOUT_FILENO]);
		(void)waitpid(write_pid, &z, 0);

		if (WEXITSTATUS(z) != 0) {
			(void)printf("\nwrite_pid error.\n");
			restart(argc, argv, loop, verbose, __LINE__,
			dns_cache_d_pid);
		}

	} else if ((!root_user && (verbose != -1)) || (root_user && !verbose)) {
		if (verbose) {
			(void)printf("\n");
		}
		(void)printf("As root, type: echo ");
		(void)printf("\"%s\" > /etc/installurl\n", array[0].http);
	}
	
	if (debug) {

debug_display:

		(void)clock_gettime(CLOCK_REALTIME, &endD);


		if (verbose != -1) {
			(void)printf("\n");
		}

		(void)printf("Elapsed time: ");

		S = (long double) (endD.tv_sec  - startD.tv_sec ) +
		    (long double) (endD.tv_nsec - startD.tv_nsec) /
				  1000000000.0L;

		if (  (S < 1.0L) && (S >= 0.0L)  ) {
			sub_one_print(S);
			(void)printf("\n");
		} else {
			(void)printf("%.9Lf\n", S);
		}
	}

	return ret;
}
