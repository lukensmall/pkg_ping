/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2017, 2018, 2019, Luke N Small, lukensmall@gmail.com
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
 * Special thanks to "Dan Mclaughlin" on misc@ for the ftp to sed idea
 *
 * "
 * ftp -o - http://www.openbsd.org/ftp.html | \
 * sed -n \
 *  -e 's:</a>$::' \
 *      -e 's:  <strong>\([^<]*\)<.*:\1:p' \
 *      -e 's:^\(       [hfr].*\):\1:p'
 * "
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct mirror_st {
	char *label;
	char *ftp_file;
	long double diff;
};

static int
diff_cmp(const void *a, const void *b)
{
	struct mirror_st *one = ((struct mirror_st **) a)[0];
	struct mirror_st *two = ((struct mirror_st **) b)[0];

	if (one->diff < two->diff)
		return -1;
	if (one->diff > two->diff)
		return 1;
	return 0;
}

static int
ftp_cmp(const void *a, const void *b)
{
	struct mirror_st *one = ((struct mirror_st **) a)[0];
	struct mirror_st *two = ((struct mirror_st **) b)[0];

	return strcmp(one->ftp_file, two->ftp_file);
}

static int
label_cmp(const void *a, const void *b)
{
	struct mirror_st *one = ((struct mirror_st **) a)[0];
	struct mirror_st *two = ((struct mirror_st **) b)[0];

	/* list the USA mirrors first, it will subsort correctly */
	int8_t temp = !strncmp("USA", one->label, 3);
	if (temp != !strncmp("USA", two->label, 3)) {
		if (temp)
			return -1;
		return 1;
	}
	return strcmp(one->label, two->label);
}

static int
label_rev_cmp(const void *a, const void *b)
{
	struct mirror_st *one = ((struct mirror_st **) a)[0];
	struct mirror_st *two = ((struct mirror_st **) b)[0];

	/* list the USA mirrors first, and will reverse subsort */
	int8_t temp = !strncmp("USA", one->label, 3);
	if (temp != !strncmp("USA", two->label, 3)) {
		if (temp)
			return -1;
		return 1;
	}
	return strcmp(two->label, one->label);
}

static void
manpage(char a[])
{
	printf("%s\n", a);
	printf("[-d (don't run Dig)]\n");

	printf("[-f (don't write to File even if run as root)]\n");

	printf("[-h (print this Help message and exit)]\n");

	printf("[-O (if your kernel is a snapshot, it will Override it and ");
	printf("search for release kernel mirrors.\n");
	printf("\tif your kernel is a release, it will Override it and ");
	printf("search for snapshot kernel mirrors.)\n");

	printf("[-S (\"Secure\" https mirrors instead. Secrecy is preserved ");
	printf("at the price of performance.\n");
	printf("\t\"insecure\" mirrors still preserve file integrity!)]\n");

	printf("[-s floating-point timeout in Seconds (eg. -s 2.3)]\n");

	printf("[-u (no USA mirrors to comply ");
	printf("with USA encryption export laws)]\n");

	printf("[-v (increase Verbosity. It recognizes up to 4 of these)]\n");
	
	printf("[-V (no Verbose output. No output but error messages)]\n");
}

int
main(int argc, char *argv[])
{
	int8_t f = (getuid() == 0) ? 1 : 0;
	int8_t num, current, insecure, u, verbose, override, d;
	long double s, S;
	pid_t ftp_pid, sed_pid, write_pid;
	int kq, i, pos, c, n, array_max, array_length, tag_len;
	int parent_to_write[2], ftp_to_sed[2], sed_to_parent[2], block_pipe[2];
	FILE *input, *pkg_write;
	struct mirror_st **array;
	struct kevent ke;
	struct timespec tv_start, tv_end;
	struct timespec timeout;
	
	/* 20 seconds and 0 nanoseconds */
	struct timespec timeout0 = { 20, 0 };
	
	if (pledge("stdio proc exec cpath wpath unveil", NULL) == -1)
		err(EXIT_FAILURE, "pledge, line: %d", __LINE__);

	if (unveil("/usr/bin/ftp", "x") == -1)
		err(EXIT_FAILURE, "unveil, line: %d", __LINE__);

	if (unveil("/usr/bin/sed", "x") == -1)
		err(EXIT_FAILURE, "unveil, line: %d", __LINE__);

	if (unveil("/usr/sbin/dig", "x") == -1)
		err(EXIT_FAILURE, "unveil, line: %d", __LINE__);
	

	if (f) {

		if (unveil("/etc/installurl", "cw") == -1)
			err(EXIT_FAILURE, "unveil, line: %d", __LINE__);

		if (pledge("stdio proc exec cpath wpath", NULL) == -1)
			err(EXIT_FAILURE, "pledge, line: %d", __LINE__);
	} else if (pledge("stdio proc exec", NULL) == -1)
		err(EXIT_FAILURE, "pledge, line: %d", __LINE__);

	
	u = verbose = current = override = 0;
	insecure = d = 1;
	s = 5;

	char *version;
	size_t len = 300;
	version = malloc(len);
	if (version == NULL) err(EXIT_FAILURE, "malloc, line: %d\n", __LINE__);

	/* stores results of "sysctl kern.version" into 'version' */
	const int mib[2] = { CTL_KERN, KERN_VERSION };
	if (sysctl(mib, 2, version, &len, NULL, 0) == -1)
                   err(EXIT_FAILURE, "sysctl, line: %d", __LINE__);
	
	/* Discovers if the kernel is not a release version */
	if (strstr(version, "beta"))
		current = 1;
	else if (strstr(version, "current"))
		current = 1;
		
	free(version);

	while ((c = getopt(argc, argv, "dfhOSs:uvV")) != -1) {
		switch (c) {
		case 'd':
			d = 0;
			break;
		case 'f':
			if (f == 0)
				break;
			if (pledge("stdio proc exec", NULL) == -1)
				err(EXIT_FAILURE, "pledge, line: %d", __LINE__);
			f = 0;
			break;
		case 'h':
			manpage(argv[0]);
			return EXIT_SUCCESS;
		case 'O':
			override = 1;
			break;
		case 'S':
			insecure = 0;
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
					errx(EXIT_FAILURE, "No negative sign.");
				errx(EXIT_FAILURE,
				    "Bad floating point format.");
			}
			if (n == 0)
				errx(EXIT_FAILURE,
				    "-s needs a numeric character.");
			errno = 0;
			s = strtold(optarg, NULL);
			if (errno == ERANGE)
				err(EXIT_FAILURE, "strtod");
			if (s > (long double)1000.0)
				errx(EXIT_FAILURE, "-s should be <= 1000");
			if (s <= (long double)0.01)
				errx(EXIT_FAILURE, "-s should be > 0.01");
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
			return EXIT_FAILURE;
		}
	}
	if (optind < argc) {
		manpage(argv[0]);
		errx(EXIT_FAILURE, "non-option ARGV-element: %s", argv[optind]);
	}


	if (verbose > 1) {
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

	if (f) {
		
		if (pipe(parent_to_write) == -1)
			err(EXIT_FAILURE, "pipe, line: %d", __LINE__);

		write_pid = fork();
		if (write_pid == (pid_t) 0) {
			
			char *tag_w;
			
			if (pledge("stdio cpath wpath", NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("pledge, line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
			
			close(parent_to_write[STDOUT_FILENO]);
						
			kq = kqueue();
			if (kq == -1) {
				printf("%s ", strerror(errno));
				printf("kq! line %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
			
			EV_SET(&ke, parent_to_write[STDIN_FILENO], EVFILT_READ,
				EV_ADD | EV_ONESHOT, 0, 0, NULL);
			if (kevent(kq, &ke, 1, &ke, 1, NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("write_pid kevent register fail,");
				printf(" line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
			close(kq);
			
			/* parent exited before sending data */
			if (ke.data == 0) {
				printf("/etc/installurl not written.\n");
				_exit(EXIT_FAILURE);
			}
			
			input = fdopen(parent_to_write[STDIN_FILENO], "r");
			if (input == NULL) {
				printf("%s ", strerror(errno));
				printf("write_pid fdopen, ");
				printf("line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
			
			tag_w = malloc(300 + 1);
			if (tag_w == NULL) {
				printf("%s ", strerror(errno));
				printf("malloc, line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
				
			i = 0;
			if (verbose >= 1)
				printf("\n");
			while ((c = getc(input)) != EOF) {
				if (i >= 300) {
					printf("\nmirror length ");
					printf("became too long.\n");
					
					printf("/etc/installurl");
					printf(" not written.\n");
					_exit(EXIT_FAILURE);
				}

				tag_w[i++] = c;
				if (c == '\n')
					break;
			}
			fclose(input);
			tag_w[i] = '\0';			
			
			/* fopen(... "w") truncates the file */
			pkg_write = fopen("/etc/installurl", "w");

			if (pledge("stdio", NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("pledge, line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
			
			if (pkg_write != NULL) {
				n = fwrite(tag_w, sizeof(char), i, pkg_write);
				fclose(pkg_write);
				if (n < i && verbose >= 0)
					printf("write error occurred.\n");
				if (n < i)
					_exit(EXIT_FAILURE);
				if (verbose >= 0)
					printf("/etc/installurl: %s", tag_w);
				_exit(EXIT_SUCCESS);
			}
			
			printf("%s ", strerror(errno));
			printf("/etc/installurl not opened.\n");
			_exit(EXIT_FAILURE);
		}
		if (write_pid == -1)
			err(EXIT_FAILURE, "write fork, line: %d", __LINE__);
			
		if (pledge("stdio proc exec", NULL) == -1)
			err(EXIT_FAILURE, "pledge, line: %d", __LINE__);

		close(parent_to_write[STDIN_FILENO]);
	}


	if (pipe(ftp_to_sed) == -1)
		err(EXIT_FAILURE, "pipe, line: %d", __LINE__);

	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

		if (pledge("stdio exec", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("ftp 1 pledge, line: %d\n", __LINE__);
			_exit(EXIT_FAILURE);
		}
		
		close(ftp_to_sed[STDIN_FILENO]);

		if (dup2(ftp_to_sed[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			printf("%s ", strerror(errno));
			printf("ftp STDOUT dup2, line: %d\n", __LINE__);
			_exit(EXIT_FAILURE);
		}
		
		if (verbose >= 2) {
			fprintf(stderr,
			    "fetching https://www.openbsd.org/ftp.html\n");
			execl("/usr/bin/ftp", "ftp", "-vmo", "-",
			    "https://www.openbsd.org/ftp.html", NULL);
		} else {
			execl("/usr/bin/ftp", "ftp", "-VMo", "-",
			    "https://www.openbsd.org/ftp.html", NULL);
		}

		fprintf(stderr, "%s ", strerror(errno));
		fprintf(stderr, "ftp 1 execl() failed, line: %d\n", __LINE__);
		_exit(EXIT_FAILURE);
	}
	if (ftp_pid == -1)
		err(EXIT_FAILURE, "ftp 1 fork, line: %d", __LINE__);

	close(ftp_to_sed[STDOUT_FILENO]);

	if (pipe(sed_to_parent) == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(EXIT_FAILURE, "pipe, line: %d", __LINE__);
	}
	sed_pid = fork();
	if (sed_pid == (pid_t) 0) {

		if (pledge("stdio exec", NULL) == -1) {
			printf("%s ", strerror(errno));
			printf("sed pledge, line: %d\n", __LINE__);
			_exit(EXIT_FAILURE);
		}
		close(sed_to_parent[STDIN_FILENO]);

		if (dup2(ftp_to_sed[STDIN_FILENO], STDIN_FILENO) == -1) {
			printf("%s ", strerror(errno));
			printf("sed STDIN dup2, line: %d\n", __LINE__);
			_exit(EXIT_FAILURE);
		}
		if (dup2(sed_to_parent[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			printf("%s ", strerror(errno));
			printf("sed STDOUT dup2, line: %d\n", __LINE__);
			_exit(EXIT_FAILURE);
		}
		execl("/usr/bin/sed", "sed", "-n",
		    "-e", "s:</a>$::",
		    "-e", "s:\t<strong>\\([^<]*\\)<.*:\\1:p",
		    "-e", "s:^\\(\t[hfr].*\\):\\1:p", NULL);

		fprintf(stderr, "%s ", strerror(errno));
		fprintf(stderr, "sed execl, line: %d\n", __LINE__);
		_exit(EXIT_FAILURE);
	}
	if (sed_pid == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		errx(EXIT_FAILURE, "sed fork, line: %d", __LINE__);
	}

	close(ftp_to_sed[STDIN_FILENO]);
	close(sed_to_parent[STDOUT_FILENO]);


	struct utsname *name = malloc(sizeof(struct utsname));
	if (name == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errno = ENOMEM;
		err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
	}
	
	if (uname(name) == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(EXIT_FAILURE, "uname, line: %d", __LINE__);
	}
	
	i = strlen(name->release);
	char *release = malloc(i + 1);
	if (release == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errno = ENOMEM;
		err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
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
		kill(sed_pid, SIGKILL);
		errno = ENOMEM;
		err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
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



	kq = kqueue();
	if (kq == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(EXIT_FAILURE, "kq! line: %d", __LINE__);
	}

	EV_SET(&ke, sed_to_parent[STDIN_FILENO], EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	i = kevent(kq, &ke, 1, &ke, 1, &timeout0);
	if (i == -1) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(EXIT_FAILURE,
		    "kevent, timeout0 may be too large. line: %d", __LINE__);
	}
	if (i == 0) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(EXIT_FAILURE,
		    "timed out fetching: https://www.openbsd.org/ftp.html");
	}
	input = fdopen(sed_to_parent[STDIN_FILENO], "r");
	if (input == NULL) {
		printf("%s ", strerror(errno));
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		err(EXIT_FAILURE, "fdopen sed_to_parent, line: %d", __LINE__);
	}

	/* if the index for line[] exceeds 299, it will error out */
	char *line = malloc(300);
	if (line == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errno = ENOMEM;
		err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
	}	

	array_max = 100;
	array = calloc(array_max, sizeof(struct mirror_st *));
	if (array == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errno = ENOMEM;
		err(EXIT_FAILURE, "calloc, line: %d", __LINE__);
	}


	num = pos = array_length = 0;
	array[0] = malloc(sizeof(struct mirror_st));
	if (array[0] == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errno = ENOMEM;
		err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
	}

	int pos_max = 0;
	
	while ((c = getc(input)) != EOF) {
		if (pos >= 300) {
			kill(ftp_pid, SIGKILL);
			kill(sed_pid, SIGKILL);
			errx(EXIT_FAILURE,
			    "pos got too big! line: %d", __LINE__);
		}
		if (num == 0) {
			if (c != '\n') {
				line[pos++] = c;
				continue;
			}
			line[pos++] = '\0';
			if (u) {
				if (!strncmp("USA", line, 3)) {
					while ((c = getc(input)) != EOF)
						if (c == '\n') break;
					pos = 0;
					continue;
				}
			}
			array[array_length]->label = malloc(pos);
			if (array[array_length]->label == NULL) {
				kill(ftp_pid, SIGKILL);
				kill(sed_pid, SIGKILL);
				errno = ENOMEM;
				err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
			}
			strlcpy(array[array_length]->label, line, pos);

			pos = 0;
			num = 1;
		} else {
			if (pos == 0) {
				if ((c != 'h') && (c != 'f') && (c != 'r'))
					continue;
				else if (insecure) {
					if (c == 'r')
						break;
					if (c == 'f') {
						line[pos++] = 'h';
						c = 't';
					}
				} else if (c != 'h')
					break;
			}
			if (c != '\n') {
				line[pos++] = c;
				continue;
			}
			
			/* pos >= 1 to get here */
			/* excise the final unnecessary '/' */
			line[pos - 1] = '\0';

			if (pos_max < pos)
				pos_max = pos;

			if (!insecure) {
				if (strncmp(line, "https", 5))
					break;
			} else if (!strncmp(line, "https", 5)) {
				free(array[array_length]->label);
				num = pos = 0;
				continue;
			}
			

			array[array_length]->ftp_file = malloc(pos);
			    
			if (array[array_length]->ftp_file == NULL) {
				kill(ftp_pid, SIGKILL);
				kill(sed_pid, SIGKILL);
				errno = ENOMEM;
				err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
			}
			
			strlcpy(array[array_length]->ftp_file, line, pos);

			if (++array_length >= array_max) {
				array_max += 20;
				array = reallocarray(array, array_max,
				    sizeof(struct mirror_st *));

				if (array == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errno = ENOMEM;
					err(EXIT_FAILURE,
					    "reallocarray, line: %d", __LINE__);
				}
			}
			array[array_length] = malloc(sizeof(struct mirror_st));

			if (array[array_length] == NULL) {
				kill(ftp_pid, SIGKILL);
				kill(sed_pid, SIGKILL);
				errno = ENOMEM;
				err(EXIT_FAILURE, "malloc, line: %d", __LINE__);
			}
			pos = num = 0;
		}
	}
	fclose(input);
	free(line);

	pos_max += tag_len;
	line = malloc(pos_max);
	if (line == NULL) err(EXIT_FAILURE, "malloc, line: %d", __LINE__);

	close(sed_to_parent[STDIN_FILENO]);

	kill(ftp_pid, SIGKILL);
	kill(sed_pid, SIGKILL);
	waitpid(ftp_pid, NULL, 0);
	waitpid(sed_pid, NULL, 0);

	if (array_length == 0)
		errx(EXIT_FAILURE, "No mirror found. Is www.openbsd.org live?");

	if (num == 1)
		free(array[array_length]->label);
	free(array[array_length]);

	
	if (insecure) {
		
		qsort(array, array_length, sizeof(struct mirror_st *), ftp_cmp);
		c = 1;
		while (c < array_length) {
			if (!strcmp(array[c - 1]->ftp_file,
			    array[c]->ftp_file)) {
				free(array[c - 1]->label);
				free(array[c - 1]->ftp_file);
				free(array[c - 1]);
				for (i = c; i < array_length; ++i)
					array[i - 1] = array[i];
				--array_length;
			} else
				++c;
		}
	}

	array = reallocarray(array, array_length, sizeof(struct mirror_st *));
	if (array == NULL)
		err(EXIT_FAILURE, "reallocarray, line: %d", __LINE__);
		
	qsort(array, array_length, sizeof(struct mirror_st *), label_cmp);
	
	S = s;

	timeout.tv_sec = (time_t) s;
	timeout.tv_nsec =
	    (long) ((s - (long double) timeout.tv_sec) *
	    (long double)1000000000);

	for (c = 0; c < array_length; ++c) {

		n = strlcpy(line, array[c]->ftp_file, pos_max);
		strlcpy(line + n, tag, pos_max - n);

		if (verbose >= 2) {
			if (verbose == 4 && d)
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



		for(n = 2 * d; n > 0; --n) {
		
			if (verbose >= 2)
				clock_gettime(CLOCK_UPTIME, &tv_start);

			pid_t dig_pid = fork();
			if (dig_pid == (pid_t) 0) {

				if (pledge("stdio exec", NULL) == -1) {
					printf("%s ", strerror(errno));
					printf("dig pledge, ");
					printf("line: %d\n", __LINE__);
					_exit(EXIT_FAILURE);
				}
				
				char *first, *last;
				
				first = strstr(line, "://");
				if (first == NULL) {
					printf("strstr(%s, \"://\")", line);
					printf(" == NULL ");
					printf("line: %d\n", __LINE__);
					_exit(EXIT_FAILURE);
				}
					
				first += 3;
					
				last = strstr( first, "/");
				if (last == NULL) {
					printf("strstr(%s, \"/\")", first);
					printf(" == NULL ");
					printf("line: %d\n", __LINE__);
					_exit(EXIT_FAILURE);
				}
				*last = '\0';
				
				if (verbose >= 2)
					printf("Running:  dig %s\n", first);
				
				if (verbose <= 3) {
					i = open("/dev/null", O_WRONLY);
					if (i != -1)
						dup2(i, STDOUT_FILENO);
				}
				execl("/usr/sbin/dig", "dig", first, NULL);
				
				fprintf(stderr, "%s ", strerror(errno));
				fprintf(stderr, "dig execl() failed, ");
				fprintf(stderr, "line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}
			if (dig_pid == -1) {
				err(EXIT_FAILURE,
				    "dig fork, line: %d", __LINE__);
			}

			waitpid(dig_pid, &i, 0);

			if (i == EXIT_FAILURE)
				errx(EXIT_FAILURE, "dig returned an error.");
			
			if (verbose >= 2) {
				clock_gettime(CLOCK_UPTIME, &tv_end);
				printf("%.9Lf\n",
				    (long double)(tv_end.tv_sec -
				    tv_start.tv_sec) +
				    (long double)(tv_end.tv_nsec -
				    tv_start.tv_nsec) /
				    (long double)1000000000);
			}		    
		}


		

		if (pipe(block_pipe) == -1)
			err(EXIT_FAILURE, "pipe, line: %d", __LINE__);

		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {

			if (pledge("stdio exec", NULL) == -1) {
				printf("%s ", strerror(errno));
				printf("ftp 2 pledge, line: %d\n", __LINE__);
				_exit(EXIT_FAILURE);
			}

			close(block_pipe[STDOUT_FILENO]);
			read(block_pipe[STDIN_FILENO], &n, sizeof(int));
			close(block_pipe[STDIN_FILENO]);
			
			if (verbose <= 2) {
				i = open("/dev/null", O_WRONLY);
				if (i != -1)
					dup2(i, STDERR_FILENO);
			}
			
			if (verbose >= 2 && d)
				printf("Running:  ftp\n");


			if (verbose >= 3) {
				execl("/usr/bin/ftp", "ftp", "-vmo",
				    "/dev/null", line, NULL);
			} else {
				execl("/usr/bin/ftp", "ftp", "-VMo",
				    "/dev/null", line, NULL);
			}

			printf("%s ", strerror(errno));
			printf("ftp 2 execl() failed, line: %d\n", __LINE__);
			_exit(EXIT_FAILURE);
		}
		if (ftp_pid == -1)
			err(EXIT_FAILURE, "ftp 2 fork, line: %d", __LINE__);


		close(block_pipe[STDIN_FILENO]);

		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
		    NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(EXIT_FAILURE,
			    "kevent register fail, line: %d", __LINE__);
		}
		clock_gettime(CLOCK_UPTIME, &tv_start);

		close(block_pipe[STDOUT_FILENO]);


		i = kevent(kq, NULL, 0, &ke, 1, &timeout);
		if (i == -1) {
			printf("%s ", strerror(errno));
			kill(ftp_pid, SIGKILL);
			errx(EXIT_FAILURE, "kevent, line: %d", __LINE__);
		}
		
		/* timeout occurred before ftp() exit was received */
		if (i == 0) {
			kill(ftp_pid, SIGKILL);
			
			/* reap event */
			if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1)
				err(EXIT_FAILURE, "kevent, line: %d", __LINE__);
			waitpid(ftp_pid, NULL, 0);
			if (verbose >= 2)
				printf("Timeout\n");
			array[c]->diff = s;
			continue;
		}
		
		waitpid(ftp_pid, &n, 0);
		
		if (n != EXIT_SUCCESS) {
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
		err(EXIT_FAILURE, "pledge, line: %d", __LINE__);

	free(line);
	free(tag);		
	close(kq);

	if (verbose == 0 || verbose == 1) {
		printf("\b \b");
		fflush(stdout);
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
		
		if (de > ds) {
			qsort(array + ds, 1 + de - ds, 
			    sizeof(struct mirror_st *), label_rev_cmp);
		}
		
		if (te > ts) {
			qsort(array + ts, 1 + te - ts,
			    sizeof(struct mirror_st *), label_rev_cmp);
		}
		
		c = array_length - 1;
		
		if (se == c)
			printf("\n\nSUCCESSFUL MIRRORS:\n\n\n");
		else if (te == c)
			printf("\n\nTIMEOUT MIRRORS:\n\n\n");
		else
			printf("\n\nDOWNLOAD ERROR MIRRORS:\n\n\n");

		for (; c >= 0; --c) {
			    
			if (array_length >= 100)
				printf("%3d", c + 1);
			else
				printf("%2d", c + 1);
			
			printf(" : %s:\n\techo ", array[c]->label);
			printf("\"%s\" > /etc/installurl",
			    array[c]->ftp_file);

			if (c <= se)
				printf(" : %.9Lf\n\n", array[c]->diff);
			else if (c <= te) {
				//~ printf(" Timeout");
				printf("\n\n");
				if (c == ts && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			} else {
				//~ printf(" Download Error");
				printf("\n\n");
				if (c == ds && ts != -1)
					printf("\nTIMEOUT MIRRORS:\n\n\n");
				else if (c == ds && se != -1)
					printf("\nSUCCESSFUL MIRRORS:\n\n\n");
			}
		}
	}

	if (array[0]->diff >= s) {
		if (current == 0) {
			printf("\n\nNo mirrors. It doesn't appear that the ");
			printf("%s release is present yet.\n", release);
			if (override == 0)
				printf("Perhaps try the -O option?\n");
			return EXIT_FAILURE;
		} else
			errx(EXIT_FAILURE, "No successful mirrors found.");
	}
	
	
	if (f) {		
		
		if (dup2(parent_to_write[STDOUT_FILENO], STDOUT_FILENO) == -1)
			err(EXIT_FAILURE, "dup2, line: %d\n", __LINE__);
		
		/* remove superfluous dynamic array memory before writing */
		for (c = 1; c < array_length; ++c) {
			free(array[c]->ftp_file);
			free(array[c]->label);
			free(array[c]);
		}
		
		/* sends the fastest mirror to write_pid process */
		printf("%s\n", array[0]->ftp_file);
		
		/* needed for verbose == -1 */
		fflush(stdout);

		waitpid(write_pid, &i, 0);

		return i;
	}

	if (verbose >= 0) {
		printf("As root, type: echo \"%s\" > /etc/installurl\n",
		    array[0]->ftp_file);
	}

	return EXIT_SUCCESS;
}
