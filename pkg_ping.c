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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

struct mirror_st {
	char *label;
	char *mirror;
	double diff;
};

static int
label_cmp(const void *a, const void *b)
{
	struct mirror_st **one;
	struct mirror_st **two;

	one = (struct mirror_st **) a;
	two = (struct mirror_st **) b;

	uint8_t temp1;
	uint8_t temp2;

	/* list the USA mirrors first, it will subsort correctly */
	if (strlen((*one)->label) >= 3)
		temp1 = !strncmp("USA",
		    (*one)->label + strlen((*one)->label) - 3, 3);
	else
		temp1 = 0;

	if (strlen((*two)->label) >= 3)
		temp2 = !strncmp("USA",
		    (*two)->label + strlen((*two)->label) - 3, 3);
	else
		temp2 = 0;


	if (temp1 != temp2) {
		if (temp1)
			return -1;
		return 1;
	}
	return strcmp((*one)->label, (*two)->label);
}

static int
ftp_cmp(const void *a, const void *b)
{
	struct mirror_st **one;
	struct mirror_st **two;

	one = (struct mirror_st **) a;
	two = (struct mirror_st **) b;

	if ((*one)->diff < (*two)->diff)
		return -1;
	if ((*one)->diff > (*two)->diff)
		return 1;
	//~return 0;

	return label_cmp(a, b);
}

static double
get_time_diff(struct timeval a, struct timeval b)
{
	long sec;
	long usec;
	sec = b.tv_sec - a.tv_sec;
	usec = b.tv_usec - a.tv_usec;
	if (usec < 0) {
		--sec;
		usec += 1000000;
	}
	return sec + ((double) usec / 1000000.0);
}

static void
manpage(char *a)
{
	printf("%s [-v (recognizes up to 3 levels of verbosity)]\n", a);
	
	printf("[-u (no USA mirrors...to comply ");
	printf("with USA encryption export laws)]\n");
	
	printf("[-n maximum_mirrors_written]\n");
	
	printf("[-s timeout (floating-point)]\n");
	
	printf("[-h (print this message and exit)]\n");
}

int
main(int argc, char *argv[])
{
	pid_t ftp_pid, write_pid;
	int parent_to_write[2];
	int verbose;
	double s;
	int kq, i, pos, num, c, n, line_max, array_max, array_length, u;
	FILE *input, *pkg_read;
	struct utsname name;
	struct mirror_st **array;
	struct kevent ke;

	extern char *malloc_options;
	malloc_options = (char *) "AFJHSUX";

	if (getuid() == 0) {
		i = pledge("stdio wpath cpath rpath proc exec id getpw", NULL);
		if (i == -1)
			err(EXIT_FAILURE, "pledge");
	} else {
		if (pledge("stdio rpath proc exec", NULL) == -1)
			err(EXIT_FAILURE, "pledge");
	}




	array_max = 100;
	line_max = 300;

	array = (struct mirror_st **)
	    calloc(array_max, sizeof(struct mirror_st *));
	if (array == NULL)
		err(1, "calloc");

	s = 5;
	n = 5000;
	u = 0;
	verbose = 0;

	if (uname(&name) == -1)
		err(1, "uname");

	while ((c = getopt(argc, argv, "s:n:vuh")) != -1) {
		switch (c) {
		case 's':
			c = -1;
			i = 0;
			while (optarg[++c] != '\0') {
				if (optarg[c] == '.')
					++i;

				if (((optarg[c] < '0' || optarg[c] > '9')
					&& (optarg[c] != '.')) || i > 1) {

					if (optarg[c] == '-')
						errx(1, "No negative numbers.");
					fprintf(stderr, "Incorrect floating ");
					fprintf(stderr, "point format.");
					return 1;
				}
			}
			errno = 0;
			strtod(optarg, NULL);
			if (errno == ERANGE)
				err(1, "ERANGE");
			if ((s = strtod(optarg, NULL)) > 1000.0)
				errx(1, "-s should <= 1000");
			if (s <= 0.001)
				errx(1, "-s should be > 0.001");
			break;
		case 'n':
			if (strlen(optarg) > 3)
				errx(1, "Integer should be <= 3 digits long.");
			c = -1;
			n = 0;
			while (optarg[++c] != '\0') {
				if (optarg[c] < '0' || optarg[c] > '9') {
					if (optarg[c] == '.')
						errx(1, "No decimal points.");
					if (optarg[c] == '-')
						errx(1, "No negative #.");
					errx(1, "Incorrect integer format.");
				}
				n = n * 10 + (int) (optarg[c] - '0');
			}
			if (n == 0)
				errx(1, "-n should not equal zero");
			break;
		case 'v':
			if (++verbose > 3)
				verbose = 3;
			break;
		case 'u':
			u = 1;
			break;
		case 'h':
			manpage(argv[0]);
			return 0;
		default:
			manpage(argv[0]);
			return 1;
		}
	}

	//~ argc -= optind;
	//~ argv += optind;


	if (pipe(parent_to_write) == -1)
		err(1, "pipe");

	write_pid = fork();
	if (write_pid == (pid_t) 0) {

		FILE *pkg_write = NULL;

		close(parent_to_write[STDOUT_FILENO]);

		if (getuid() == 0) {
			if (pledge("stdio wpath cpath rpath", NULL) == -1) {
				fprintf(stderr, "pledge\n");
				_exit(EXIT_FAILURE);
			}
		} else {
			if (pledge("stdio rpath", NULL) == -1) {
				fprintf(stderr, "pledge\n");
				_exit(EXIT_FAILURE);
			}
		}

		input = fdopen(parent_to_write[STDIN_FILENO], "r");
		if (input == NULL) {
			fprintf(stderr,"fdopen ");
			fprintf(stderr,"parent_to_write[STDIN_FILENO]\n");
			_exit(EXIT_FAILURE);
		}
		if (getuid() == 0) {
			if (pledge("stdio wpath cpath", NULL) == -1) {
				fprintf(stderr, "pledge\n");
				_exit(EXIT_FAILURE);
			}
		} else {
			if (pledge("stdio", NULL) == -1) {
				fprintf(stderr, "pledge\n");
				_exit(EXIT_FAILURE);
			}
		}


		kq = kqueue();
		if (kq == -1) {
			printf("kq\n");
			_exit(EXIT_FAILURE);
		}
		EV_SET(&ke, parent_to_write[STDIN_FILENO], EVFILT_READ,
		    EV_ADD | EV_ONESHOT, 0, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("parent_to_write[0] kevent register fail.\n");
			_exit(EXIT_FAILURE);
		}
		i = kevent(kq, NULL, 0, &ke, 1, NULL);
		if (i == -1) {
			fprintf(stderr, "kevent\n");
			_exit(EXIT_FAILURE);
		}
		close(kq);
		/*
		 * kqueue is used in this fork(), purely to kill the
		 * process if the pipe closes because the parent exited
		 * prematurely
		 */
		if (ke.flags & EV_EOF)
			_exit(EXIT_FAILURE);

		if (getuid() == 0) {
			pkg_write = fopen("/etc/pkg.conf", "w");
			if (pkg_write == NULL) {
				fprintf(stderr, "fopen /etc/pkg.conf, \"w\"\n");
				_exit(EXIT_FAILURE);
			}
			if (pledge("stdio", NULL) == -1) {
				fprintf(stderr, "pledge\n");
				_exit(EXIT_FAILURE);
			}
		}
		if (pkg_write != NULL) {
			if (verbose >= 2)
				printf("\n");
			printf("\nEdit out all PKG_PATH environment variable ");
			printf("exports and run \"unset PKG_PATH\".\n");
			if (verbose > 0)
				printf("\n/etc/pkg.conf:\n");
			i = 0;
			while (((c = getc(input)) != EOF) && ++i < 15000) {
				if (verbose > 0)
					printf("%c", c);
				putc(c, pkg_write);
			}
			printf("\n");
			if (i == 15000) {
				printf("i == 15000\n");
				_exit(EXIT_FAILURE);
			}
			fclose(input);
			fclose(pkg_write);
		} else if (verbose > 0) {
			if (verbose >= 2)
				printf("\n");
			printf("\nThis could have been the contents of ");
			printf("/etc/pkg.conf (run as superuser):\n");
			i = 0;
			while (((c = getc(input)) != EOF) && ++i < 15000)
				printf("%c", c);
			printf("\n");
			if (i == 15000) {
				printf("i == 15000\n");
				_exit(EXIT_FAILURE);
			}
			fclose(input);
		}
		if (argc == 1)
			manpage(argv[0]);
		_exit(0);
	}
	if (write_pid == -1)
		err(1, "fork");

	close(parent_to_write[STDIN_FILENO]);

	if (getuid() == 0) {
		setuid(1000);

		if (pledge("stdio proc exec rpath", NULL) == -1)
			err(EXIT_FAILURE, "pledge");
	}
	/* Error handled later and is not a deal-breaker */
	pkg_read = fopen("/etc/pkg.conf", "r");

	input = fopen("/etc/examples/pkg.conf", "r");

	if (pledge("stdio proc exec", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	if (input == NULL)
		err(1, "fopen /etc/examples/pkg.conf");


	struct timespec timeout;

	timeout.tv_sec = (int) s;
	timeout.tv_nsec = (int) ((s - (double) timeout.tv_sec) * 1000000000);

	kq = kqueue();
	if (kq == -1)
		err(1, "kq!");


	/* clear out the header and the '#' following it */
	while ((c = getc(input)) != EOF) {
		if (c == '\n') {
			c = getc(input);
			if (c == '\n') {
				if (getc(input) == EOF)
					errx(1, "EOF");
				break;
			}
			if (c == EOF)
				errx(1, "EOF");
		}
	}

	int space = 0;
	char *line;
	line = malloc(line_max);
	if (line == NULL)
		err(1, "malloc");
	num = 0;
	pos = 0;
	array_length = 1;
	struct mirror_st *sm;
	array[0] = (struct mirror_st *) malloc(sizeof(struct mirror_st));
	if (array[0] == NULL)
		err(1, "malloc");

	while ((c = getc(input)) != EOF) {
		if (pos >= line_max) {
			errx(1, "line[] got too long!");
		}
		if (num == 0) {
			if (c != '\n')
				line[pos++] = c;
			else {
				sm = array[array_length - 1];
				sm->label = malloc(pos);
				if (sm->label == NULL)
					err(1, "malloc");
				strlcpy(sm->label,
				    line + 1, pos);

				if (pos >= 4 && u && !strncmp("USA",
				    sm->label + pos - 4, 3)) {
					free(sm->label);
					sm->label = NULL;
					c = getc(input);
					while (c != EOF) {
						if (num == 1 &&
						    c == '\n')
							break;
						num = 0;
						if (c == '\n')
							num = 1;
						c = getc(input);
					}
					pos = 0;
					num = 0;
					space = 0;
					continue;
				}
				pos = 0;
				num = 1;
				space = 0;
			}
		} else {
			if (space < 2) {
				if (c == ' ')
					++space;
				continue;
			}
			if (c != '\n')
				line[pos++] = c;
			else {

				array[array_length - 1]->mirror = malloc(++pos);
				if (array[array_length - 1]->mirror == NULL)
					err(1, "malloc");
				strlcpy(array[array_length - 1]->mirror,
				    line, pos);


				if (++array_length >= array_max) {
					array_max += 25;
					array = reallocarray(array, array_max,
					    sizeof(struct mirror_st));

					if (array == NULL)
						err(1, "reallocarray");
				}
				array[array_length - 1]
				    = (struct mirror_st *)
				    calloc(1, sizeof(struct mirror_st));

				if (array[array_length - 1] == NULL) 
					err(1, "calloc");
				pos = 0;
				num = 0;
				space = 0;

				if ((c = getc(input)) == '\n') {
					c = getc(input);
					if (c == EOF)
						break;
					continue;
				}
				if (c == EOF)
					break;

				pos = strlen(array[array_length - 2]->label);
				array[array_length - 1]->label = malloc(++pos);
				if (array[array_length - 1]->label == NULL) 
					err(1, "malloc");
				strlcpy(array[array_length - 1]->label,
				    array[array_length - 2]->label, pos);
				num = 1;
				pos = 0;
			}
		}
	}

	fclose(input);


	if (--array_length == 0)
		errx(1, "No mirrors found.");

	free(array[array_length]);

	int mirror_num = array_length;


	char *ftp_file;

	qsort(array, mirror_num, sizeof(struct mirror_st *), label_cmp);

	for (c = 0; c < mirror_num; ++c) {

		pos = strlcpy(line, array[c]->mirror, line_max) + 1;

		if (pos >= 16) {
			if (!strncmp(line + pos - 16, "%c/packages/%a/", 15)) {
				line[pos - 16] = '\0';
				pos -= 15;
			}
		}

		if (!strncmp(line, "http://", 7));
		else if ((pos + 7) < line_max) {
			memmove(line + 7, line, pos);
			pos += 7;
			memcpy(line, "http://", 7);
		} else
			err(1, "line got too long");

		if (line[pos - 2] != '/') {
			if (pos + 13 >= line_max)
				err(1, "line got too long");
			else {
				strlcpy(line + pos - 1,
				    "/pub/OpenBSD/", 13 + 1);
				pos += 13;
			}
		}
		pos += strlen(name.release) + 1 + strlen(name.machine)
		    + strlen("/SHA256");

		ftp_file = malloc(pos);
		if (ftp_file == NULL)
			err(1, "malloc");

		strlcpy(ftp_file,         line, pos);
		strlcat(ftp_file, name.release, pos);
		strlcat(ftp_file,          "/", pos);
		strlcat(ftp_file, name.machine, pos);
		strlcat(ftp_file,    "/SHA256", pos);

		if (verbose >= 2) {
			if (mirror_num >= 100) {
				printf("\n%3d : %s  :  %s\n", mirror_num - c,
				    array[c]->label, ftp_file);
			} else {
				printf("\n%2d : %s  :  %s\n", mirror_num - c,
				    array[c]->label, ftp_file);
			}
		} else {
			i = mirror_num - c;
			if ((i == 99) || (i == 9))
				printf("\b \b\b\b%d", i);
			else
				printf("\b\b\b%d", i);
			fflush(stdout);
		}




		ftp_pid = fork();
		if (ftp_pid == -1)
			err(1, "fork");

		if (ftp_pid == (pid_t) 0) {
			if (verbose >= 2) {
				execl("/usr/bin/ftp", "ftp", "-Vmo",
				    "/dev/null", ftp_file, NULL);
			} else {
				i = open("/dev/null", O_WRONLY);
				if (i != -1)
					dup2(i, STDERR_FILENO);
				execl("/usr/bin/ftp", "ftp", "-VMo",
				    "/dev/null", ftp_file, NULL);
			}
			err(1, "ftp execl() failed.");
		}
		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
		    NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			kill(ftp_pid, SIGKILL);
			errx(EXIT_FAILURE, "kevent register fail.");
		}
		array[c]->diff = 0;
		struct timeval tv_start, tv_end;
		gettimeofday(&tv_start, NULL);

		/* Loop until ftp() is dead and 'ke' is populated */
		for (;;) {
			i = kevent(kq, NULL, 0, &ke, 1, &timeout);
			if (i == -1) {
				kill(ftp_pid, SIGKILL);
				errx(1, "kevent");
			}
			if (i == 0) {
				if (verbose >= 2)
					printf("\nTimeout\n");
				kill(ftp_pid, SIGKILL);
				array[c]->diff = s;
			} else
				break;
		}

		if (ke.data == 0) {
			gettimeofday(&tv_end, NULL);
			array[c]->diff = get_time_diff(tv_start, tv_end);
			if (array[c]->diff > s) {
				if (verbose >= 2)
					printf("%f (Timeout)\n",array[c]->diff);
				array[c]->diff = s;
			} else if (verbose >= 2)
				printf("%f\n", array[c]->diff);
		} else if (array[c]->diff == 0) {
			array[c]->diff = s + 1;
			if (verbose >= 2)
				printf("Download Error\n");
		}
		free(ftp_file);
	}

	free(line);
		
	if (pledge("stdio", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	if (verbose < 2) {
		printf("\b \b");
		fflush(stdout);
	}
	qsort(array, mirror_num, sizeof(struct mirror_st *), ftp_cmp);

	if (verbose == 3) {
		printf("\n\n");
		for (c = mirror_num - 1; c >= 0; --c) {

			if (array[c]->diff < s) {
				if (c > (n - 1)) {
					if (mirror_num >= 100) {
						printf("%3d : %s:\n\t%s : ",
						    c + 1, array[c]->label,
						    array[c]->mirror);
					    } else {
						printf("%2d : %s:\n\t%s : ",
						    c + 1, array[c]->label,
						    array[c]->mirror);
					    }

					printf("%f\n\n", array[c]->diff);
				}
			} else {
				if (mirror_num >= 100) {
					printf("%3d : %s:\n\t%s : ", c + 1,
					    array[c]->label, array[c]->mirror);
				} else {
					printf("%2d : %s:\n\t%s : ", c + 1,
					    array[c]->label, array[c]->mirror);
				}

				if (array[c]->diff == s)
					printf("Timeout\n\n");
				else
					printf("Download Error\n\n");
			}
		}
	}
	if (array[0]->diff >= s)
		errx(1, "No mirrors found within timeout period.");

	char *buf;
	int lines;
	int copy;
	int j;
	int label_length;

	if (mirror_num == 0)
		return 0;

	if (n < mirror_num)
		mirror_num = n;

	c = dup2(parent_to_write[STDOUT_FILENO], STDOUT_FILENO);
	if (c == -1)
		err(1, "dup2");

	if (pkg_read == NULL) {
		printf("\n");
		goto skip;
	}
	fseek(pkg_read, 0, SEEK_END);
	if (ftell(pkg_read) > (uint32_t)0x7FffFFff)
		errx(1, "example file is too large.");
	num = ftell(pkg_read);
	fseek(pkg_read, 0, SEEK_SET);
	buf = (char *) malloc(num + 11 + 1);
	if (buf == NULL)
		err(1, "malloc");
	fread(buf, 1, num, pkg_read);
	fclose(pkg_read);

	lines = 0;
	for (c = 0; c < num; ++c) {
		if (buf[c] == '\n')
			++lines;
	}

/* erase installpath lines from buf: length 'c' into buf: length 'copy' */
	copy = 0;
	pos = 0;
	for (c = 0; c < num; ++c) {
		if (buf[c] == '\n') {
			--lines;
			if (pos == 0)
				continue;
			pos = 0;
		} else if (pos++ == 0) {
			if (buf[c] == '#') {
				if (lines == 0)
					break;
				i = c;
				j = lines;

		back:

				while (buf[++i] != '\n');
				--j;
				++i;
				while ((buf[i] == ' ') && (i < num))
					++i;
				if (i >= num) {
					buf[copy++] = buf[c];
					continue;
				}
				if (buf[i] == '\n') {
					buf[copy++] = buf[c];
					continue;
				}
				if (buf[i] == '#') {
					if (j)
						goto back;
					buf[copy++] = buf[c];
					continue;
				}
				if (strncmp(buf + i, "installpath", 11)) {
					buf[copy++] = buf[c];
					continue;
				}
				if (!j)
					break;
				lines = j;
				c = i + 11;

				while (buf[++c] != '\n');
				--lines;
				pos = 0;
				continue;
			} else if (!strncmp(buf + c, "installpath", 11)) {
				if (lines == 0)
					break;
				while (buf[++c] != '\n');
				--lines;
				pos = 0;
				continue;
			} else if (buf[c] == ' ') {
				pos = 0;
				continue;
			}
		}
		buf[copy++] = buf[c];
	}
	
	if (copy) {
		buf[copy] = '\0';
		if (buf[copy - 1] != '\n')
			printf("%s\n", buf);
		else
			printf("%s", buf);
	}
	free(buf);

skip:
	label_length = strlen(array[0]->label);
	for (pos = 1; pos < mirror_num; ++pos) {
		if (array[pos]->diff >= s)
			break;
		j = strlen(array[pos]->label);
		if (j > label_length)
			label_length = j;
	}
	
	for (pos = 0; pos < mirror_num; ++pos) {

		/* Eliminates download error and timeout mirrors */
		if (array[pos]->diff >= s)
			break;
		if (mirror_num >= 100)
			printf("\n# %3d : ", pos + 1);
		else if (mirror_num >= 10)
			printf("\n# %2d : ", pos + 1);
		else
			printf("\n# %d : ", pos + 1);
		
		
		copy = strlen(array[pos]->label);
		if ((label_length - copy) % 2)
			printf(" ");

		for (j = (label_length - copy) / 2; j > 0; --j)
			printf(" ");

		printf("%s", array[pos]->label);
		
		for (j = (label_length - copy) / 2; j > 0; --j)
			printf(" ");


		printf(" : %fs\n", array[pos]->diff);
		
		if (pos == 0)
			printf("installpath  = %s\n", array[pos]->mirror);
		else
			printf("installpath += %s\n", array[pos]->mirror);
	}
	
	fflush(stdout);
	close(parent_to_write[STDOUT_FILENO]);
	close(STDOUT_FILENO);

	for(j = array_length - 1; j >= 0;--j)
	{
		free(array[j]->label);
		free(array[j]->mirror);
		free(array[j]);
	}
	
	wait(&c);

	return c;
}

