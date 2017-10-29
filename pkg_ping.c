/*
 * Copyright (c) 2017 Luke N. Small
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/*
 * Special thanks to Dan Mclaughlin for the ftp to sed idea
 *
 * ftp -o - http://www.openbsd.org/ftp.html | \
 * sed -n \
 *  -e 's:</a>$::' \
 * 	-e 's:	<strong>\([^<]*\)<.*:\1:p' \
 * 	-e 's:^\(	[hfr].*\):\1:p'
 */

/*
 * indent pkg_ping3.c -bap -br -ce -ci4 -cli0 -d0 -di0 -i8 -ip -l79 -nbc -ncdb \
 * -ndj -ei -nfc1 -nlp -npcs -psl -sc -sob
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
	char *ftp_file;
	char *mirror;
	double diff;
};

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
	return 0;
}

static int
label_cmp(const void *a, const void *b)
{
	struct mirror_st **one;
	struct mirror_st **two;
	int8_t temp;

	one = (struct mirror_st **) a;
	two = (struct mirror_st **) b;

	/* list the USA mirrors first, it will subsort correctly */
	temp = !strncmp("USA", (*one)->label, 3);
	if (temp != !strncmp("USA", (*two)->label, 3)) {
		if (temp)
			return -1;
		return 1;
	}
	return strcmp((*one)->label, (*two)->label);
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
	
	printf("[-s timeout (floating-point)]\n");
	
	printf("[-h (print this message and exit)]\n");
}

int
main(int argc, char *argv[])
{
	if (pledge("stdio wpath cpath proc exec id getpw", NULL) == -1)
		err(EXIT_FAILURE, "pledge");
	pid_t ftp_pid, sed_pid, write_pid;
	int ftp_to_sed[2];
	int sed_to_parent[2];
	int parent_to_write[2];
	double s;
	int kq, i, pos, num, c, n, array_max, array_length, u, verbose;
	FILE *input;
	struct utsname name;
	struct mirror_st **array;
	struct kevent ke;

	array_max = 300;

	array = (struct mirror_st **)
	    calloc(array_max, sizeof(struct mirror_st *));
	if (array == NULL)
		err(1, "calloc");

	s = 5;
	n = 5000;
	u = 0;
	verbose = 0;

	if (uname(&name) == -1)
		err(1, NULL);

	while ((c = getopt(argc, argv, "s:vuh")) != -1) {
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
				err(1, "strtod");
			if ((s = strtod(optarg, NULL)) > 1000.0)
				errx(1, "-s should <= 1000");
			if (s <= 0.01)
				errx(1, "-s should be > 0.01");
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
			exit(0);
		default:
			manpage(argv[0]);
			exit(1);
		}
	}

	//~argc -= optind;
	//~argv += optind;




	if (pipe(parent_to_write) == -1)
		err(1, NULL);

	write_pid = fork();
	if (write_pid == (pid_t) 0) {
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
		close(parent_to_write[1]);
		if (dup2(parent_to_write[0], STDIN_FILENO) == -1)
			err(1, NULL);

		kq = kqueue();
		if (kq == -1)
			err(1, "kq!");

		EV_SET(&ke, parent_to_write[0], EVFILT_READ,
		    EV_ADD | EV_ONESHOT, 0, 0, NULL);

		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("parent_to_write kevent register fail.\n");
			_exit(1);
		}
		i = kevent(kq, NULL, 0, &ke, 1, NULL);
		if (i == -1) {
			printf("parent_to_write pipe failed.\n");
			_exit(1);
		}
		if (i == 0) {
			printf("parent_to_write pipe signal received.\n");
			_exit(1);
		}
		FILE *pkg_write;
		if (getuid() == 0) {
			pkg_write = fopen("/etc/installurl", "w");

			if (pledge("stdio", NULL) == -1) {
				printf("pledge\n");
				_exit(1);
			}
		} else
			pkg_write = NULL;

		input = fdopen(parent_to_write[0], "r");
		if (input == NULL) {
			printf("input = fdopen (parent_to_write[0], \"r\") ");
			printf("failed.\n");
			_exit(1);
		}
		if (pkg_write != NULL) {
			if (verbose > 1)
				printf("\n\n");
			if (verbose > 0)
				printf("/etc/installurl: ");
			while ((c = getc(input)) != EOF) {
				if (verbose > 0)
					printf("%c", c);
				putc(c, pkg_write);
			}
			fclose(pkg_write);
		} else if (verbose > 0) {
			if (verbose > 1)
				printf("\n");
			printf("\nThis could have been the contents of ");
			printf("/etc/installurl (run as superuser):\n");
			while ((c = getc(input)) != EOF)
				printf("%c", c);
		}
		fclose(input);
		close(parent_to_write[0]);

		_exit(0);
	}
	if (write_pid == -1)
		err(1, "fork");

	close(parent_to_write[0]);
	setuid(1000);

	if (pledge("stdio proc exec", NULL) == -1)
		err(EXIT_FAILURE, "pledge");


	struct timespec timeout0 = {20, 0};
	struct timespec timeout;

	timeout.tv_sec = (int) s;
	timeout.tv_nsec = (int) ((s - (double) timeout.tv_sec) * 1000000000);

	kq = kqueue();
	if (kq == -1)
		err(1, "kq!");


	if (pipe(ftp_to_sed) == -1)
		err(1, "pipe");


	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

		if (pledge("stdio exec", NULL) == -1)
			err(EXIT_FAILURE, "pledge");

		close(ftp_to_sed[STDIN_FILENO]);
		if (dup2(ftp_to_sed[STDOUT_FILENO], STDOUT_FILENO) == -1)
			err(1, "dup2");

		execl("/usr/bin/ftp", "ftp", "-Vo", "-",
		    "https://www.openbsd.org/ftp.html", NULL);
		err(1, "ftp execl() failed.");
	}
	if (ftp_pid == -1)
		err(1, "fork");

	close(ftp_to_sed[STDOUT_FILENO]);

	if (pipe(sed_to_parent) == -1)
		err(1, NULL);

	sed_pid = fork();
	if (sed_pid == (pid_t) 0) {

		if (pledge("stdio exec", NULL) == -1)
			err(EXIT_FAILURE, "pledge");

		close(sed_to_parent[STDIN_FILENO]);
		if (dup2(ftp_to_sed[STDIN_FILENO], STDIN_FILENO) == -1) {
			kill(ftp_pid, SIGKILL);
			errx(1, "dup2");
		}
		if (dup2(sed_to_parent[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			kill(ftp_pid, SIGKILL);
			errx(1, "dup2");
		}
		execl("/usr/bin/sed", "sed", "-n",
		    "-e", "s:</a>$::",
		    "-e", "s:\t<strong>\\([^<]*\\)<.*:\\1:p",
		    "-e", "s:^\\(\t[hfr].*\\):\\1:p", NULL);
		kill(ftp_pid, SIGKILL);
		errx(1, "sed execl() failed.");
	}
	if (sed_pid == -1) {
		kill(ftp_pid, SIGKILL);
		err(1, NULL);
	}
	close(ftp_to_sed[STDIN_FILENO]);
	close(sed_to_parent[STDOUT_FILENO]);

	EV_SET(&ke, sed_to_parent[STDIN_FILENO], EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(1, "sed_to_parent kevent register fail.");
	}
	i = kevent(kq, NULL, 0, &ke, 1, &timeout0);
	if (i == -1) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		printf("kevent, timeout may be too large.\n");
		manpage(argv[0]);
	}
	if (i == 0) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		printf("timed out fetching openbsd.org/ftp.html\n");
		manpage(argv[0]);
	}
	input = fdopen(sed_to_parent[STDIN_FILENO], "r");
	if (input == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(1, "input = fdopen (sed_to_parent[0], \"r\") failed.");
	}
	char line[300];
	num = 0;
	pos = 0;
	array_length = 0;
	array[0] = malloc(sizeof(struct mirror_st));
	if (array[0] == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(1, "malloc failed.");
	}
	while ((c = getc(input)) != EOF) {
		if (pos >= 300) {
			kill(ftp_pid, SIGKILL);
			kill(sed_pid, SIGKILL);
			errx(1, "line[] got too long!");
		}
		if (num == 0) {
			if (c != '\n')
				line[pos++] = c;
			else {
				line[pos++] = '\0';
				if (u && pos >= 3) {
					if (!strncmp("USA", line, 3)) {
						c = getc(input);
						while (c != EOF) {
							if (c == '\n')
								break;
							c = getc(input);
						}
						array[array_length]->label
						    = NULL;
						if (c == EOF)
							break;
						pos = 0;
						continue;
					}
				}
				array[array_length]->label = malloc(pos);
				if (array[array_length]->label == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc failed.");
				}
				strlcpy(array[array_length]->label, line, pos);

				pos = 0;
				num = 1;
			}
		} else {
			if (pos == 0) {
				if ((c != 'h') && (c != 'f') && (c != 'r'))
					continue;
				else if (c != 'h')
					break;
			}
			if (pos == 5) {
				if (strncmp(line, "https", 5))
					break;
			}
			if (c != '\n')
				line[pos++] = c;
			else {
				line[pos++] = '\0';

				pos += num = strlen(name.release) + 1
				    + strlen(name.machine) + strlen("/SHA256");



				array[array_length]->ftp_file = malloc(pos);
				if (array[array_length]->ftp_file == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc");
				}
				strlcpy(array[array_length]->ftp_file,
				    line, pos);

				strlcat(array[array_length]->ftp_file,
				    name.release, pos);

				strlcat(array[array_length]->ftp_file,
				    "/", pos);

				strlcat(array[array_length]->ftp_file,
				    name.machine, pos);

				strlcat(array[array_length]->ftp_file,
				    "/SHA256", pos);

				/* intentionally strip off the trailing '/' */
				pos -= num + 1;
				array[array_length]->mirror = malloc(pos);
				if (array[array_length]->mirror == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc");
				}
				strlcpy(array[array_length]->mirror, line, pos);

				if (++array_length > array_max) {
					array_max += 100;
					array = reallocarray(array, array_max,
					    sizeof(struct mirror_st));

					if (array == NULL)
						err(1, "reallocarray");
				}
				array[array_length]
				    = (struct mirror_st *)
				    malloc(sizeof(struct mirror_st));

				if (array[array_length] == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc");
				}
				pos = 0;
				num = 0;
			}
		}
	}

	fclose(input);

	close(sed_to_parent[STDIN_FILENO]);

	if (array_length == 0)
		errx(1, "No mirrors found.");

	free(array[array_length]->label);
	free(array[array_length]);



	qsort(array, array_length, sizeof(struct mirror_st *), label_cmp);


	double S = s;

	for (c = 0; c < array_length; ++c) {
		if (verbose >= 2) {
			if (array_length >= 100) {
				printf("\n%3d : %s  :  %s\n", array_length - c,
				    array[c]->label, array[c]->ftp_file);
			} else {
				printf("\n%2d : %s  :  %s\n", array_length - c,
				    array[c]->label, array[c]->ftp_file);
			}
		} else {
			i = array_length - c;
			if ((i == 9) || (i == 99))
				printf("\b \b\b\b%d", i);
			else
				printf("\b\b\b%d", i);
			fflush(stdout);
		}


		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {
			if (verbose >= 2) {
				execl("/usr/bin/ftp", "ftp", "-Vmo",
				    "/dev/null", array[c]->ftp_file, NULL);
			} else {
				i = open("/dev/null", O_WRONLY);
				if (i != -1)
					dup2(i, STDERR_FILENO);
				execl("/usr/bin/ftp", "ftp", "-VMo",
				    "/dev/null", array[c]->ftp_file, NULL);
			}
			err(1, "ftp execl() failed.");
		}
		if (ftp_pid == -1)
			err(1, "fork");
		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
		    NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			kill(ftp_pid, SIGKILL);
			err(EXIT_FAILURE, "kevent register fail.");
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
		
		waitpid(ftp_pid, NULL, 0);

		if (ke.data == 0) {
			gettimeofday(&tv_end, NULL);
			array[c]->diff = get_time_diff(tv_start, tv_end);
			if (verbose >= 2) {
				if (array[c]->diff > s)
					array[c]->diff = s;
				else
					printf("%f\n", array[c]->diff);
			} else {
				S = array[c]->diff;
				timeout.tv_sec = (int) S;
				timeout.tv_nsec =
				    (int) ((S - (double) timeout.tv_sec)
				    * 1000000000);
			}
		} else if (array[c]->diff == 0) {
			array[c]->diff = s + 1;
			if (verbose >= 2)
				printf("Download Error\n");
		}
	}

	if (pledge("stdio", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	if (verbose < 2) {
		printf("\b \b");
		fflush(stdout);
	}
	qsort(array, array_length, sizeof(struct mirror_st *), ftp_cmp);


	if (verbose == 3) {
		printf("\n\n");
		for (c = array_length - 1; c >= 0; --c) {
			printf("%d : %s:\n\t%s : ", c + 1, array[c]->label,
			    array[c]->mirror);

			if (array[c]->diff < s)
				printf("%f\n\n", array[c]->diff);
			else if (array[c]->diff == s)
				printf("Timeout\n\n");
			else
				printf("Download Error\n\n");
		}
	}
	if (array[0]->diff >= s)
		errx(1, "No mirrors found within timeout period.");

	if (dup2(parent_to_write[STDOUT_FILENO], STDOUT_FILENO) == -1) {
		kill(write_pid, SIGKILL);
		printf("%s\n", array[0]->mirror);
		return 1;
	}
	printf("%s\n", array[0]->mirror);
	fflush(stdout);
	close(parent_to_write[STDOUT_FILENO]);
	close(STDOUT_FILENO);

	wait(&c);

	return c;
}
