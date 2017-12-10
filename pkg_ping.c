/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2017, Luke N Small, lukensmall@gmail.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
 * indent pkg_ping.c -bap -br -ce -ci4 -cli0 -d0 -di0 -i8 -ip -l79 -nbc -ncdb \
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
	int64_t sec;
	int64_t usec;
	double temp;
	sec = (int64_t) b.tv_sec - (int64_t) a.tv_sec;
	usec = (int64_t) b.tv_usec - (int64_t) a.tv_usec;
	if (usec < 0) {
		--sec;
		usec += 1000000;
	}
	temp = (double) usec;
	temp /= (double)1000000.0;
	temp += (double) sec;
	return temp;
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
	int tag_len;
	FILE *input;
	struct utsname name;
	struct mirror_st **array;
	struct kevent ke;
	char *tag;

	array_max = 300;

	array = (struct mirror_st **)
	    calloc(array_max, sizeof(struct mirror_st *));
	if (array == NULL)
		err(EXIT_FAILURE, "calloc");

	s = 5;
	n = 5000;
	u = 0;
	verbose = 0;

	if (uname(&name) == -1)
		err(EXIT_FAILURE, "uname");
		
	tag_len = strlen("/") + strlen(name.release) + strlen("/") +
				strlen(name.machine) + strlen("/SHA256");
				
	tag = (char*)malloc(tag_len - 1 + 1);
	if (tag == NULL) err(1, "malloc");
	
	strlcpy(tag, name.release, tag_len);
	strlcat(tag,          "/", tag_len);
	strlcat(tag, name.machine, tag_len);
	strlcat(tag,    "/SHA256", tag_len);

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
						errx(EXIT_FAILURE, "No negative numbers.");
					printf("Incorrect floating ");
					printf("point format.");
					return 1;
				}
			}
			errno = 0;
			strtod(optarg, NULL);
			if (errno == ERANGE)
				err(EXIT_FAILURE, "strtod");
			if ((s = strtod(optarg, NULL)) > 1000.0)
				errx(EXIT_FAILURE, "-s should <= 1000");
			if (s <= 0.01)
				errx(EXIT_FAILURE, "-s should be > 0.01");
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
			return 1;
		default:
			manpage(argv[0]);
			return 1;
		}
	}

	//~argc -= optind;
	//~argv += optind;




	if (pipe(parent_to_write) == -1)
		err(EXIT_FAILURE, "pipe");

	write_pid = fork();
	if (write_pid == (pid_t) 0) {
		if (getuid() == 0) {
			if (pledge("stdio wpath cpath", NULL) == -1) {
				printf("pledge\n");
				_exit(EXIT_FAILURE);
			}
		} else if (pledge("stdio", NULL) == -1) {
			printf("pledge\n");
			_exit(EXIT_FAILURE);
		}
		close(parent_to_write[STDOUT_FILENO]);
		if (dup2(parent_to_write[STDIN_FILENO], STDIN_FILENO) == -1) {
			printf("dup2\n");
			_exit(EXIT_FAILURE);
		}
		kq = kqueue();
		if (kq == -1) {
			printf("kq!\n");
			_exit(EXIT_FAILURE);
		}
		EV_SET(&ke, parent_to_write[STDIN_FILENO], EVFILT_READ,
		    EV_ADD | EV_ONESHOT, 0, 0, NULL);

		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			printf("parent_to_write kevent register fail.\n");
			_exit(EXIT_FAILURE);
		}
		i = kevent(kq, NULL, 0, &ke, 1, NULL);
		if (i == -1) {
			printf("parent_to_write pipe failed.\n");
			_exit(EXIT_FAILURE);
		}
		if (i == 0) {
			printf("parent_to_write pipe signal received.\n");
			_exit(EXIT_FAILURE);
		}
		FILE *pkg_write;
		if (getuid() == 0) {
			pkg_write = fopen("/etc/installurl", "w");

			if (pledge("stdio", NULL) == -1) {
				printf("pledge\n");
				_exit(EXIT_FAILURE);
			}
		} else
			pkg_write = NULL;

		input = fdopen(parent_to_write[STDIN_FILENO], "r");
		if (input == NULL) {
			printf("input = fdopen (parent_to_write[0], \"r\") ");
			printf("failed.\n");
			_exit(EXIT_FAILURE);
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
		close(parent_to_write[STDIN_FILENO]);

		_exit(0);
	}
	if (write_pid == -1)
		err(EXIT_FAILURE, "fork");

	close(parent_to_write[STDIN_FILENO]);
	setuid(1000);

	if (pledge("stdio proc exec", NULL) == -1)
		err(EXIT_FAILURE, "pledge");


	struct timespec timeout0 = {20, 0};
	struct timespec timeout;

	timeout.tv_sec = (int) s;
	timeout.tv_nsec = (int) ((s - (double) timeout.tv_sec) * 1000000000);

	kq = kqueue();
	if (kq == -1)
		err(EXIT_FAILURE, "kq!");


	if (pipe(ftp_to_sed) == -1)
		err(EXIT_FAILURE, "pipe");


	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {

		if (pledge("stdio exec", NULL) == -1)
			err(EXIT_FAILURE, "pledge");

		close(ftp_to_sed[STDIN_FILENO]);
		if (dup2(ftp_to_sed[STDOUT_FILENO], STDOUT_FILENO) == -1)
			err(EXIT_FAILURE, "dup2");

		execl("/usr/bin/ftp", "ftp", "-Vo", "-",
		    "https://www.openbsd.org/ftp.html", NULL);

		if (pledge("stdio", NULL) == -1)
			err(EXIT_FAILURE, "pledge");

		err(EXIT_FAILURE, "ftp execl() failed.");
	}
	if (ftp_pid == -1)
		err(EXIT_FAILURE, "fork");

	close(ftp_to_sed[STDOUT_FILENO]);

	if (pipe(sed_to_parent) == -1)
		err(EXIT_FAILURE, NULL);

	sed_pid = fork();
	if (sed_pid == (pid_t) 0) {

		close(sed_to_parent[STDIN_FILENO]);
		
		if (dup2(ftp_to_sed[STDIN_FILENO], STDIN_FILENO) == -1) {
			kill(ftp_pid, SIGKILL);
			errx(EXIT_FAILURE, "dup2");
		}
		if (dup2(sed_to_parent[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			kill(ftp_pid, SIGKILL);
			errx(EXIT_FAILURE, "dup2");
		}
		execl("/usr/bin/sed", "sed", "-n",
		    "-e", "s:</a>$::",
		    "-e", "s:\t<strong>\\([^<]*\\)<.*:\\1:p",
		    "-e", "s:^\\(\t[hfr].*\\):\\1:p", NULL);

		if (pledge("stdio proc", NULL) == -1)
			err(EXIT_FAILURE, "pledge");

		kill(ftp_pid, SIGKILL);
		errx(EXIT_FAILURE, "sed execl() failed.");
	}
	if (sed_pid == -1) {
		kill(ftp_pid, SIGKILL);
		err(EXIT_FAILURE, "fork");
	}
	close(ftp_to_sed[STDIN_FILENO]);
	close(sed_to_parent[STDOUT_FILENO]);

	EV_SET(&ke, sed_to_parent[STDIN_FILENO], EVFILT_READ,
	    EV_ADD | EV_ONESHOT, 0, 0, NULL);
	if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(EXIT_FAILURE, "sed_to_parent kevent register fail.");
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
		errx(EXIT_FAILURE,
		    "input = fdopen (sed_to_parent[0], \"r\") failed.");
	}
	char line[300];
	num = 0;
	pos = 0;
	array_length = 0;
	array[0] = malloc(sizeof(struct mirror_st));
	if (array[0] == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(EXIT_FAILURE, "malloc");
	}
	while ((c = getc(input)) != EOF) {
		if (pos >= 300) {
			kill(ftp_pid, SIGKILL);
			kill(sed_pid, SIGKILL);
			errx(EXIT_FAILURE, "pos got too big!");
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
					errx(EXIT_FAILURE, "malloc");
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

				pos += tag_len - 1;


				array[array_length]->ftp_file = malloc(pos);
				if (array[array_length]->ftp_file == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc");
				}
				strlcpy(array[array_length]->ftp_file,
				    line, pos);

				strlcat(array[array_length]->ftp_file,
				    tag, pos);

				if (++array_length > array_max) {
					array_max += 100;
					array = reallocarray(array, array_max,
					    sizeof(struct mirror_st));

					if (array == NULL)
						err(EXIT_FAILURE, "reallocarray");
				}
				array[array_length]
				    = (struct mirror_st *)
				    malloc(sizeof(struct mirror_st));

				if (array[array_length] == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(EXIT_FAILURE, "malloc");
				}
				pos = 0;
				num = 0;
			}
		}
	}

	fclose(input);

	close(sed_to_parent[STDIN_FILENO]);

	waitpid(ftp_pid, NULL, 0);
	waitpid(sed_pid, NULL, 0);

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
			if (c > 0) {
				if ((i == 9) || (i == 99))
					printf("\b \b");
				n = i;
				while (n > 0) {
					printf("\b");
					n /= 10;
				}
			}
			printf("%d", i);
			fflush(stdout);
		}

		int block_pipe[2];
		struct timeval tv_start, tv_end;

		if (pipe(block_pipe) == -1)
			err(EXIT_FAILURE, "pipe!");

		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {

			if (pledge("stdio exec", NULL) == -1)
				err(EXIT_FAILURE, "pledge");

			close(block_pipe[STDOUT_FILENO]);
			read(block_pipe[STDIN_FILENO], &n, sizeof(int));
			close(block_pipe[STDIN_FILENO]);

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

			if (pledge("stdio", NULL) == -1)
				err(EXIT_FAILURE, "pledge");

			err(EXIT_FAILURE, "ftp execl() failed.");
		}
		if (ftp_pid == -1)
			err(EXIT_FAILURE, "fork");


		close(block_pipe[STDIN_FILENO]);

		EV_SET(&ke, ftp_pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
		    NOTE_EXIT, 0, NULL);
		if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
			kill(ftp_pid, SIGKILL);
			err(EXIT_FAILURE, "kevent register fail.");
		}
		gettimeofday(&tv_start, NULL);

		close(block_pipe[STDOUT_FILENO]);

		array[c]->diff = 0;



		/* Loop until ftp() is dead and 'ke' is populated */
		for (;;) {
			i = kevent(kq, NULL, 0, &ke, 1, &timeout);
			if (i == -1) {
				kill(ftp_pid, SIGKILL);
				errx(EXIT_FAILURE, "kevent");
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
		waitpid(ftp_pid, NULL, 0);
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
			array[c]->ftp_file[strlen(array[c]->ftp_file) - tag_len] = '\0';
			printf("%d : %s:\n\t%s : ", c + 1, array[c]->label,
			    array[c]->ftp_file);

			if (array[c]->diff < s)
				printf("%f\n\n", array[c]->diff);
			else if (array[c]->diff == s)
				printf("Timeout\n\n");
			else
				printf("Download Error\n\n");
		}
	}
	else
		array[0]->ftp_file[strlen(array[0]->ftp_file) - tag_len] = '\0';
		
	if (array[0]->diff >= s)
		errx(EXIT_FAILURE, "No mirrors found within timeout period.");

	if (dup2(parent_to_write[STDOUT_FILENO], STDOUT_FILENO) == -1) {
		printf("%s\n", array[0]->ftp_file);
		close(parent_to_write[STDOUT_FILENO]);
		wait(NULL);
		return 1;
	}

	printf("%s\n", array[0]->ftp_file);
	fflush(stdout);
	close(parent_to_write[STDOUT_FILENO]);
	close(STDOUT_FILENO);

	wait(&c);

	return c;
}
