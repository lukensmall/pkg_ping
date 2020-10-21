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
 * Special thanks to Dan Mclaughlin for the ftp to sed idea
 *
 * ftp -o - http://www.openbsd.org/ftp.html | \
 * sed -n \
 *  -e 's:</a>$::' \
 * 	-e 's:	<strong>\([^<]*\)<.*:\1:p' \
 * 	-e 's:^\(	[hfr].*\):\1:p'
 *
 * indent pkg_ping.c -bap -br -ce -ci4 -cli0 -d0 -di0 -i8 -ip -l79 -nbc -ncdb \
 * -ndj -ei -nfc1 -nlp -npcs -psl -sc -sob
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


#define EVENT_NOPOLL
#define EVENT_NOSELECT

#include <err.h>
#include <errno.h>
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

void
manpage(char *a)
{
	printf("%s [-n maximum_mirrors_written] [-s timeout] ", a);
	printf("[-u (no USA mirrors)]");
}

int
main(int argc, char *argv[])
{
	if(pledge("stdio wpath cpath rpath proc exec id getpw", NULL) == -1)
		err(EXIT_FAILURE, "pledge");
	pid_t ftp_pid, sed_pid, write_pid;
	int ftp_to_sed[2];
	int sed_to_parent[2];
	int parent_to_write[2];
	double s;
	int kq, i, pos, num, c, n, array_max, array_length, u;
	FILE *input, *pkgRead;
	struct utsname name;
	struct mirror_st **array;
	struct kevent ke;


	pkgRead = fopen("/etc/pkg.conf", "r");

	array_max = 300;

	if ((array = calloc(array_max, sizeof(struct mirror_st *))) == NULL)
		errx(1, "calloc failed.");

	s = 5;
	n = 5000;
	u = 0;

	if (uname(&name) == -1)
		err(1, NULL);

	while ((c = getopt(argc, argv, "s:n:u")) != -1) {
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
			if (s <= 0.01)
				errx(1, "-s should be > 0.01");
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
		case 'u':
			u = 1;
			break;
		default:
			manpage(argv[0]);
		}
	}

	//~ argc -= optind;
	//~ argv += optind;




	if (pipe(parent_to_write) == -1)
		err(1, NULL);

	write_pid = fork();
	if (write_pid == (pid_t) 0) {
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
		close(parent_to_write[1]);
		if (dup2(parent_to_write[0], STDIN_FILENO) == -1)
			err(1, NULL);
		kq = kqueue();

		EV_SET(&ke, parent_to_write[0], EVFILT_READ, EV_ADD | EV_ONESHOT,
		    0, 0, NULL);
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
		input = fdopen(parent_to_write[0], "r");
		if (input == NULL) {
			printf("input = fdopen (parent_to_write[0], \"r\") failed.\n");
			_exit(1);
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

		FILE *PkgWrite;
		if (getuid() == 0) {
			PkgWrite = fopen("/etc/pkg.conf", "w");
			
			if(pledge("stdio", NULL) == -1) {
				printf("pledge\n");
				_exit(1);
			}
		}
		else
			PkgWrite = NULL;
		
		if (PkgWrite != NULL) {
			printf("\n\n");
			printf("Edit out all PKG_PATH environment variable exports ");
			printf("and run \"unset PKG_PATH\".\n\n");
			printf("/etc/pkg.conf:\n");
			while ((c = getc(input)) != EOF) {
				printf("%c", c);
				putc(c,PkgWrite);
			}
			fclose(input);
			fclose(PkgWrite);
		} else {
			printf("\n\n");
			printf("This could have been the contents of /etc/pkg.conf");
			printf(" (run as superuser):\n");
			while ((c = getc(input)) != EOF)
				printf("%c", c);
		}
		
		printf("\n");

		if (argc == 1) {
			printf("%s [-n maximum_mirrors_written]", argv[0]);
			printf(" [-s timeout] [-u (no USA mirrors)]\n");
		}
		_exit(0);
	}
	if (write_pid == -1)
		err(1, NULL);
		
	close(parent_to_write[0]);
	setuid(1000);

	if(pledge("stdio proc exec", NULL) == -1)
		err(EXIT_FAILURE, "pledge");


	struct timespec timeout0 = {20, 0};
	struct timespec timeout;

	timeout.tv_sec = (int) s;
	timeout.tv_nsec = (int) ((s - (double) timeout.tv_sec) * 1000000000);

	kq = kqueue();
	if (kq == -1)
		errx(1, "kq!");


	if (pipe(ftp_to_sed) == -1)
		err(1, NULL);


	ftp_pid = fork();
	if (ftp_pid == (pid_t) 0) {
		close(ftp_to_sed[0]);
		if (dup2(ftp_to_sed[1], STDOUT_FILENO) == -1)
			err(1, NULL);
		execl("/usr/bin/ftp", "ftp", "-Vo", "-",
		    "https://www.openbsd.org/ftp.html", NULL);
		err(1, "ftp execl() failed.");
	}
	if (ftp_pid == -1)
		err(1, NULL);

	close(ftp_to_sed[1]);

	if (pipe(sed_to_parent) == -1)
		err(1, NULL);

	sed_pid = fork();
	if (sed_pid == (pid_t) 0) {
		close(sed_to_parent[0]);
		if(dup2(ftp_to_sed[0], STDIN_FILENO) == -1) {
			kill(ftp_pid, SIGKILL);
			errx(1, "dup2");
		}
		if(dup2(sed_to_parent[1], STDOUT_FILENO) == -1) {
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
	EV_SET(&ke, sed_to_parent[0], EVFILT_READ, EV_ADD | EV_ONESHOT,
	    0, 0, NULL);
	if (kevent(kq, &ke, 1, NULL, 0, NULL) == -1) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(1, "sed_to_parent kevent register fail.");
	}
	close(ftp_to_sed[0]);
	close(sed_to_parent[1]);

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
		printf("timed out fetching openbsd.org/ftp.html.\n");
		manpage(argv[0]);
	}
	input = fdopen(sed_to_parent[0], "r");
	if (input == NULL) {
		kill(ftp_pid, SIGKILL);
		kill(sed_pid, SIGKILL);
		errx(1, "input = fdopen (sed_to_parent[0], \"r\") failed.");
	}
	char line[300];
	num = 0;
	pos = 0;
	array_length = 0;
	array[array_length] = malloc(sizeof(struct mirror_st));
	if (array[array_length] == NULL) {
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
				else if (c == 'r')
					break;
				else if (c == 'f') {
				/*
				 * This changes ftp listings to http.
				 * ftp.html says they can be either one.
				 */
					line[pos++] = 'h';
					line[pos++] = 't';
					continue;
				}
			}
			if (c != '\n')
				line[pos++] = c;
			else {
				line[pos++] = '\0';

				pos += num = strlen(name.release) + 1
				    + strlen(name.machine)+ strlen("/SHA256");



				array[array_length]->ftp_file = malloc(pos);
				if (array[array_length]->ftp_file == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc failed.");
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

				pos -= num;
				array[array_length]->mirror = malloc(pos);
				if (array[array_length]->mirror == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc failed.");
				}
				strlcpy(array[array_length]->mirror, line, pos);

				if(++array_length > array_max) {
					array_max += 100;
					array = reallocarray(array, array_max,
					    sizeof(struct mirror_st));
					    
					if (array == NULL)
						err(1, "reallocarray");
				}

				array[array_length]
				    = malloc(sizeof(struct mirror_st));
				    
				if (array[array_length] == NULL) {
					kill(ftp_pid, SIGKILL);
					kill(sed_pid, SIGKILL);
					errx(1, "malloc failed.");
				}

				pos = 0;
				num = 0;
			}
		}
	}

	if (c != 'r')
		errx(1, "rsync url listings not found.");

	fclose(input);

	close(sed_to_parent[0]);

	if (array_length <= 1)
		errx(1, "No mirrors found.");

	free(array[array_length]->label);
	free(array[array_length]);

	int m_temp1, m_temp2;


	if (u) {
		/* Eliminate USA mirrors if it is requested */
		for (m_temp2 = 0; m_temp2 < array_length; ++m_temp2) {
			if (!strncmp("USA", array[m_temp2]->label, 3)) {

				free(array[m_temp2]->label);
				free(array[m_temp2]->mirror);
				free(array[m_temp2]->ftp_file);
				free(array[m_temp2]);
				
				/* 
				 * swap the last entry into the freed spot,
				 * decrement the length index
				 * and evaluate new pointer at m_temp2
				 */
				 
				array[m_temp2--] = array[--array_length];
			}
		}
	}


	/* Eliminate redundant mirrors */
	for (m_temp1 = 0; m_temp1 < array_length; ++m_temp1) {
		for (m_temp2 = m_temp1 + 1; m_temp2 < array_length; ++m_temp2) {
			if (!strcmp(array[m_temp1]->mirror,
			    array[m_temp2]->mirror)) {
					
				free(array[m_temp2]->label);
				free(array[m_temp2]->mirror);
				free(array[m_temp2]->ftp_file);
				free(array[m_temp2]);
				
				/* 
				 * swap the last entry into the freed spot,
				 * decrement the length index,
				 * go to next m_temp1
				 */
				 
				array[m_temp2] = array[--array_length];
				break;
			}
		}
	}

	int mirror_num = array_length;




	qsort(array, mirror_num, sizeof(struct mirror_st *), label_cmp);

	for (c = 0; c < mirror_num; ++c) {
		printf("\n%d : %s  :  %s\n", mirror_num - c,
		    array[c]->label, array[c]->ftp_file);

		ftp_pid = fork();
		if (ftp_pid == (pid_t) 0) {
			execl("/usr/bin/ftp", "ftp", "-Vmo", "/dev/null",
			    array[c]->ftp_file, NULL);
			errx(1, "ftp execl() failed.");
		}
		if (ftp_pid == -1)
			err(1, NULL);
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
				printf("\nTimeout\n");
				kill(ftp_pid, SIGKILL);
				array[c]->diff = s;
			} else
				break;
		}

		if (ke.data == 0) {
			gettimeofday(&tv_end, NULL);
			array[c]->diff = get_time_diff(tv_start, tv_end);
			printf("%f\n", array[c]->diff);
		} else if (array[c]->diff == 0) {
			array[c]->diff = s + 1;
			printf("Download Error\n");
		}
	}
	
	if(pledge("stdio", NULL) == -1)
		err(EXIT_FAILURE, "pledge");

	qsort(array, mirror_num, sizeof(struct mirror_st *), ftp_cmp);

	printf("\n\n");

	for (c = mirror_num - 1; c >= 0; --c) {
		printf("%d : %s:\n\t%s : ", c + 1, array[c]->label,
		    array[c]->mirror);

		if (array[c]->diff < s)
			printf("%f\n\n", array[c]->diff);
		else if (array[c]->diff == s)
			printf("Timeout\n\n");
		else
			printf("Download Error\n\n");
	}

	if (array[0]->diff >= s)
		errx(1, "No mirrors found within timeout period.");

	char *buf;
	int lines;
	int total_length;
	int copy;
	int j;

	copy = 0;

	if (n < mirror_num)
		mirror_num = n;

	if (mirror_num == 0)
		return 0;

	total_length = mirror_num * strlen("installpath += ");

	for (pos = 0; pos < mirror_num; ++pos)
		total_length += strlen(array[pos]->mirror);

	total_length += mirror_num * strlen("%c/packages/%a/\n");
	
	if (pkgRead == NULL) {		
		buf = (char *) malloc(total_length + 1);
		if (buf == NULL)
			errx(1, "malloc failed.");
	} else {
		fseek(pkgRead, 0, SEEK_END);
		num = ftell(pkgRead);
		total_length += num;
		fseek(pkgRead, 0, SEEK_SET);
		lines = 0;
		buf = (char *) malloc(total_length + 11 + 1);
		if (buf == NULL)
			errx(1, "malloc failed.");
		fread(buf, 1, num, pkgRead);
		fclose(pkgRead);

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
			if (buf[copy - 1] != '\n')
				buf[copy++] = '\n';
			buf[copy] = '\0';
		}
	}

	for (pos = 0; pos < mirror_num; ++pos) {

		/* Eliminates dowload error and timeout mirrors */
		if (array[pos]->diff >= s)
			break;

		if (pos == 0) {
			copy += strlcpy(buf + copy, "installpath =  ",
				total_length - copy);
		} else {
			copy += strlcpy(buf + copy, "installpath += ",
				total_length - copy);
		}
		
		j = strlen(array[pos]->mirror);

		if (j > 20) {
			if (!strncmp(array[pos]->mirror + j - 13, "/pub/OpenBSD/", 13)) {
				if (!strncmp(array[pos]->mirror, "http://", 7)) {
					j -= 20;
					memmove(array[pos]->mirror, array[pos]->mirror + 7, j);
					array[pos]->mirror[j] = '\0';
					copy += strlcpy(buf + copy, array[pos]->mirror,
						total_length - copy);
					copy += strlcpy(buf + copy, "\n", total_length - copy);
					continue;
				}
			}
		}
		copy += strlcpy(buf + copy, array[pos]->mirror,
			total_length - copy);

		copy += strlcpy(buf + copy, "%c/packages/%a/\n",
			total_length - copy);
	}

	buf[copy] = '\0';

	if (dup2(parent_to_write[STDOUT_FILENO], STDOUT_FILENO) == -1) {
		kill(write_pid, SIGKILL);
		printf("%s", buf);
		return 1;
	}

	printf("%s", buf);
	fflush(stdout);
	close(parent_to_write[STDOUT_FILENO]);
	close(STDOUT_FILENO);
	
	wait(&c);

	return c;
}
