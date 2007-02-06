/* Busyboxed by Denis Vlasenko <vda.linux@googlemail.com> */
/* TODO: depends on runit_lib.c - review and reduce/eliminate */

#include <sys/poll.h>
#include <sys/file.h>
#include "busybox.h"
#include "runit_lib.h"

static const char *acts;
static char **service;
static unsigned rc;
static struct taia tstart, tnow;
static char svstatus[20];

#define usage() bb_show_usage()

static void fatal_cannot(const char *m1) ATTRIBUTE_NORETURN;
static void fatal_cannot(const char *m1)
{
	bb_perror_msg("fatal: cannot %s", m1);
	_exit(151);
}

static void out(const char *p, const char *m1)
{
	printf("%s%s: %s", p, *service, m1);
	if (errno) {
		printf(": %s", strerror(errno));
	}
	puts(""); /* will also flush the output */
}

#define WARN    "warning: "
#define OK      "ok: "

static void fail(const char *m1) {
	++rc;
	out("fail: ", m1);
}
static void failx(const char *m1) {
	errno = 0;
	fail(m1);
}
static void warn_cannot(const char *m1) {
	++rc;
	out("warning: cannot ", m1);
}
static void warnx_cannot(const char *m1) {
	errno = 0;
	warn_cannot(m1);
}
static void ok(const char *m1) {
	errno = 0;
	out(OK, m1);
}

static int svstatus_get(void)
{
	int fd, r;

	fd = open_write("supervise/ok");
	if (fd == -1) {
		if (errno == ENODEV) {
			*acts == 'x' ? ok("runsv not running")
			             : failx("runsv not running");
			return 0;
		}
		warn_cannot("open supervise/ok");
		return -1;
	}
	close(fd);
	fd = open_read("supervise/status");
	if (fd == -1) {
		warn_cannot("open supervise/status");
		return -1;
	}
	r = read(fd, svstatus, 20);
	close(fd);
	switch (r) {
	case 20: break;
	case -1: warn_cannot("read supervise/status"); return -1;
	default: warnx_cannot("read supervise/status: bad format"); return -1;
	}
	return 1;
}

static unsigned svstatus_print(const char *m)
{
	long diff;
	int pid;
	int normallyup = 0;
	struct stat s;
	struct tai tstatus;

	if (stat("down", &s) == -1) {
		if (errno != ENOENT) {
			bb_perror_msg(WARN"cannot stat %s/down", *service);
			return 0;
		}
		normallyup = 1;
	}
	pid = (unsigned char) svstatus[15];
	pid <<= 8; pid += (unsigned char)svstatus[14];
	pid <<= 8; pid += (unsigned char)svstatus[13];
	pid <<= 8; pid += (unsigned char)svstatus[12];
	tai_unpack(svstatus, &tstatus);
	if (pid) {
		switch (svstatus[19]) {
		case 1: printf("run: "); break;
		case 2: printf("finish: "); break;
		}
		printf("%s: (pid %d) ", m, pid);
	} else {
		printf("down: %s: ", m);
	}
	diff = tnow.sec.x - tstatus.x;
	printf("%lds", (diff < 0 ? 0L : diff));
	if (pid) {
		if (!normallyup) printf(", normally down");
	} else {
		if (normallyup) printf(", normally up");
	}
	if (pid && svstatus[16]) printf(", paused");
	if (!pid && (svstatus[17] == 'u')) printf(", want up");
	if (pid && (svstatus[17] == 'd')) printf(", want down");
	if (pid && svstatus[18]) printf(", got TERM");
	return pid ? 1 : 2;
}

static int status(const char *unused)
{
	int r;

	r = svstatus_get();
	switch (r) { case -1: case 0: return 0; }

	r = svstatus_print(*service);
	if (chdir("log") == -1) {
		if (errno != ENOENT) {
			printf("; log: "WARN"cannot change to log service directory: %s",
					strerror(errno));
		}
	} else if (svstatus_get()) {
		printf("; ");
		svstatus_print("log");
	}
	puts(""); /* will also flush the output */
	return r;
}

static int checkscript(void)
{
	char *prog[2];
	struct stat s;
	int pid, w;

	if (stat("check", &s) == -1) {
		if (errno == ENOENT) return 1;
		bb_perror_msg(WARN"cannot stat %s/check", *service);
		return 0;
	}
	/* if (!(s.st_mode & S_IXUSR)) return 1; */
	if ((pid = fork()) == -1) {
		bb_perror_msg(WARN"cannot fork for %s/check", *service);
		return 0;
	}
	if (!pid) {
		prog[0] = (char*)"./check";
		prog[1] = NULL;
		close(1);
		execve("check", prog, environ);
		bb_perror_msg(WARN"cannot run %s/check", *service);
		_exit(0);
	}
	while (wait_pid(&w, pid) == -1) {
		if (errno == EINTR) continue;
		bb_perror_msg(WARN"cannot wait for child %s/check", *service);
		return 0;
	}
	return !wait_exitcode(w);
}

static int check(const char *a)
{
	int r;
	unsigned pid;
	struct tai tstatus;

	r = svstatus_get();
	if (r == -1)
		return -1;
	if (r == 0) {
		if (*a == 'x')
			return 1;
		return -1;
	}
	pid = (unsigned char)svstatus[15];
	pid <<= 8; pid += (unsigned char)svstatus[14];
	pid <<= 8; pid += (unsigned char)svstatus[13];
	pid <<= 8; pid += (unsigned char)svstatus[12];
	switch (*a) {
	case 'x':
		return 0;
	case 'u':
		if (!pid || svstatus[19] != 1) return 0;
		if (!checkscript()) return 0;
		break;
	case 'd':
		if (pid) return 0;
		break;
	case 'c':
		if (pid && !checkscript()) return 0;
		break;
	case 't':
		if (!pid && svstatus[17] == 'd') break;
		tai_unpack(svstatus, &tstatus);
		if ((tstart.sec.x > tstatus.x) || !pid || svstatus[18] || !checkscript())
			return 0;
		break;
	case 'o':
		tai_unpack(svstatus, &tstatus);
		if ((!pid && tstart.sec.x > tstatus.x) || (pid && svstatus[17] != 'd'))
			return 0;
	}
	printf(OK);
	svstatus_print(*service);
	puts(""); /* will also flush the output */
	return 1;
}

static int control(const char *a)
{
	int fd, r;

	if (svstatus_get() <= 0) return -1;
	if (svstatus[17] == *a) return 0;
	fd = open_write("supervise/control");
	if (fd == -1) {
		if (errno != ENODEV)
			warn_cannot("open supervise/control");
		else
			*a == 'x' ? ok("runsv not running") : failx("runsv not running");
		return -1;
	}
	r = write(fd, a, strlen(a));
	close(fd);
	if (r != strlen(a)) {
		warn_cannot("write to supervise/control");
		return -1;
	}
	return 1;
}

int sv_main(int argc, char **argv);
int sv_main(int argc, char **argv)
{
	unsigned opt;
	unsigned i, want_exit;
	char *x;
	char *action;
	const char *varservice = "/var/service/";
	unsigned services;
	char **servicex;
	unsigned long waitsec = 7;
	smallint kll = 0;
	smallint verbose = 0;
	int (*act)(const char*);
	int (*cbk)(const char*);
	int curdir;

	xfunc_error_retval = 100;

	x = getenv("SVDIR");
	if (x) varservice = x;
	x = getenv("SVWAIT");
	if (x) waitsec = xatoul(x);

	opt = getopt32(argc, argv, "w:v", &x);
	if (opt & 1) waitsec = xatoul(x); // -w
	if (opt & 2) verbose = 1; // -v
	argc -= optind;
	argv += optind;
	action = *argv++;
	if (!action || !*argv) usage();
	service = argv;
	services = argc - 1;

	taia_now(&tnow);
	tstart = tnow;
	curdir = open_read(".");
	if (curdir == -1)
		fatal_cannot("open current directory");

	act = &control;
	acts = "s";
	cbk = &check;

	switch (*action) {
	case 'x':
	case 'e':
		acts = "x";
		if (!verbose) cbk = NULL;
		break;
	case 'X':
	case 'E':
		acts = "x";
		kll = 1;
		break;
	case 'D':
		acts = "d";
		kll = 1;
		break;
	case 'T':
		acts = "tc";
		kll = 1;
		break;
	case 'c':
		if (!str_diff(action, "check")) {
			act = NULL;
			acts = "c";
			break;
		}
	case 'u': case 'd': case 'o': case 't': case 'p': case 'h':
	case 'a': case 'i': case 'k': case 'q': case '1': case '2':
		action[1] = '\0';
		acts = action;
		if (!verbose) cbk = NULL;
		break;
	case 's':
		if (!str_diff(action, "shutdown")) {
			acts = "x";
			break;
		}
		if (!str_diff(action, "start")) {
			acts = "u";
			break;
		}
		if (!str_diff(action, "stop")) {
			acts = "d";
			break;
		}
		/* "status" */
		act = &status;
		cbk = NULL;
		break;
	case 'r':
		if (!str_diff(action, "restart")) {
			acts = "tcu";
			break;
		}
		usage();
	case 'f':
		if (!str_diff(action, "force-reload")) {
			acts = "tc";
			kll = 1;
			break;
		}
		if (!str_diff(action, "force-restart")) {
			acts = "tcu";
			kll = 1;
			break;
		}
		if (!str_diff(action, "force-shutdown")) {
			acts = "x";
			kll = 1;
			break;
		}
		if (!str_diff(action, "force-stop")) {
			acts = "d";
			kll = 1;
			break;
		}
	default:
		usage();
	}

	servicex = service;
	for (i = 0; i < services; ++i) {
		if ((**service != '/') && (**service != '.')) {
			if (chdir(varservice) == -1)
				goto chdir_failed_0;
		}
		if (chdir(*service) == -1) {
 chdir_failed_0:
			fail("cannot change to service directory");
			goto nullify_service_0;
		}
		if (act && (act(acts) == -1)) {
 nullify_service_0:
			*service = NULL;
		}
		if (fchdir(curdir) == -1)
			fatal_cannot("change to original directory");
		service++;
	}

	if (cbk) while (1) {
		//struct taia tdiff;
		long diff;

		//taia_sub(&tdiff, &tnow, &tstart);
		diff = tnow.sec.x - tstart.sec.x;
		service = servicex;
		want_exit = 1;
		for (i = 0; i < services; ++i, ++service) {
			if (!*service)
				continue;
			if ((**service != '/') && (**service != '.')) {
				if (chdir(varservice) == -1)
					goto chdir_failed;
			}
			if (chdir(*service) == -1) {
 chdir_failed:
				fail("cannot change to service directory");
				goto nullify_service;
			}
			if (cbk(acts) != 0)
				goto nullify_service;
			want_exit = 0;
			if (diff >= waitsec) {
				printf(kll ? "kill: " : "timeout: ");
				if (svstatus_get() > 0) {
					svstatus_print(*service);
					++rc;
				}
				puts(""); /* will also flush the output */
				if (kll)
					control("k");
 nullify_service:
				*service = NULL;
			}
			if (fchdir(curdir) == -1)
				fatal_cannot("change to original directory");
		}
		if (want_exit) break;
		usleep(420000);
		taia_now(&tnow);
	}
	return rc > 99 ? 99 : rc;
}
