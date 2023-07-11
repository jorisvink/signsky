/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
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

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/wait.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

/* List of all worker processes. */
static LIST_HEAD(, signsky_proc)		proclist;

/* Some human understand process types. */
static const char *proctab[] = {
	"unknown",
	"signsky-clear",
	"signsky-crypto",
	"signsky-encrypt",
	"signsky-decrypt",
	"signsky-keying"
};

/* Points to the process its own signsky_proc, or NULL or parent. */
static struct signsky_proc	*process = NULL;

/*
 * Initialize the process system so new processes can be started.
 */
void
signsky_proc_init(void)
{
	LIST_INIT(&proclist);
}

/*
 * Start the clear and crypto sides.
 *
 * We create all the shared memory queues and pass them to each process.
 * The processes themselves will remove the queues they do not need.
 */
void
signsky_proc_start(void)
{
	struct signsky_proc_io		io;

	io.tx = signsky_alloc_shared(sizeof(struct signsky_key), NULL);
	io.rx = signsky_alloc_shared(sizeof(struct signsky_key), NULL);
	io.arwin = signsky_alloc_shared(sizeof(struct signsky_arwin), NULL);

	io.clear = signsky_ring_alloc(1024);
	io.crypto = signsky_ring_alloc(1024);
	io.encrypt = signsky_ring_alloc(1024);
	io.decrypt = signsky_ring_alloc(1024);

	signsky_proc_create(SIGNSKY_PROC_CLEAR, signsky_clear_entry, &io);
	signsky_proc_create(SIGNSKY_PROC_CRYPTO, signsky_crypto_entry, &io);
	signsky_proc_create(SIGNSKY_PROC_KEYING, signsky_keying_entry, &io);
	signsky_proc_create(SIGNSKY_PROC_ENCRYPT, signsky_encrypt_entry, &io);
	signsky_proc_create(SIGNSKY_PROC_DECRYPT, signsky_decrypt_entry, &io);

	signsky_shm_detach(io.tx);
	signsky_shm_detach(io.rx);
	signsky_shm_detach(io.arwin);
	signsky_shm_detach(io.clear);
	signsky_shm_detach(io.crypto);
	signsky_shm_detach(io.encrypt);
	signsky_shm_detach(io.decrypt);
}

/*
 * Create a new process that will start executing at the given entry
 * point. The process is not yet started.
 */
void
signsky_proc_create(u_int16_t type,
    void (*entry)(struct signsky_proc *), void *arg)
{
	struct passwd		*pw;
	struct signsky_proc	*proc;

	PRECOND(type == SIGNSKY_PROC_CLEAR ||
	    type == SIGNSKY_PROC_CRYPTO ||
	    type == SIGNSKY_PROC_ENCRYPT ||
	    type == SIGNSKY_PROC_DECRYPT ||
	    type == SIGNSKY_PROC_KEYING);
	PRECOND(entry != NULL);
	/* arg is optional. */

	if (signsky->runas[type] == NULL)
		fatal("no runas user configured for %s", proctab[type]);

	if ((proc = calloc(1, sizeof(*proc))) == NULL)
		fatal("calloc: failed to allocate new proc entry");

	proc->arg = arg;
	proc->type = type;
	proc->entry = entry;
	proc->name = proctab[type];

	if ((pw = getpwnam(signsky->runas[proc->type])) == NULL)
		fatal("getpwnam(%s): %s", signsky->runas[proc->type], errno_s);

	proc->uid = pw->pw_uid;
	proc->gid = pw->pw_gid;

	if ((proc->pid = fork()) == -1)
		fatal("failed to fork child: %s", errno_s);

	if (proc->pid == 0) {
		openlog(proc->name, LOG_NDELAY | LOG_PID, LOG_DAEMON);

		process = proc;
		proc->pid = getpid(),
		proc->entry(proc);
		/* NOTREACHED */
	}

	syslog(LOG_INFO, "started %s (pid=%d)", proc->name, proc->pid);

	LIST_INSERT_HEAD(&proclist, proc, list);
}

/*
 * Have a process drop its privileges.
 */
void
signsky_proc_privsep(struct signsky_proc *proc)
{
	PRECOND(proc != NULL);

	switch (proc->type) {
	case SIGNSKY_PROC_CLEAR:
	case SIGNSKY_PROC_CRYPTO:
	case SIGNSKY_PROC_KEYING:
	case SIGNSKY_PROC_ENCRYPT:
	case SIGNSKY_PROC_DECRYPT:
		break;
	default:
		fatal("%s: unknown process type %d", __func__, proc->type);
	}

	if (setgroups(1, &proc->gid) == -1 ||
	    setgid(proc->gid) == -1 || setegid(proc->gid) == -1 ||
	    setuid(proc->uid) == -1 || seteuid(proc->uid) == -1)
		fatal("failed to drop privileges (%s)", errno_s);
}

/*
 * Reap a single process.
 */
void
signsky_proc_reap(void)
{
	pid_t			pid;
	struct signsky_proc	*proc;
	int			status;

	for (;;) {
		if ((pid = waitpid(-1, &status, WNOHANG)) == -1) {
			if (errno == ECHILD)
				break;
			if (errno == EINTR)
				continue;
			fatal("waitpid: %s", errno_s);
		}

		if (pid == 0)
			break;

		LIST_FOREACH(proc, &proclist, list) {
			if (proc->pid == pid) {
				syslog(LOG_NOTICE, "%s exited (%d)",
				    proc->name, status);
				LIST_REMOVE(proc, list);
				free(proc);
				break;
			}
		}
	}
}

/*
 * Send the given signal to all running processes.
 */
void
signsky_proc_killall(int sig)
{
	struct signsky_proc	*proc;

	LIST_FOREACH(proc, &proclist, list) {
		if (kill(proc->pid, sig) == -1) {
			syslog(LOG_NOTICE, "failed to signal proc %u (%s)\n",
			    proc->type, errno_s);
		}
	}
}

/*
 * Shutdown all processes, they each receive a SIGQUIT signal and are
 * given time to cleanup and exit.
 */
void
signsky_proc_shutdown(void)
{
	signsky_proc_killall(SIGQUIT);

	while (!LIST_EMPTY(&proclist))
		signsky_proc_reap();
}

/*
 * Returns the signsky_process for the active process.
 * Will return NULL on the parent process.
 */
struct signsky_proc *
signsky_process(void)
{
	return (process);
}
