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

#include <arpa/inet.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__)
#include <bsd/stdlib.h>
#endif

#include "signsky.h"

static void	config_parse_peer(char *);
static void	config_parse_local(char *);
static void	config_parse_runas(char *);
static void	config_parse_host(char *, struct sockaddr_in *);

static char	*config_read_line(FILE *, char *, size_t);

static const struct {
	const char		*option;
	void			(*cb)(char *);
} keywords[] = {
	{ "peer",		config_parse_peer },
	{ "local",		config_parse_local },
	{ "run",		config_parse_runas },
	{ NULL,			NULL },
};

static const struct {
	const char		*name;
	u_int16_t		type;
} proctab[] = {
	{ "clear",		SIGNSKY_PROC_CLEAR },
	{ "crypto",		SIGNSKY_PROC_CRYPTO },
	{ "keying",		SIGNSKY_PROC_KEYING },
	{ "encrypt",		SIGNSKY_PROC_ENCRYPT },
	{ "decrypt",		SIGNSKY_PROC_DECRYPT },
	{ NULL,			0 },
};

void
signsky_config_load(const char *file)
{
	FILE		*fp;
	int		idx;
	char		buf[BUFSIZ], *option, *value;

	PRECOND(file != NULL);

	if ((fp = fopen(file, "r")) == NULL)
		fatal("failed to open '%s': %s", file, errno_s);

	while ((option = config_read_line(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(option) == 0)
			continue;

		if ((value = strchr(option, ' ')) == NULL)
			fatal("malformed option '%s'", option);

		*(value)++ = '\0';

		for (idx = 0; keywords[idx].option != NULL; idx++) {
			if (!strcmp(keywords[idx].option, option)) {
				keywords[idx].cb(value);
				break;
			}
		}

		if (keywords[idx].option == NULL)
			fatal("unknown option '%s'", option);
	}

	if (ferror(fp))
		fatal("error reading the configuration file");

	fclose(fp);
}

static char *
config_read_line(FILE *fp, char *in, size_t len)
{
	char		*p, *t;

	PRECOND(fp != NULL);
	PRECOND(in != NULL);

	if (fgets(in, len, fp) == NULL)
		return (NULL);

	p = in;
	in[strcspn(in, "\n")] = '\0';

	while (isspace(*(unsigned char *)p))
		p++;

	if (p[0] == '#' || p[0] == '\0') {
		p[0] = '\0';
		return (p);
	}

	for (t = p; *t != '\0'; t++) {
		if (*t == '\t')
			*t = ' ';
	}

	return (p);
}

static void
config_parse_peer(char *peer)
{
	PRECOND(peer != NULL);

	config_parse_host(peer, &signsky->peer);
}

static void
config_parse_local(char *local)
{
	PRECOND(local != NULL);

	config_parse_host(local, &signsky->local);
}

static void
config_parse_runas(char *runas)
{
	int		idx;
	u_int16_t	type;
	char		proc[16], user[32];

	PRECOND(runas != NULL);

	memset(proc, 0, sizeof(proc));
	memset(user, 0, sizeof(user));

	if (sscanf(runas, "%15s as %31s", proc, user) != 2)
		fatal("option 'run %s' invalid", runas);

	for (idx = 0; proctab[idx].name != NULL; idx++) {
		if (!strcmp(proctab[idx].name, proc))
			break;
	}

	if (proctab[idx].name == NULL)
		fatal("process '%s' is unknown", proc);

	type = proctab[idx].type;

	if (signsky->runas[type] != NULL)
		fatal("process '%s' user already set", proc);

	if ((signsky->runas[type] = strdup(user)) == NULL)
		fatal("strdup");
}

static void
config_parse_host(char *host, struct sockaddr_in *sin)
{
	char		*port;
	const char	*errstr;

	PRECOND(host != NULL);
	PRECOND(sin != NULL);

	if ((port = strchr(host, ':')) == NULL)
		fatal("'%s': argument must be in format ip:port", host);
	*(port)++ = '\0';

	if (inet_pton(AF_INET, host, &sin->sin_addr.s_addr) == -1)
		fatal("ip '%s' invalid", host);

	sin->sin_port = strtonum(port, 1, USHRT_MAX, &errstr);
	if (errstr)
		fatal("port '%s' invalid: %s", port, errstr);

	sin->sin_port = htons(sin->sin_port);
}
