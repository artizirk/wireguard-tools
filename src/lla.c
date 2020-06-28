// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include "blake2s.h"
#include "encoding.h"
#include "subcommands.h"

int lla_main(int argc, char *argv[])
{
	uint8_t key[WG_KEY_LEN] __attribute__((aligned(sizeof(uintptr_t))));
	char base64[WG_KEY_LEN_BASE64];
	uint8_t prefix[16] = {0xfe, 0x80};  // fe80::
	uint8_t mask[16] = {0xff, 0xc0};  // /10 netmask
	uint8_t address[16];
	char saddress[INET6_ADDRSTRLEN+1];
	int trailing_char;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (fread(base64, 1, sizeof(base64) - 1, stdin) != sizeof(base64) - 1) {
		errno = EINVAL;
		fprintf(stderr, "%s: Key is not the correct length or format\n", PROG_NAME);
		return 1;
	}
	base64[WG_KEY_LEN_BASE64 - 1] = '\0';

	for (;;) {
		trailing_char = getc(stdin);
		if (!trailing_char || isspace(trailing_char) || isblank(trailing_char))
			continue;
		if (trailing_char == EOF)
			break;
		fprintf(stderr, "%s: Trailing characters found after key\n", PROG_NAME);
		return 1;
	}

	if (!key_from_base64(key, base64)) {
		fprintf(stderr, "%s: Key is not the correct length or format\n", PROG_NAME);
		return 1;
	}

	blake2s(key, key, NULL, 32, WG_KEY_LEN, 0);

	for (uint8_t i = 0; i < 16; i++) {
		address[i] = (prefix[i] & mask[i]) | (key[i] & ~mask[i]);
	}

	inet_ntop(AF_INET6, address, saddress, INET6_ADDRSTRLEN);
	puts(saddress);
	return 0;
}
