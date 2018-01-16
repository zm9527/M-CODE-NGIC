/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>

#include "main.h"
#include "cdr.h"
#include "master_cdr.h"
#include "pipeline/epc_packet_framework.h"

/* app config structure */
struct app_params app;

/* prints the usage statement and quits with an error message */
static inline void dp_print_usage(void)
{
	printf("\nDataplane supported command line arguments are:\n\n");

	printf("+-------------------+-------------+"
			"--------------------------------------------+\n");
#define ARGUMENT_WIDTH 17
#define PRESENCE_WIDTH 11
#define DESCRIPTION_WIDTH 42
	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "ARGUMENT",
			PRESENCE_WIDTH,    "PRESENCE",
			DESCRIPTION_WIDTH, "DESCRIPTION");
	printf("+-------------------+-------------+"
			"--------------------------------------------+\n");
	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_gw_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U GW IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_mask",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U GW network mask of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U port mac address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_sgwu_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_SGWU IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_sgwu_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_SGWU port mac address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_pgwu_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_PGWU IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_pgwu_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_PGWU port mac address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_gw_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI GW IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_mask",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI GW network mask of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI port mac address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1uc",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "core number to run s1u rx/tx.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgic",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "core number to run sgi rx/tx.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--bal",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "core number to run load balancer.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--mct",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "core number to run mcast pkts.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--iface",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH,
			"core number to run Interface with CP.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--stats",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH,
			"core number to run timer for stats.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--num_workers",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH, "no. of worker instances.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--log",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"log level, 1- Notification, 2- Debug.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--cdr_path",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH,
			"CDR file path location.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--master_cdr",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH,
			"CDR Master file.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--numa",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"numa 1- enable, 0- disable.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--spgw_cfg",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"spgw_cfg 01 - SGW, 02- PGW, 03- SPGW.");

	printf("+-------------------+-------------+"
			"--------------------------------------------+\n");
	printf("\n\nExample Usage:\n"
			"$ ./build/ngic_dataplane -c 0xfff -n 4 --\n"
			"--spgw_cfg 01\n"
			"--s1u_ip 11.1.1.100 --s1u_mac 90:e2:ba:58:c8:64\n"
			"--s5s8_sgwu_ip 12.3.1.93\n"
			"--s5s8_pgwu_ip 14.3.1.93\n"
			"--sgi_ip 13.1.1.93 --sgi_mac 90:e2:ba:58:c8:65\n"
			"--s1uc 0 --sgic 1\n"
			"--bal 2 --mct 3 --iface 4 --stats 3\n"
			"--num_workers 2 --numa 0 --log 1\n");
	exit(0);
}

/* parse ethernet address */
static inline int parse_ether_addr(struct ether_addr *hwaddr, const char *str)
{
	/* 01 34 67 90 23 56 */
	/* XX:XX:XX:XX:XX:XX */
	if (strlen(str) != 17 ||
			!isxdigit(str[0]) ||
			!isxdigit(str[1]) ||
			str[2] != ':' ||
			!isxdigit(str[3]) ||
			!isxdigit(str[4]) ||
			str[5] != ':' ||
			!isxdigit(str[6]) ||
			!isxdigit(str[7]) ||
			str[8] != ':' ||
			!isxdigit(str[9]) ||
			!isxdigit(str[10]) ||
			str[11] != ':' ||
			!isxdigit(str[12]) ||
			!isxdigit(str[13]) ||
			str[14] != ':' ||
			!isxdigit(str[15]) ||
			!isxdigit(str[16])) {
		printf("invalid mac hardware address format->%s<-\n", str);
		return 0;
	}
	sscanf(str, "%02zx:%02zx:%02zx:%02zx:%02zx:%02zx",
			(size_t *) &hwaddr->addr_bytes[0],
			(size_t *) &hwaddr->addr_bytes[1],
			(size_t *) &hwaddr->addr_bytes[2],
			(size_t *) &hwaddr->addr_bytes[3],
			(size_t *) &hwaddr->addr_bytes[4],
			(size_t *) &hwaddr->addr_bytes[5]);
	return 1;
}

static inline void set_unused_lcore(int *core, uint64_t *used_coremask)
{
	if (*core != -1) {
		if (!rte_lcore_is_enabled(*core))
			rte_panic("Invalid Core Assignment - "
					"core %u not in coremask", *core);
		return;
	}
	unsigned lcore;
	RTE_LCORE_FOREACH(lcore) {
		if ((1ULL << lcore) & *used_coremask)
			continue;
		*used_coremask |= (1ULL << lcore);
		*core = lcore;
		return;
	}
	rte_panic("No free core available - check coremask");
}

/**
 * Function to parse command line config.
 *
 * @param app
 *	global app config structure.
 * @param argc
 *	number of arguments.
 * @param argv
 *	list of arguments.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static inline int
parse_config_args(struct app_params *app, int argc, char **argv)
{
	int opt;
	int option_index;
	int i;
	struct ether_addr mac_addr;
	uint64_t used_coremask = 0;
	const char *master_cdr_file = NULL;

	static struct option spgw_opts[] = {
		{"s1u_ip", required_argument, 0, 'i'},
		{"sgi_ip", required_argument, 0, 's'},
		{"s1u_mac", required_argument, 0, 'm'},
		{"s5s8_sgwu_mac", required_argument, 0, 'j'},
		{"s5s8_pgwu_mac", required_argument, 0, 'k'},
		{"sgi_mac", required_argument, 0, 'n'},
		{"s1u_gw_ip", required_argument, 0, 'o'},
		{"s1u_mask", required_argument, 0, 'q'},
		{"s5s8_sgwu_ip", required_argument, 0, 'v'},
		{"s5s8_pgwu_ip", required_argument, 0, 'r'},
		{"sgi_gw_ip", required_argument, 0, 'x'},
		{"sgi_mask", required_argument, 0, 'z'},
		{"log", required_argument, 0, 'l'},
		{"s1uc", required_argument, 0, 'u'},
		{"sgic", required_argument, 0, 'g'},
		{"bal", required_argument, 0, 'b'},
		{"mct", required_argument, 0, 'c'},
		{"spns_dns", required_argument, 0, 'p'},
		{"num_workers", required_argument, 0, 'w'},
		{"iface", required_argument, 0, 'd'},
		{"stats", required_argument, 0, 't'},
		{"cdr_path", required_argument, 0, 'a'},
		{"master_cdr", required_argument, 0, 'e'},
		{"numa", required_argument, 0, 'f'},
		{"spgw_cfg",  required_argument, 0, 'h'},
		{NULL, 0, 0, 0}
	};

	optind = 0;/* reset getopt lib */

	while ((opt = getopt_long(argc, argv, "i:s:m:n:u:g:b:m:w:d",
					spgw_opts, &option_index)) != EOF) {
		switch (opt) {
		case 'h':
			app->spgw_cfg = atoi(optarg);
			break;

		/* s1u_ip address */
		case 'i':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_ip)) {
				printf("Invalid s1u interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_ip = 0;
				return -1;
			}
			printf("Parsed s1u ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s1u_ip)));
			break;

			/* sgi_ip address */
		case 's':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_ip)) {
				printf("invalid sgi interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_ip = 0;
				return -1;
			}
			printf("Parsed sgi ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->sgi_ip)));
			break;

			/* s1u_mac address */
		case 'm':
			if (!parse_ether_addr(&app->s1u_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s1u_ether_addr, &mac_addr)) {
					printf("s1u port %d\n", i);
					app->s1u_port = i;
					break;
				}
			}
			break;

			/* s5s8_sgwu_mac address */
		case 'j':
			if (!parse_ether_addr(&app->s5s8_sgwu_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s5s8_sgwu_ether_addr, &mac_addr)) {
					printf("s5s8_sgwu port %d\n", i);
					app->s5s8_sgwu_port = i;
					break;
				}
			}
			break;

			/* s5s8_pgwu_mac address */
		case 'k':
			if (!parse_ether_addr(&app->s5s8_pgwu_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s5s8_pgwu_ether_addr, &mac_addr)) {
					printf("s5s8_pgwu port %d\n", i);
					app->s5s8_pgwu_port = i;
					break;
				}
			}
			break;

			/* sgi_mac address */
		case 'n':
			if (!parse_ether_addr(&app->sgi_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->sgi_ether_addr, &mac_addr)) {
					printf("sgi port %d\n", i);
					app->sgi_port = i;
					break;
				}
			}
			break;

			/* s1u_gw_ip address */
		case 'o':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_gw_ip)) {
				printf("Invalid s1u gateway ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_gw_ip = 0;
				return -1;
			}
			printf("Parsed s1u gw ip: %s\n",
					inet_ntoa(*((struct in_addr *)&app->s1u_gw_ip)));
			break;

			/* s1u_net address */
		case 'q':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_mask)) {
				printf("Invalid s1u network mask ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_mask = 0;
				return -1;
			}
			printf("Parsed s1u network mask: %s\n",
					inet_ntoa(*((struct in_addr *)&app->s1u_mask)));
			break;

		/* s5s8_sgwu_ip address */
		case 'v':
			if (!inet_aton(optarg, (struct in_addr *)&app->s5s8_sgwu_ip)) {
				printf("Invalid s5s8_sgwu interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s5s8_sgwu_ip = 0;
				return -1;
			}
			printf("Parsed s5s8_sgwu ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s5s8_sgwu_ip)));
			break;

		/* s5s8_pgwu_ip address */
		case 'r':
			if (!inet_aton(optarg, (struct in_addr *)&app->s5s8_pgwu_ip)) {
				printf("Invalid s5s8_pgwu interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s5s8_pgwu_ip = 0;
				return -1;
			}
			printf("Parsed s5s8_pgwu ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s5s8_pgwu_ip)));
			break;

			/* sgi_gw_ip address */
		case 'x':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_gw_ip)) {
				printf("Invalid sgi gateway ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_gw_ip = 0;
				return -1;
			}
			printf("Parsed sgi gw ip: %s\n",
					inet_ntoa(*((struct in_addr *)&app->sgi_gw_ip)));
			break;

			/* sgi_net address */
		case 'z':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_mask)) {
				printf("Invalid sgi network mask ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_mask = 0;
				return -1;
			}
			printf("Parsed sgi network mask: %s\n",
					inet_ntoa(*((struct in_addr *)&app->sgi_mask)));
			break;

		case 'l':
			app->log_level = atoi(optarg);
			break;

		case 'u':
			epc_app.core_rx[S1U_PORT_ID] = atoi(optarg);
			epc_app.core_tx[S1U_PORT_ID] = atoi(optarg);
			printf("Parsed core_s1u:\t%d\n",
						epc_app.core_rx[S1U_PORT_ID]);
			used_coremask |= (1ULL << epc_app.core_rx[S1U_PORT_ID]);
			break;

		case 'g':
			epc_app.core_rx[SGI_PORT_ID] = atoi(optarg);
			epc_app.core_tx[SGI_PORT_ID] = atoi(optarg);
			printf("Parsed core_sgi:\t%d\n",
						epc_app.core_rx[SGI_PORT_ID]);
			used_coremask |= (1ULL << epc_app.core_rx[SGI_PORT_ID]);
			break;

		case 'b':
			epc_app.core_load_balance = atoi(optarg);
			printf("Parsed core_load_balance:\t%d\n",
						epc_app.core_load_balance);
			used_coremask |= (1ULL << epc_app.core_load_balance);
			break;

		case 'c':
			epc_app.core_mct = atoi(optarg);
			printf("Parsed core_mct:\t%d\n", epc_app.core_mct);
			used_coremask |= (1ULL << epc_app.core_mct);
			break;

		case 'p':
			epc_app.core_spns_dns = atoi(optarg);
			printf("Parsed core_spns_dns:\t%d\n", epc_app.core_spns_dns);
			used_coremask |= (1ULL << epc_app.core_spns_dns);
			break;

		case 'w':
			epc_app.num_workers = atoi(optarg);
			printf("Parsed num_workers:\t%d\n",
						epc_app.num_workers);
			break;

		case 'd':
			epc_app.core_iface = atoi(optarg);
			printf("Parsed core_iface:\t%d\n", epc_app.core_iface);
			used_coremask |= (1ULL << epc_app.core_iface);
			break;

		case 't':
#ifdef STATS
			epc_app.core_stats = atoi(optarg);
			printf("Parsed core_stats:\t%d\n", epc_app.core_stats);
			used_coremask |= (1ULL << epc_app.core_stats);
#else
			printf("DP compiled without STATS flag in Makefile."
				" Ignoring stats core assignment");
#endif
			break;

		case 'a':
			set_cdr_path(optarg);
			break;

		case 'e':
			master_cdr_file = optarg;
			break;

		case 'f':
			app->numa_on = atoi(optarg);
			break;

		default:
			dp_print_usage();
			return -1;
		}		/* end switch (opt) */
	}			/* end while() */

	set_master_cdr_file(master_cdr_file);
	set_unused_lcore(&epc_app.core_rx[S1U_PORT_ID], &used_coremask);
	epc_app.core_tx[S1U_PORT_ID] = epc_app.core_rx[S1U_PORT_ID];
	set_unused_lcore(&epc_app.core_rx[SGI_PORT_ID], &used_coremask);
	epc_app.core_tx[SGI_PORT_ID] = epc_app.core_rx[SGI_PORT_ID];
	set_unused_lcore(&epc_app.core_load_balance, &used_coremask);
	set_unused_lcore(&epc_app.core_mct, &used_coremask);
	set_unused_lcore(&epc_app.core_iface, &used_coremask);
#ifdef STATS
	set_unused_lcore(&epc_app.core_stats, &used_coremask);
#endif
	set_unused_lcore(&epc_app.core_spns_dns, &used_coremask);
	for (i = 0; i < epc_app.num_workers; ++i) {
		epc_app.worker_cores[i] = -1;
		set_unused_lcore(&epc_app.worker_cores[i], &used_coremask);
	}

	app->s1u_net = app->s1u_ip & app->s1u_mask;
	app->sgi_net = app->sgi_ip & app->sgi_mask;

	return 0;
}

/**
 * Function to initialize the dp config.
 *
 * @param argc
 *	number of arguments.
 * @param argv
 *	list of arguments.
 *
 * @return
 *	None
 */
void dp_init(int argc, char **argv)
{
	if (parse_config_args(&app, argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Error: Config parse fail !!!\n");
}
