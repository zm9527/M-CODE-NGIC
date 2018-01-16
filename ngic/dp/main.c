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

#include <unistd.h>
#include <locale.h>
#include <signal.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_branch_prediction.h>

#include "main.h"
#include "interface.h"
#include "cdr.h"
#include "session_cdr.h"
#include "master_cdr.h"

/* Temp. work around for debug log level. Issue in DPDK-16.11*/
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
uint8_t RTE_LOG_LEVEL;
#endif

/**
 * Main function.
 */
int main(int argc, char **argv)
{
	int ret;

	/* Initialize the Environment Abstraction Layer */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");
	argc -= ret;
	argv += ret;

	dp_port_init();

	/* DP Init */
	dp_init(argc, argv);

/** Note :In dpdk set max log level is INFO, here override the
 *  max value of RTE_LOG_INFO for enable DEBUG logs (dpdk-16.11.4).
 */
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
	if (app.log_level == DEBUG)
		RTE_LOG_LEVEL = RTE_LOG_DEBUG;
#endif

	switch (app.spgw_cfg) {
		case SGWU:
			/* Pipeline Init */
			epc_init_packet_framework(app.s5s8_sgwu_port, app.s1u_port);

			/**
			 *UE <--S1U-->[SGW]<--S5/8-->[PGW]<--SGi-->
			 */

			/*S1U port handler*/
			register_worker(s1u_pkt_handler, app.s1u_port);

			/*S5/8 port handler*/
			register_worker(sgw_s5_s8_pkt_handler, app.s5s8_sgwu_port);
			break;

		case PGWU:
			/* Pipeline Init */
			epc_init_packet_framework(app.sgi_port, app.s5s8_pgwu_port);

			/**
			 *UE <--S1U-->[SGW]<--S5/8-->[PGW]<--SGi-->
			 */

			/*S5/8 port handler*/
			register_worker(pgw_s5_s8_pkt_handler, app.s5s8_pgwu_port);

			/*SGi port handler*/
			register_worker(sgi_pkt_handler, app.sgi_port);
			break;

		case SPGWU:
			/* Pipeline Init */
			epc_init_packet_framework(app.sgi_port, app.s1u_port);

			/**
			 * UE <--S1U--> [SPGW] <--SGi-->
			 */

			/*S1U port handler*/
			register_worker(s1u_pkt_handler, app.s1u_port);

			/*SGi port handler*/
			register_worker(sgi_pkt_handler, app.sgi_port);
			break;

		default:
			rte_exit(EXIT_FAILURE, "Invalid DP type(SPGW_CFG).\n");
	}

	finalize_cur_cdrs(cdr_path);

	sess_cdr_init();


	iface_module_constructor();
	dp_table_init();

	packet_framework_launch();

	rte_eal_mp_wait_lcore();

	return 0;
}
