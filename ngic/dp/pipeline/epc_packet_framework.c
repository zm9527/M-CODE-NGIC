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

#include <string.h>
#include <sched.h>
#include <unistd.h>

#include <rte_ring.h>
#include <rte_pipeline.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_port_ethdev.h>
#include <rte_table_hash.h>
#include <rte_table_stub.h>
#include <rte_byteorder.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_port_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "main.h"
#include "stats.h"
#include "epc_packet_framework.h"
#include "interface.h"
#include "meter.h"
#include "acl.h"
#include "commands.h"

struct rte_ring *epc_mct_spns_dns_rx;
struct epc_app_params epc_app = {
	/* Ports */
	.n_ports = NUM_SPGW_PORTS,

	/* Rings */
	.ring_rx_size = EPC_DEFAULT_RING_SZ,
	.ring_tx_size = EPC_DEFAULT_RING_SZ,

	/* Burst sizes */
	.burst_size_rx_read = EPC_DEFAULT_BURST_SZ,
	.burst_size_rx_write = EPC_BURST_SZ_64,
	.burst_size_worker_read = EPC_DEFAULT_BURST_SZ,
	.burst_size_worker_write = EPC_BURST_SZ_64,
	.burst_size_tx_read = EPC_DEFAULT_BURST_SZ,
	.burst_size_tx_write = EPC_BURST_SZ_64,

	.core_rx[S1U_PORT_ID] = -1,
	.core_tx[S1U_PORT_ID] = -1,
	.core_rx[SGI_PORT_ID] = -1,
	.core_tx[SGI_PORT_ID] = -1,
	.core_load_balance = -1,
	.core_mct = -1,
	.core_iface = -1,
	.core_stats = -1,
	.core_spns_dns = -1,
};

static void *dp_zmq_thread(__rte_unused void *arg)
{
	while (1)
		iface_remove_que(COMM_ZMQ);
}

static void epc_iface_core(__rte_unused void *args)
{
#ifdef SIMU_CP
	static int simu_call;

	if (simu_call == 0) {
		simu_cp();
		simu_call = 1;
	}
#else
	uint32_t lcore;

	lcore = rte_lcore_id();
	RTE_LOG(NOTICE, API, "RTE NOTICE enabled on lcore %d\n", lcore);
	RTE_LOG(INFO, API, "RTE INFO enabled on lcore %d\n", lcore);
	RTE_LOG(DEBUG, API, "RTE DEBUG enabled on lcore %d\n", lcore);
#if defined(SDN_ODL_BUILD)
	pthread_t t;
	int err;

	err = pthread_create(&t, NULL, &dp_zmq_thread, NULL);
	if (err != 0)
		RTE_LOG(INFO, API, "\ncan't create ZMQ read thread :[%s]", strerror(err));
	else
		RTE_LOG(INFO, API, "\n ZMQ read thread created successfully\n");
#endif  /* DP:(SDN_ODL_BUILD */
	/*
	 * Poll message que. Populate hash table from que.
	 */
	while (1)
		iface_process_ipc_msgs();
#endif
}

static void epc_init_lcores(void)
{
	unsigned i;

	epc_alloc_lcore(epc_rx, &epc_app.rx_params[WEST_PORT_ID],
						epc_app.core_rx[WEST_PORT_ID]);
	epc_alloc_lcore(epc_rx, &epc_app.rx_params[EAST_PORT_ID],
						epc_app.core_rx[EAST_PORT_ID]);

	epc_alloc_lcore(epc_load_balance, &epc_app.lb_params,
						epc_app.core_load_balance);
	epc_alloc_lcore(epc_arp_icmp, NULL, epc_app.core_mct);

	for (i = 0; i < epc_app.num_workers; i++) {
		epc_alloc_lcore(epc_worker_core, &epc_app.worker[i],
				epc_app.worker_cores[i]);
	}

	epc_alloc_lcore(epc_tx, &epc_app.tx_params[WEST_PORT_ID],
						epc_app.core_tx[WEST_PORT_ID]);
	epc_alloc_lcore(epc_tx, &epc_app.tx_params[EAST_PORT_ID],
						epc_app.core_tx[EAST_PORT_ID]);

	epc_alloc_lcore(epc_iface_core, NULL, epc_app.core_iface);

	epc_alloc_lcore(scan_dns_ring, NULL, epc_app.core_spns_dns);
#ifdef STATS
	epc_alloc_lcore(epc_stats_core, NULL, epc_app.core_stats);
#endif
}

#define for_each_port(port) for (port = 0; port < epc_app.n_ports; port++)
#define for_each_core(core) for (core = 0; core < DP_MAX_LCORE; core++)

/* initialize rings common to all pipelines */
static void epc_init_rings(void)
{
	uint32_t i;
	uint32_t port;

	/* create communication rings between RX-core and lb core */
	for_each_port(port) {
		char name[32];

		snprintf(name, sizeof(name), "rx_to_lb_%u", port);
		epc_app.epc_lb_rx[port] = rte_ring_create(name,
				epc_app.ring_rx_size,
				rte_socket_id(),
				RING_F_SP_ENQ |
				RING_F_SC_DEQ);

		if (epc_app.epc_lb_rx[port] == NULL)
			rte_exit(EXIT_FAILURE,"Cannot create RX ring %u\n", port);
	}

	/* create communication rings between RX-core and mct core */
	for_each_port(port) {
		char name[32];

		snprintf(name, sizeof(name), "rx_to_mct_%u", port);
		epc_app.epc_mct_rx[port] = rte_ring_create(name,
				epc_app.ring_rx_size,
				rte_socket_id(),
				RING_F_SP_ENQ |
				RING_F_SC_DEQ);
		if (epc_app.epc_mct_rx[port] == NULL)
			rte_exit(EXIT_FAILURE,"Cannot create RX ring %u\n", port);

		snprintf(name, sizeof(name), "tx_from_mct_%u", port);

	}
	char name[32];

	port = epc_app.ports[1];
	snprintf(name, sizeof(name), "rx_to_mct_spns_dns%u", port);
	epc_mct_spns_dns_rx = rte_ring_create(name,
				epc_app.ring_rx_size * 16,
				rte_socket_id(),
				RING_F_SC_DEQ);
	if (epc_mct_spns_dns_rx == NULL)
		rte_panic("Cannot create RX ring %u\n", port);

	for_each_port(port) {
		/* Create transmit & receive rings per core */
		for_each_core(i) {
			char name[32];

			snprintf(name, sizeof(name), "epc_work_rx_%u_%u", i,
					port);
			epc_app.epc_work_rx[i][port] =
				rte_ring_create(name, epc_app.ring_rx_size,
						rte_socket_id(),
						RING_F_SP_ENQ | RING_F_SC_DEQ);

			if (epc_app.epc_work_rx[i][port] == NULL)
				rte_exit(EXIT_FAILURE,"Cannot create RX ring %u\n", i);

			snprintf(name, sizeof(name), "app_ring_tx_%u_%u", i,
					port);

			epc_app.ring_tx[i][port] = rte_ring_create(name,
					epc_app.
					ring_tx_size,
					rte_socket_id
					(),
					RING_F_SP_ENQ
					|
					RING_F_SC_DEQ);

			if (epc_app.ring_tx[i][port] == NULL)
				rte_exit(EXIT_FAILURE,"Cannot create TX ring %u\n", i);

		}
	}
}


static inline void epc_run_pipeline(void)
{
	struct epc_lcore_config *config;
	int i;
	unsigned lcore;

	lcore = rte_lcore_id();
	config = &epc_app.lcores[lcore];

#ifdef INSTMNT
	uint64_t start_tsc, end_tsc;

	if (lcore == epc_app.worker_cores[0]) {
		for (i = 0; i < config->allocated; i++) {
			start_tsc = rte_rdtsc();
			config->launch[i].func(config->launch[i].arg);
			if (flag_wrkr_update_diff) {
				end_tsc = rte_rdtsc();
				diff_tsc_wrkr += end_tsc - start_tsc;
				flag_wrkr_update_diff = 0;
			}
		}
	} else
#endif
		for (i = 0; i < config->allocated; i++)
			config->launch[i].func(config->launch[i].arg);
}
static int epc_lcore_main_loop(__attribute__ ((unused))
		void *arg)
{
	struct epc_lcore_config *config;
	uint32_t lcore;

	lcore = rte_lcore_id();
	config = &epc_app.lcores[lcore];

	if (config->allocated == 0)
		return 0;

	/* enable DP log level */
	if (app.log_level == DEBUG)
		rte_set_log_level(RTE_LOG_DEBUG);
	else if (app.log_level == NOTICE)
		rte_set_log_level(RTE_LOG_NOTICE);
	else
		rte_set_log_level(RTE_LOG_INFO);

	RTE_LOG(NOTICE, DP, "RTE NOTICE enabled on lcore %d\n", lcore);
	RTE_LOG(INFO, DP, "RTE INFO enabled on lcore %d\n", lcore);
	RTE_LOG(DEBUG, DP, "RTE DEBUG enabled on lcore %d\n", lcore);

	while (1)
		epc_run_pipeline();

	return 0;
}

void epc_init_packet_framework(uint8_t east_port_id, uint8_t west_port_id)
{
	unsigned i;

	if (epc_app.n_ports > NUM_SPGW_PORTS) {
		printf("number of ports exceeds a configured number %d\n",
				epc_app.n_ports);
		exit(1);
	}

	epc_app.ports[WEST_PORT_ID] = west_port_id;
	epc_app.ports[EAST_PORT_ID] = east_port_id;
	RTE_LOG(INFO, DP, "west rx/tx running on lcore    :\t%d\n",
						epc_app.core_rx[WEST_PORT_ID]);
	RTE_LOG(INFO, DP, "east rx/tx running on lcore    :\t%d\n",
						epc_app.core_rx[EAST_PORT_ID]);
	RTE_LOG(INFO, DP, "load balancer running on lcore:\t%d\n",
						epc_app.core_load_balance);
	RTE_LOG(INFO, DP, "multicast running on lcore    :\t%d\n",
						epc_app.core_mct);
	RTE_LOG(INFO, DP, "iface running on lcore        :\t%d\n",
						epc_app.core_iface);
	RTE_LOG(INFO, DP, "spns dns running on lcore        :\t%d\n",
						epc_app.core_spns_dns);


#ifdef STATS
	RTE_LOG(INFO, DP, "stats timer running on lcore  :\t%d\n",
						epc_app.core_stats);
#endif
	RTE_LOG(INFO, DP, "workers running on lcores :\n");
	for (i = 0; i < epc_app.num_workers; ++i) {
		RTE_LOG(INFO, DP, "\t%u\n", epc_app.worker_cores[i]);
	}

	/*
	 * Initialize rings
	 */
	epc_init_rings();
	epc_spns_dns_init();

	/*
	 * Initialize pipelines
	 */
	epc_tx_init(&epc_app.tx_params[WEST_PORT_ID],
				epc_app.core_rx[WEST_PORT_ID], WEST_PORT_ID);
	epc_tx_init(&epc_app.tx_params[EAST_PORT_ID],
				epc_app.core_rx[EAST_PORT_ID], EAST_PORT_ID);

	epc_arp_icmp_init();
	epc_load_balance_init(&epc_app.lb_params);

	for (i = 0; i < epc_app.num_workers; i++)
		epc_worker_core_init(&epc_app.worker[i],
				epc_app.worker_cores[i], i);

	epc_rx_init(&epc_app.rx_params[WEST_PORT_ID],
				epc_app.core_rx[WEST_PORT_ID], WEST_PORT_ID);
	epc_rx_init(&epc_app.rx_params[EAST_PORT_ID],
				epc_app.core_rx[EAST_PORT_ID], EAST_PORT_ID);

	/*
	 * Assign pipelines to cores
	 */
	epc_init_lcores();

	/* Init IPC msgs */
	iface_init_ipc_node();

}
#if 0
void epc_init_packet_framework(uint8_t sgi_port_id, uint8_t s1u_port_id)
{
	unsigned i;

	if (epc_app.n_ports > num_spgw_ports) {
		printf("number of ports exceeds a configured number %d\n",
				epc_app.n_ports);
		exit(1);
	}

	epc_app.ports[S1U_PORT_ID] = s1u_port_id;
	epc_app.ports[SGI_PORT_ID] = sgi_port_id;
	RTE_LOG(INFO, DP, "s1u rx/tx running on lcore    :\t%d\n",
						epc_app.core_rx[S1U_PORT_ID]);
	RTE_LOG(INFO, DP, "sgi rx/tx running on lcore    :\t%d\n",
						epc_app.core_rx[SGI_PORT_ID]);
	RTE_LOG(INFO, DP, "load balancer running on lcore:\t%d\n",
						epc_app.core_load_balance);
	RTE_LOG(INFO, DP, "multicast running on lcore    :\t%d\n",
						epc_app.core_mct);
	RTE_LOG(INFO, DP, "iface running on lcore        :\t%d\n",
						epc_app.core_iface);
	RTE_LOG(INFO, DP, "spns dns running on lcore        :\t%d\n",
						epc_app.core_spns_dns);


#ifdef STATS
	RTE_LOG(INFO, DP, "stats timer running on lcore  :\t%d\n",
						epc_app.core_stats);
#endif
	RTE_LOG(INFO, DP, "workers running on lcores :\n");
	for (i = 0; i < epc_app.num_workers; ++i) {
		RTE_LOG(INFO, DP, "\t%u\n", epc_app.worker_cores[i]);
	}

	/*
	 * initialize rings
	 */
	epc_init_rings();
	epc_spns_dns_init();

	/*
	 * initialize pipelines
	 */
	epc_tx_init(&epc_app.tx_params[S1U_PORT_ID],
				epc_app.core_rx[S1U_PORT_ID], S1U_PORT_ID);
	epc_tx_init(&epc_app.tx_params[SGI_PORT_ID],
				epc_app.core_rx[SGI_PORT_ID], SGI_PORT_ID);

	epc_arp_icmp_init();
	epc_load_balance_init(&epc_app.lb_params);

	for (i = 0; i < epc_app.num_workers; i++)
		epc_worker_core_init(&epc_app.worker[i],
				epc_app.worker_cores[i], i);

	epc_rx_init(&epc_app.rx_params[S1U_PORT_ID],
				epc_app.core_rx[S1U_PORT_ID], S1U_PORT_ID);
	epc_rx_init(&epc_app.rx_params[SGI_PORT_ID],
				epc_app.core_rx[SGI_PORT_ID], SGI_PORT_ID);

	/*
	 * assign pipelines to cores
	 */
	epc_init_lcores();

	/* Init IPC msgs */
	iface_init_ipc_node();

}
#endif

void packet_framework_launch(void)
{
	if (rte_eal_mp_remote_launch(epc_lcore_main_loop, NULL, CALL_MASTER) < 0)
		rte_exit(EXIT_FAILURE,"MP remote lauch fail !!!");
}

void epc_alloc_lcore(pipeline_func_t func, void *arg, int core)
{
	struct epc_lcore_config *lcore;

	if (core >= DP_MAX_LCORE)
		rte_exit(EXIT_FAILURE,"%s: Core %d exceed Max core %d\n", __func__, core,
				DP_MAX_LCORE);

	lcore = &epc_app.lcores[core];
	lcore->launch[lcore->allocated].func = func;
	lcore->launch[lcore->allocated].arg = arg;

	lcore->allocated++;
}
