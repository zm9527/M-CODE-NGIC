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

#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "main.h"

/**
 * macro to config rx ring size.
 */
#define RX_RING_SIZE 128

/**
 * macro to config tx ring size.
 */
#define TX_RING_SIZE 512

/**
 * macro to config number of mbufs.
 */
#define NUM_MBUFS 8191

/**
 * macro to config cache size.
 */
#define MBUF_CACHE_SIZE 250

/**
 * default port config structure .
 */
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN,
		.hw_strip_crc = 1}
};


/**
 * Function to Initialize a given port using global settings and with the rx
 * buffers coming from the mbuf_pool passed as parameter
 * @param port
 *	port number.
 * @param mbuf_pool
 *	memory pool pointer.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;
	/* TODO: use q 1 for arp */

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port),
				NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port),
				NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */

	rte_eth_macaddr_get(port, &ports_eth_addr[port]);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			ports_eth_addr[port].addr_bytes[0],
			ports_eth_addr[port].addr_bytes[1],
			ports_eth_addr[port].addr_bytes[2],
			ports_eth_addr[port].addr_bytes[3],
			ports_eth_addr[port].addr_bytes[4],
			ports_eth_addr[port].addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

void dp_port_init(void)
{
	struct rte_mempool *mbuf_pool;
	uint32_t nb_ports;
	uint8_t portid;

	nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be two\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
			MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mempool !!!\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu8 "\n",
					portid);

	printf("DP Port initialization completed.\n");
}
