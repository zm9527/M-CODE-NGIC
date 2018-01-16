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

#ifndef __EPC_ARP_ICMP_H__
#define __EPC_ARP_ICMP_H__
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of ARP packet processing.
 */
#include <rte_ether.h>
#include <rte_rwlock.h>

/**
 * seconds between ARP request retransmission.
 */
#define ARP_TIMEOUT 2
/**
 * ring size.
 */
#define ARP_BUFFER_RING_SIZE 128
/**
 * ARP entry populated and echo reply received.
 */
#define COMPLETE   1
/**
 * ARP entry populated and awaiting ARP reply.
 */
#define INCOMPLETE 0
/**
 * set to enable debug.
 */
#define ARPICMP_DEBUG  0

/** Pipeline arguments */
struct pipeline_arp_icmp_in_port_h_arg {
	/** rte pipeline */
	struct  pipeline_arp_icmp *p;
	/** in port id */
	uint8_t in_port_id;
};

/**
 * print mac format.
 */
#define FORMAT_MAC  \
	"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8":" \
"%02"PRIx8
/**
 * print eth_addr.
 */
#define FORMAT_MAC_ARGS(eth_addr)  \
	(eth_addr).addr_bytes[0],  \
(eth_addr).addr_bytes[1],  \
(eth_addr).addr_bytes[2],  \
(eth_addr).addr_bytes[3],  \
(eth_addr).addr_bytes[4],  \
(eth_addr).addr_bytes[5]


/** IPv4 key for ARP table. */
struct pipeline_arp_icmp_arp_key_ipv4 {
	/** ipv4 address */
	uint32_t ip;
	/** port id */
	uint8_t port_id;
	/** key filler */
	uint8_t filler1;
	/** key filler */
	uint8_t filler2;
	/** key filler */
	uint8_t filler3;
};


/** ARP table entry. */

struct arp_entry_data {
	/** ether address */
	struct ether_addr eth_addr;
	/** port number */
	uint8_t port;
	/** status: COMPLETE/INCOMPLETE */
	uint8_t status;
	/** ipv4 address */
	uint32_t ip;
	/** last update time */
	time_t last_update;
	/** pkts queued */
	struct rte_ring *queue;
	/** queue lock */
	rte_rwlock_t queue_lock;
} __attribute__((packed));

/**
 * Print ARP packet.
 *
 * @param pkt
 *	ARP packet.
 *
 */
void print_pkt1(struct rte_mbuf *pkt);

/**
 * Send ARP request.
 *
 * @param port_id
 *	port id.
 * @param ip
 *	ip address to resolve the mac.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int send_arp_req(unsigned port_id, uint32_t ip);

/**
 * Retrieve MAC address.
 *
 * @param ipaddr
 *	dst IP address.
 * @param phy_port
 *	port no.
 * @param hw_addr
 *	mac address.
 * @param nhip
 *	next hop ip.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int arp_icmp_get_dest_mac_address(__rte_unused const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr, uint32_t *nhip);

/**
 * Retrieve ARP entry.
 *
 * @param arp_key
 *	key.
 *
 * @return
 *	arp entry data if found.
 *	neg value if error.
 */
struct arp_entry_data *retrieve_arp_entry(
			const struct pipeline_arp_icmp_arp_key_ipv4 arp_key);

/**
 * Queue unresolved arp pkts.
 *
 * @param arp_data
 *	arp entry data.
 * @param m
 *	packet pointer.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int arp_queue_unresolved_packet(struct arp_entry_data *arp_data,
				struct rte_mbuf *m);

#endif /*__EPC_ARP_ICMP_H__ */
