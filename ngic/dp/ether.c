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

#include <arpa/inet.h>

#include <rte_ip.h>

#include "main.h"
#include "ether.h"
#include "util.h"
#include "ipv4.h"
#include "pipeline/epc_arp_icmp.h"

/**
 * Function to set ethertype.
 *
 * @param m
 *	mbuf pointer
 * @param type
 *	type
 *
 * @return
 *	None
 */
static inline void set_ether_type(struct rte_mbuf *m, uint16_t type)
{
	struct ether_hdr *eth_hdr = get_mtoeth(m);
	/* src/dst mac will be updated by send_to() */
	eth_hdr->ether_type = htons(type);
}

/**
 * Function to construct L2 headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	- 0  on success
 *	- -1 on failure (ARP lookup fail)
 */
int construct_ether_hdr(struct rte_mbuf *m, uint8_t portid,
		struct dp_sdf_per_bearer_info **sess_info)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, void *);
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)&eth_hdr[1];
	struct pipeline_arp_icmp_arp_key_ipv4 tmp_arp_key = {
		.ip = ipv4_hdr->dst_addr,
		.port_id = portid,
		0, 0, 0 /* filler */
	};

	if (app.spgw_cfg == SPGWU) {
		if (portid == app.s1u_port) {
			if (app.s1u_gw_ip != 0 &&
					(tmp_arp_key.ip & app.s1u_mask) != app.s1u_net)
				tmp_arp_key.ip = app.s1u_gw_ip;
		} else if(portid == app.sgi_port) {
			if (app.sgi_gw_ip != 0 &&
					(tmp_arp_key.ip & app.sgi_mask) != app.sgi_net)
				tmp_arp_key.ip = app.sgi_gw_ip;
		}
	} else if (app.spgw_cfg == SGWU) {
		if (portid == app.s1u_port) {
			if (app.s1u_gw_ip != 0)
				tmp_arp_key.ip = app.s1u_gw_ip;
		} else if (portid == app.s5s8_sgwu_port) {
			uint32_t s5s8_pgwu_addr =
				sess_info[0]->bear_sess_info->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr;
			if (s5s8_pgwu_addr != 0)
				tmp_arp_key.ip = htonl(s5s8_pgwu_addr);
		}
	} else if(app.spgw_cfg == PGWU) {
		if (portid == app.sgi_port) {
			if (app.sgi_gw_ip != 0)
				tmp_arp_key.ip = app.sgi_gw_ip;
		} else if (portid == app.s5s8_pgwu_port) {
			uint32_t s5s8_sgwu_addr =
				sess_info[0]->bear_sess_info->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr;
			if (s5s8_sgwu_addr != 0)
				tmp_arp_key.ip = htonl(s5s8_sgwu_addr);
		}
	}

	/* IPv4 L2 hdr */
	eth_hdr->ether_type = htons(ETH_TYPE_IPv4);

#ifdef SKIP_ARP_LOOKUP

	uint8_t i;
	struct ether_addr hw_addr;
	for (i = 0; i < 6; i++)
		hw_addr.addr_bytes[i] = 0x00 + i;

	ether_addr_copy(&hw_addr, &eth_hdr->d_addr);
#else				/* !SKIP_ARP_LOOKUP */
	struct arp_entry_data *ret_arp_data = NULL;

	if (ARPICMP_DEBUG)
		printf("arp_icmp_get_dest_mac_address search ip 0x%x\n",
								tmp_arp_key.ip);
#ifdef INDEX_ARP_LOOKUP
	if ((ipaddr & 0xff000000) == 0xb000000)
		ret_arp_data = &arp_index_dl[ipaddr & 0xfff];
	else
		ret_arp_data = &arp_index_ul[ipaddr & 0xfff];

	if (ret_arp_data->ip == ipaddr) {
		ether_addr_copy(&ret_arp_data->eth_addr, hw_addr);
		return 1;
	} else
		return 0;
#endif
	ret_arp_data = retrieve_arp_entry(tmp_arp_key);


	if (ret_arp_data == NULL) {
		RTE_LOG(DEBUG, DP, "%s: ARP lookup failed for ip 0x%x\n",
				__func__, tmp_arp_key.ip);
		return -1;
	}

	if (ret_arp_data->status == INCOMPLETE)	{
		if (arp_queue_unresolved_packet(ret_arp_data, m) == 0) {
			RTE_LOG(DEBUG, DP, "%s: after arp_queue_unresolved_packet"
					" returning -1 for ip 0x%x\n", __func__, tmp_arp_key.ip);
			return -1;
		}
	}

	RTE_LOG(DEBUG, DP,
			"MAC found for ip %s"
			", port %d - %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(*(struct in_addr *)&tmp_arp_key.ip), portid,
					ret_arp_data->eth_addr.addr_bytes[0],
					ret_arp_data->eth_addr.addr_bytes[1],
					ret_arp_data->eth_addr.addr_bytes[2],
					ret_arp_data->eth_addr.addr_bytes[3],
					ret_arp_data->eth_addr.addr_bytes[4],
					ret_arp_data->eth_addr.addr_bytes[5]);

	ether_addr_copy(&ret_arp_data->eth_addr, &eth_hdr->d_addr);
#endif				/* SKIP_ARP_LOOKUP */

	ether_addr_copy(&ports_eth_addr[portid], &eth_hdr->s_addr);

#ifdef INSTMNT
	flag_wrkr_update_diff = 1;
	total_wrkr_pkts_processed++;
#endif
	return 0;
}
