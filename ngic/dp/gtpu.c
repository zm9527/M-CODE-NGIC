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
#include "gtpu.h"

/**
 * Function to construct gtpu header.
 *
 * @param m
 *  m - mbuf pointer
 * @param teid
 *  teid - tunnel endpoint id
 * @param tpdu_len
 *  tpdu_len - length of tunneled pdu
 *
 * @return
 *  None
 */
#ifdef GTPU_HDR_SEQNB
	static uint16_t gtpu_seqnb = 0;
#endif  /* GTPU_HDR_SEQNB */

static inline void
construct_gtpu_hdr(struct rte_mbuf *m, uint32_t teid, uint16_t tpdu_len)
{
	uint8_t *gpdu_hdr;

	/* Construct GPDU header. */
	gpdu_hdr = (uint8_t *) get_mtogtpu(m);
#ifdef GTPU_HDR_SEQNB
	*(gpdu_hdr++) = (GTPU_VERSION << 5) |
					(GTP_PROTOCOL_TYPE_GTP << 4) |
					(GTPU_SEQPRESENT << 1);
	*(gpdu_hdr++) = GTP_GPDU;
	tpdu_len = tpdu_len + sizeof(GTPU_STATIC_SEQNB);
	*((uint16_t *) gpdu_hdr) = htons(tpdu_len);
	gpdu_hdr += 2;
	*((uint32_t *) gpdu_hdr) = htonl(teid);
	gpdu_hdr +=sizeof(teid);
	*((uint32_t *) gpdu_hdr) = GTPU_STATIC_SEQNB |
								htons(gtpu_seqnb);
	gtpu_seqnb++;
#else
	*(gpdu_hdr++) = (GTPU_VERSION << 5) | (GTP_PROTOCOL_TYPE_GTP << 4);
	*(gpdu_hdr++) = GTP_GPDU;
	*((uint16_t *) gpdu_hdr) = htons(tpdu_len);
	gpdu_hdr += 2;
	*((uint32_t *) gpdu_hdr) = htonl(teid);
#endif  /* GTPU_HDR_SEQNB */
}

int decap_gtpu_hdr(struct rte_mbuf *m)
{
	void *ret;

	/* Remove the GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes, UDP = 8 Bytes
	 *  from the tunneled packet.
	 * Note: the ether header must be updated before tx.
	 */
	ret = rte_pktmbuf_adj(m, GPDU_HDR_SIZE + UDP_HDR_SIZE + IPv4_HDR_SIZE);
	if (ret == NULL) {
		RTE_LOG(ERR, DP, "Error: Failed to remove GTPU header\n");
		return -1;
	}

	RTE_LOG(DEBUG, DP,
			"Decap: modified mbuf offset %d, data_len %d, pkt_len%d\n",
			m->data_off, m->data_len, m->pkt_len);
	return 0;
}

int encap_gtpu_hdr(struct rte_mbuf *m, uint32_t teid)
{
	uint8_t *pkt_ptr;
	uint16_t tpdu_len;

	tpdu_len = rte_pktmbuf_data_len(m);
	tpdu_len -= ETH_HDR_SIZE;
	/* Prepend GPDU hdr = 8 Bytes, IPv4 hdr= 20 Bytes,
	 * UDP = 8 Bytes to mbuf data in headroom.
	 */
	pkt_ptr =
		(uint8_t *) rte_pktmbuf_prepend(m,
				GPDU_HDR_SIZE + UDP_HDR_SIZE +
				IPv4_HDR_SIZE);
	if (pkt_ptr == NULL) {
		RTE_LOG(ERR, DP, "Error: Failed to add GTPU header\n");
		return -1;
	}
	RTE_LOG(DEBUG, DP,
			"Encap: modified mbuf offset %d, data_len %d, pkt_len %d\n",
			m->data_off, m->data_len, m->pkt_len);

	construct_gtpu_hdr(m, teid, tpdu_len);

	return 0;
}

uint32_t gtpu_inner_src_ip(struct rte_mbuf *m)
{
	uint8_t *pkt_ptr;
	struct ipv4_hdr *inner_ipv4_hdr;

	pkt_ptr = (uint8_t *) get_mtogtpu(m);
	RTE_LOG(DEBUG, DP, "ASR-SpirentvLS gtpu.c: GPDU_HDR_SIZE %u\n",
			GPDU_HDR_SIZE);

	pkt_ptr += GPDU_HDR_SIZE;
	inner_ipv4_hdr = (struct ipv4_hdr *)pkt_ptr;

	return inner_ipv4_hdr->src_addr;
}
