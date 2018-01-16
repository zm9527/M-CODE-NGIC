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

/**
 * pkt_handler.c: Main processing for uplink and downlink packets.
 * Also process any notification coming from interface core for
 * messages from CP for modifications to an active session.
 * This is done by the worker core in the pipeline.
 */

#include <unistd.h>
#include <locale.h>

#include "main.h"
#include "acl.h"
#include "interface.h"

#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_east;
extern pcap_dumper_t *pcap_dumper_west;
#endif /* PCAP_GEN */
int
notification_handler(struct rte_pipeline *p,
	struct rte_mbuf **pkts,
	uint32_t n,
	void *arg)
{
	struct rte_mbuf *buf_pkt = NULL;
	uint64_t pkt_mask = 0, pkts_queue_mask = 0;
	struct rte_ring *ring;
	int64_t *sess;
	unsigned int ret = 32, num = 32, i;
	struct dp_session_info *data;
	struct dp_session_info *sess_info[MAX_BURST_SZ];
	int wk_index = (uintptr_t)arg;
	struct epc_worker_params *wk_params = &epc_app.worker[wk_index];
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ];

	for (i = 0; i < n; ++i) {
		buf_pkt = pkts[i];
		sess = rte_pktmbuf_mtod(buf_pkt, uint64_t *);
		data = get_session_data(*sess, 1);

		if (data == NULL)
			continue;

		rte_ctrlmbuf_free(buf_pkt);
		ring = data->dl_ring;
		if (data->sess_state != CONNECTED)
			data->sess_state = CONNECTED;

		if (!ring)
			continue; /* No dl ring*/
		/* de-queue this ring and send the downlink pkts*/
		while (ret) {
			ret = rte_ring_sc_dequeue_burst(ring,
					(void **)pkts, num);
			pkt_mask = (1 << ret) - 1;
			for (i = 0; i < ret; ++i)
				sess_info[i] = data;
			gtpu_encap(&sess_info[0], (struct rte_mbuf **)pkts, ret,
					&pkt_mask, &pkts_queue_mask);
			if (pkts_queue_mask != 0)
				RTE_LOG(ERR, DP, "Something is wrong!!, the "
						"session still doesnt hv "
						"enb teid\n");
			update_nexthop_info((struct rte_mbuf **)pkts, num,
					&pkt_mask, app.s1u_port, &sdf_info[0]);
			for (i = 0; i < ret; ++i)
				rte_pipeline_port_out_packet_insert(
					epc_app.worker[wk_index].pipeline,
					app.s1u_port, pkts[i]);
		}
		if (rte_ring_enqueue(wk_params->dl_ring_container, ring) ==
				ENOBUFS) {
			RTE_LOG(ERR, DP, "Can't put ring back, so free it\n");
			rte_ring_free(ring);
		}
	}

	return 0;
}

int
sgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index)
{
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ];
	struct dp_session_info *si[MAX_BURST_SZ];
	uint64_t pkts_mask;

	pkts_mask = (~0LLU) >> (64 - n);

	/* Get downlink session info */
	dl_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0], &si[0]);

	update_enb_info(pkts, n, &pkts_mask, &sdf_info[0]);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.s1u_port, &sdf_info[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

void
filter_ul_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, uint64_t *pkts_mask)
{
	uint32_t *sdf_rule_id = NULL;
	struct pcc_id_precedence sdf_info[MAX_BURST_SZ];
	struct pcc_id_precedence adc_info[MAX_BURST_SZ];
	void *adc_ue_info[MAX_BURST_SZ] = {NULL};
	struct dp_sdf_per_bearer_info *sdf_bearer_info[MAX_BURST_SZ] = {NULL};
	uint64_t adc_pkts_mask = 0;
	uint32_t *adc_rule_a;
	uint32_t adc_rule_b[MAX_BURST_SZ];

	sdf_rule_id = sdf_lookup(pkts, n);

	filter_pcc_entry_lookup(FILTER_SDF, sdf_rule_id, n, &sdf_info[0]);

	/* ADC table lookup*/
	adc_rule_a = adc_ul_lookup(pkts, n);

	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], UL_FLOW);

	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);

	/* get ADC UE info struct*/
	adc_ue_info_get(pkts, n, adc_rule_a, &adc_ue_info[0], UL_FLOW);

	filter_pcc_entry_lookup(FILTER_ADC, adc_rule_a, n, &adc_info[0]);

	pcc_gating(&sdf_info[0], &adc_info[0], n, pkts_mask);

	ul_sess_info_get(pkts, n, pkts_mask, &sdf_bearer_info[0]);

	update_sdf_cdr(&adc_ue_info[0], &sdf_bearer_info[0], pkts, n,
			&adc_pkts_mask, pkts_mask, UL_FLOW);

	return;
}

int
s1u_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ];
	uint64_t pkts_mask;
	uint32_t next_port;

	pkts_mask = (~0LLU) >> (64 - n);

	switch(app.spgw_cfg) {
		case SPGWU: {
			/* Decap GTPU and update meta data*/
			gtpu_decap(pkts, n, &pkts_mask);

			/*Apply adc, sdf, pcc filters on uplink traffic*/
			filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask);

			/*Set next hop directly to SGi*/
			next_port = app.sgi_port;
			break;
		}

		case SGWU: {
			ul_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0]);

			/* Set next hop IP to S5/S8 PGW port*/
			next_port = app.s5s8_sgwu_port;
			update_nexts5s8_info(pkts, n, &pkts_mask, &sdf_info[0]);
			break;
		}

		default:
			break;
	}

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &sdf_info[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

int
pgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index)
{
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ];
	uint64_t pkts_mask;

	pkts_mask = (~0LLU) >> (64 - n);

	gtpu_decap(pkts, n, &pkts_mask);

	/*Apply adc, sdf, pcc filters on uplink traffic*/
	filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.sgi_port, &sdf_info[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

static uint64_t
filter_dl_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, struct dp_sdf_per_bearer_info *sdf_info[],
		struct dp_session_info *si[])
{
	uint32_t *sdf_rule_id = NULL;
	uint64_t pkts_mask;
	struct pcc_id_precedence sdf_info_dl[MAX_BURST_SZ];
	struct pcc_id_precedence adc_info_dl[MAX_BURST_SZ];
	uint64_t adc_pkts_mask = 0;
	void *adc_ue_info[MAX_BURST_SZ] = {NULL};

	pkts_mask = (~0LLU) >> (64 - n);

	sdf_rule_id = sdf_lookup(pkts, n);

	filter_pcc_entry_lookup(FILTER_SDF, sdf_rule_id, n, &sdf_info_dl[0]);

	uint32_t *adc_rule_a;
	uint32_t adc_rule_b[MAX_BURST_SZ];

	/* ADC table lookup*/
	adc_rule_a = adc_dl_lookup(pkts, n);

	/* Identify the DNS rule and update the meta*/
	update_dns_meta(pkts, n, adc_rule_a);

	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], DL_FLOW);

	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);

	filter_pcc_entry_lookup(FILTER_ADC, adc_rule_a, n, &adc_info_dl[0]);

	pcc_gating(&sdf_info_dl[0], &adc_info_dl[0], n, &pkts_mask);

	dl_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0], &si[0]);

	update_sdf_cdr(&adc_ue_info[0], &sdf_info[0], pkts, n,
			&adc_pkts_mask, &pkts_mask, DL_FLOW);
#ifdef HYPERSCAN_DPI
	/* Send cloned dns pkts to dns handler*/
	clone_dns_pkts(pkts, n, pkts_mask);
#endif /* HYPERSCAN_DPI */

	return pkts_mask;
}

/**
 * Process Downlink traffic: sdf and adc filter, metering, charging and encap gtpu.
 * Update adc hash if dns reply is found with ip addresses.
 */
int
sgi_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ];
	struct dp_session_info *si[MAX_BURST_SZ];
	uint64_t pkts_mask, pkts_queue_mask = 0;
	uint32_t next_port;

	pkts_mask = (~0LLU) >> (64 - n);

	/**
	 * TODO : filter_dl_traffic and gtpu_encap can be called irrespective
	 *      of app configuration.
	 *      Do we need enqueue_dl_pkts and hijack ?
	 */
	switch(app.spgw_cfg) {
		case SPGWU:
			/* Filter Downlink traffic. Apply adc, sdf, pcc*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, sdf_info, si);

			/* Encap GTPU header*/
			gtpu_encap(&si[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Next port is S1U for SPGW*/
			next_port = app.s1u_port;

			/* En-queue DL pkts */
			if (pkts_queue_mask) {
				rte_pipeline_ah_packet_hijack(p, pkts_queue_mask);
				enqueue_dl_pkts(&sdf_info[0], pkts, pkts_queue_mask, wk_index);
			}
			break;

		case PGWU:
			/*Filter downlink traffic. Apply adc, sdf, pcc*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, sdf_info, si);

			/* Encap for S5/S8*/
			gtpu_encap(&si[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Set next port to S5/S8*/
			next_port = app.s5s8_pgwu_port;
			break;

		default:
			break;
	}


	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &sdf_info[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}
