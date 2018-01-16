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

#include "ue.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

struct parse_modify_bearer_request_t {
	ue_context *context;
	pdn_connection *pdn;
	eps_bearer *bearer;

	gtpv2c_ie *bearer_context_to_be_created_ebi;
	gtpv2c_ie *s1u_enb_fteid;
	uint8_t *delay;
	uint32_t *s11_mme_gtpc_fteid;
};
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];
/**
 * parses gtpv2c message and populates  parse_modify_bearer_request_t structure
 * @param gtpv2c_rx
 *   buffer containing received modify bearer request message
 * @param modify_bearer_request
 *   structure to contain parsed information from message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
parse_modify_bearer_request(gtpv2c_header *gtpv2c_rx,
		struct parse_modify_bearer_request_t *modify_bearer_request)
{

	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
	    (void **) &modify_bearer_request->context);

	if (ret < 0 || !modify_bearer_request->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	/** TODO: we should fully verify mandatory fields within received
	 * message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			FOR_EACH_GROUPED_IE(current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == IE_EBI &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					modify_bearer_request->
					bearer_context_to_be_created_ebi =
					current_group_ie;
				} else if (current_group_ie->type == IE_FTEID &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					modify_bearer_request->s1u_enb_fteid =
							current_group_ie;
				}
			}
		} else if (current_ie->type == IE_FTEID &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			modify_bearer_request->s11_mme_gtpc_fteid =
				    &(IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
				    current_ie)->fteid_ie_hdr.teid_or_gre);
		} else if (current_ie->type == IE_DELAY_VALUE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			modify_bearer_request->delay =
					&IE_TYPE_PTR_FROM_GTPV2C_IE(delay_ie,
						current_ie)->delay_value;
		}
	}

	if (!modify_bearer_request->bearer_context_to_be_created_ebi
			|| !modify_bearer_request->s1u_enb_fteid) {
		fprintf(stderr, "Dropping packet\n");
		return -EPERM;
	}

	uint8_t ebi_index = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
	    modify_bearer_request->bearer_context_to_be_created_ebi) - 5;
	if (!(modify_bearer_request->context->bearer_bitmap &
			(1 << ebi_index))) {
		fprintf(stderr,
		    "Received modify bearer on non-existent EBI - "
		    "Dropping packet\n");
		return -EPERM;
	}


	modify_bearer_request->bearer =
	    modify_bearer_request->context->eps_bearers[ebi_index];
	if (!modify_bearer_request->bearer) {
		fprintf(stderr,
		    "Received modify bearer on non-existent EBI - "
		    "Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	modify_bearer_request->pdn = modify_bearer_request->bearer->pdn;

	return 0;
}

/**
 * from parameters, populates gtpv2c message 'modify bearer response' and
 * populates required information elements as defined by
 * clause 7.2.8 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'modify bearer request' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the bearer to be modified
 * @param bearer
 *   bearer data structure to be modified
 */
static void
set_modify_bearer_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer)
{
	set_gtpv2c_teid_header(gtpv2c_tx, GTP_MODIFY_BEARER_RSP,
	    context->s11_mme_gtpc_teid, sequence);

	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);

	gtpv2c_ie *bearer_context_group =
		create_bearer_context_ie(gtpv2c_tx, IE_INSTANCE_ZERO);
	add_grouped_ie_length(bearer_context_group,
		set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO));
	add_grouped_ie_length(bearer_context_group,
		set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
				bearer->eps_bearer_id));
	add_grouped_ie_length(bearer_context_group,
		set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S1U_SGW_GTPU,
		IE_INSTANCE_ZERO, s1u_sgw_ip,
		bearer->s1u_sgw_gtpu_teid));
}


int
process_modify_bearer_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx)
{
	struct dp_id dp_id = { .id = DPN_ID };
	struct parse_modify_bearer_request_t modify_bearer_request = { 0 };
	uint32_t i;
	int ret = parse_modify_bearer_request(gtpv2c_rx,
			&modify_bearer_request);
	if (ret)
		return ret;

	/* TODO something with modify_bearer_request.delay if set */

	if (modify_bearer_request.s11_mme_gtpc_fteid != NULL &&
			modify_bearer_request.context->s11_mme_gtpc_teid !=
			*modify_bearer_request.s11_mme_gtpc_fteid)
		modify_bearer_request.context->s11_mme_gtpc_teid =
		    *modify_bearer_request.s11_mme_gtpc_fteid;


	modify_bearer_request.bearer->s1u_enb_gtpu_ipv4 =
	    IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
			    modify_bearer_request.s1u_enb_fteid)->ip_u.ipv4;
	modify_bearer_request.bearer->s1u_enb_gtpu_teid =
	    IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
			    modify_bearer_request.s1u_enb_fteid)->
			    fteid_ie_hdr.teid_or_gre;
	modify_bearer_request.bearer->eps_bearer_id =
			*IE_TYPE_PTR_FROM_GTPV2C_IE(
	    uint8_t, modify_bearer_request.bearer_context_to_be_created_ebi);

	set_modify_bearer_response(gtpv2c_tx, gtpv2c_rx->teid_u.has_teid.seq,
	    modify_bearer_request.context, modify_bearer_request.bearer);

	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));
	 session.ue_addr.iptype = IPTYPE_IPV4;
	 session.ue_addr.u.ipv4_addr =
		 ntohl(modify_bearer_request.pdn->ipv4.s_addr);
	 session.ul_s1_info.sgw_teid =
		 ntohl(modify_bearer_request.bearer->s1u_sgw_gtpu_teid);
	 session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	 session.ul_s1_info.sgw_addr.u.ipv4_addr =
		 ntohl(modify_bearer_request.bearer->s1u_sgw_gtpu_ipv4.s_addr);
	 session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	 session.ul_s1_info.enb_addr.u.ipv4_addr =
		 ntohl(modify_bearer_request.bearer->s1u_enb_gtpu_ipv4.s_addr);
	 session.dl_s1_info.enb_teid =
		 ntohl(modify_bearer_request.bearer->s1u_enb_gtpu_teid);
	 session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	 session.dl_s1_info.enb_addr.u.ipv4_addr =
		 ntohl(modify_bearer_request.bearer->s1u_enb_gtpu_ipv4.s_addr);
	 session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	 session.dl_s1_info.sgw_addr.u.ipv4_addr =
		 ntohl(modify_bearer_request.bearer->s1u_sgw_gtpu_ipv4.s_addr);
	 session.ul_apn_mtr_idx = 0;
	 session.dl_apn_mtr_idx = 0;
	 session.num_ul_pcc_rules = 1;
	 session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	 session.num_dl_pcc_rules = 1;
	 session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

	 session.num_adc_rules = num_adc_rules;
	 for (i = 0; i < num_adc_rules; ++i)
			 session.adc_rule_id[i] = adc_rule_id[i];

	 session.sess_id = SESS_ID(
			modify_bearer_request.context->s11_sgw_gtpc_teid,
			modify_bearer_request.bearer->eps_bearer_id);

	if (session_modify(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE, "Bearer Session modify fail !!!");
	return 0;
}
