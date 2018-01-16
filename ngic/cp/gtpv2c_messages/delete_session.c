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

#include <rte_debug.h>

#include "ue.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "gtpv2c_set_ie.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

/**
 * Parses delete session request message and handles the removal of
 * corresponding data structures internal to the control plane - as well as
 * notifying the data plane of such changes
 * @param gtpv2c_rx
 *   buffer containing create delete session request message
 * @param _context
 *   returns the UE context structure pertaining to the session to be deleted
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
delete_context(gtpv2c_header *gtpv2c_rx, ue_context **_context)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *limit_ie;
	int ret;
	int i;
	ue_context *context = NULL;
	gtpv2c_ie *ebi_ei_to_be_removed = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
	    (void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	/** TODO: we should verify mandatory fields within received message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		switch (current_ie->type) {
		case IE_EBI:
			if (current_ie->instance == IE_INSTANCE_ZERO)
				ebi_ei_to_be_removed = current_ie;
			break;
		}
	}

	if (!ebi_ei_to_be_removed) {
		/* TODO: should be responding with response indicating error
		 * in request */
		fprintf(stderr, "Received delete session without ebi! - "
				"dropping\n");
		return -EPERM;
	}

	uint8_t ebi = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
			ebi_ei_to_be_removed);
	uint8_t ebi_index = ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
		    "Received delete session on non-existent EBI - "
		    "Dropping packet\n");
		fprintf(stderr, "ebi %u\n",
		    *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t, ebi_ei_to_be_removed));
		fprintf(stderr, "ebi_index %u\n", ebi_index);
		fprintf(stderr, "bearer_bitmap %04x\n", context->bearer_bitmap);
		fprintf(stderr, "mask %04x\n", (1 << ebi_index));
		return -EPERM;
	}

	pdn_connection *pdn = context->pdns[ebi_index];
	if (!pdn) {
		fprintf(stderr, "Received delete session on "
				"non-existent EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	if (pdn->default_bearer_id != ebi) {
		fprintf(stderr,
		    "Received delete session referencing incorrect "
		    "default bearer ebi");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	eps_bearer *bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr, "Received delete session on non-existent "
				"default EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	for (i = 0; i < MAX_BEARERS; ++i) {
		if (pdn->eps_bearers[i] == NULL)
			continue;

		if (context->eps_bearers[i] == pdn->eps_bearers[i]) {
			bearer = context->eps_bearers[i];
			struct session_info si;
			memset(&si, 0, sizeof(si));

			/**
			 * ebi and s1u_sgw_teid is set here for zmq/sdn
			 */
			si.bearer_id = ebi;
			si.ue_addr.u.ipv4_addr =
				ntohl(pdn->ipv4.s_addr);
			si.ul_s1_info.sgw_teid = bearer->s1u_sgw_gtpu_teid;
			si.sess_id = SESS_ID(
					context->s11_sgw_gtpc_teid,
					si.bearer_id);
			struct dp_id dp_id = { .id = DPN_ID };
			session_delete(dp_id, si);

			rte_free(pdn->eps_bearers[i]);
			pdn->eps_bearers[i] = NULL;
			context->eps_bearers[i] = NULL;
			context->bearer_bitmap &= ~(1 << i);
		} else {
			rte_panic("Incorrect provisioning of bearers\n");
		}
	}
	--context->num_pdns;
	rte_free(pdn);
	context->pdns[ebi_index] = NULL;
	context->teid_bitmap = 0;

	*_context = context;
	return 0;
}

int
process_delete_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
{
	ue_context *context = NULL;
	int ret;

	if (spgw_cfg == SGWC) {
		gtpv2c_ie *current_ie;
		gtpv2c_ie *limit_ie;
		pdn_connection *pdn = NULL;
		gtpv2c_ie *del_ebi_ie = NULL;
		uint32_t s5s8_pgw_gtpc_del_teid;
		static uint32_t process_sgwc_s5s8_ds_req_cnt;

		/* s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
		ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &gtpv2c_rx->teid_u.has_teid.teid,
			(void **) &context);

		if (ret < 0 || !context)
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

		FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
		{
			switch (current_ie->type) {
			case IE_EBI:
				if (current_ie->instance == IE_INSTANCE_ZERO)
					del_ebi_ie = current_ie;
				break;
			}
		}
		uint8_t del_ebi =
				*IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
				del_ebi_ie);
		uint8_t del_ebi_index = del_ebi -5;
		pdn = context->pdns[del_ebi_index];
	 	/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
		 * key->ue_context_by_fteid_hash */
		s5s8_pgw_gtpc_del_teid = pdn->s5s8_pgw_gtpc_teid;
		ret =
			gen_sgwc_s5s8_delete_session_request(gtpv2c_rx,
				gtpv2c_s5s8_tx, s5s8_pgw_gtpc_del_teid,
				gtpv2c_rx->teid_u.has_teid.seq, del_ebi);
		RTE_LOG(DEBUG, CP, "NGIC- delete_session.c::"
				"\n\tprocess_delete_session_request::case= %d;"
				"\n\tprocess_sgwc_s5s8_ds_req_cnt= %u;"
				"\n\tue_ip= pdn->ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
				"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
				"\n\tgen_delete_s5s8_session_request= %d\n",
				spgw_cfg, process_sgwc_s5s8_ds_req_cnt++,
				inet_ntoa(pdn->ipv4),
				inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
				pdn->s5s8_sgw_gtpc_teid,
				inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
				pdn->s5s8_pgw_gtpc_teid,
				ret);
		return ret;
	}

	ret = delete_context(gtpv2c_rx, &context);
	if (ret)
		return ret;

	set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
	    context->s11_mme_gtpc_teid, gtpv2c_rx->teid_u.has_teid.seq);
	set_cause_accepted_ie(gtpv2c_s11_tx, IE_INSTANCE_ZERO);

	return 0;
}
