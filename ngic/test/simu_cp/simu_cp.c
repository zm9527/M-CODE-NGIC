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

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>

#include "interface.h"
#include "main.h"
#include "util.h"
#include "meter.h"
#include "nsb_test_util.h"

#ifdef SIMU_CP
#define SIMU_CP_FILE "../config/simu_cp.cfg"
#define NSB_SIMU

#define ADC_RULE_FILENAME "../config/adc_rules.cfg"
#define UL_SDF_MTR_IDX 1
#define DL_SDF_MTR_IDX 2
#define APN_MTR_IDX 3

#define DDN_TEST 1

uint32_t num_adc_rule;

static uint32_t name_to_num(char *name)
{
	uint32_t num = 0;
	int i;

	for (i = strlen(name) - 1; i >= 0; i--)
		num = (num << 4) | (name[i] - 'a');

	return num;
}

static void print_adc_rule(struct adc_rules *adc_rule)
{
	printf("%-8u ", adc_rule->rule_id);
	switch (adc_rule->sel_type) {
	case DOMAIN_IP_ADDR:
		printf("%-10s " IPV4_ADDR, "IP",
			IPV4_ADDR_HOST_FORMAT(adc_rule->u.domain_ip.u.ipv4_addr));
		break;
	case DOMAIN_IP_ADDR_PREFIX:
		printf("%-10s " IPV4_ADDR"/%d ", "IP_PREFIX",
			IPV4_ADDR_HOST_FORMAT(adc_rule->u.domain_prefix.ip_addr.u.ipv4_addr),
			adc_rule->u.domain_prefix.prefix);
		break;
	case DOMAIN_NAME:
		printf("%-10s %-35s ", "DOMAIN", adc_rule->u.domain_name);
	}
	printf("%8s %15s %15u %15u %15s %15s <\n",
			(adc_rule->gate_status == CLOSE) ? "CLOSE" : "OPEN",
			adc_rule->sponsor_id,
			adc_rule->service_id,
			adc_rule->rating_group,
			adc_rule->tarriff_group,
			adc_rule->tarriff_time);
}

void parse_adc_rules(struct dp_id dp_id)
{
	FILE *adc_rule_file = fopen(ADC_RULE_FILENAME, "r");

	if (!adc_rule_file)
		rte_exit(EXIT_FAILURE, "Cannot open file: %s\n",
				ADC_RULE_FILENAME);

	uint32_t lines = 1, line = 0;
	uint32_t longest_line = 0, line_length = 0;
	const char *delimit = " \n\t";
	struct in_addr addr;

	while (!feof(adc_rule_file)) {
		char ch = fgetc(adc_rule_file);

		if (ch == '\n') {
			++lines;
			if (longest_line < line_length)
				longest_line = line_length + 1;
			line_length = 0;
		} else {
			line_length++;
		}
	}
	rewind(adc_rule_file);
	clearerr(adc_rule_file);
	char *buffer = (char *)rte_malloc_socket(NULL, sizeof(char) * longest_line,
				RTE_CACHE_LINE_SIZE, rte_socket_id());

	for (line = 0; line < lines && !feof(adc_rule_file); ++line) {
		struct adc_rules entry = { 0 };
		char in;

		*buffer = '\0';
		while (fread(&in, 1, 1, adc_rule_file)) {
			if (in == '\n')
				break;
			strncat(buffer, &in, 1);
		}

		if (*buffer == '#' || *buffer == '\n')
			continue;

		{ /* determine rule (if any)*/
			char *rule_str = strtok(buffer, delimit);

			if (rule_str != NULL) {
				char *t;

				/* assume IP unless '/' or alpha is encountered*/
				entry.sel_type = DOMAIN_IP_ADDR;
				for (t = rule_str; *t; ++t) {
					if (isalpha(*t)) {
						entry.sel_type = DOMAIN_NAME;
						strcpy(entry.u.domain_name, rule_str);
						break;
					} else if (*t == '/') {
						*t = '\0';
						entry.sel_type = DOMAIN_IP_ADDR_PREFIX;
						entry.u.domain_prefix.prefix =
							strtol(t+1, NULL, 10);

						inet_aton(rule_str, &addr);
						entry.u.domain_prefix.ip_addr.u.ipv4_addr = ntohl(addr.s_addr);

						break;
					} else if (*t != '.' && !isdigit(*t)) {
						rte_exit(EXIT_FAILURE, "Unexpected char in %s file :%s\n", ADC_RULE_FILENAME, rule_str);
						break;
					}
				}

				if (entry.sel_type == DOMAIN_IP_ADDR) {
					inet_aton(rule_str, &addr);
					entry.u.domain_ip.u.ipv4_addr = ntohl(addr.s_addr);
					entry.u.domain_ip.iptype = IPTYPE_IPV4;
				}
			} else
				continue;
		}
		{
			char *sponsor_id = strtok(NULL, delimit);

			if (sponsor_id != NULL) {
				entry.gate_status = strcmp(sponsor_id, "DROP");
				if (entry.gate_status == CLOSE)
					sponsor_id = strtok(NULL, delimit);
				if (sponsor_id != NULL)
					strcpy(entry.sponsor_id, sponsor_id);
			}
		}
		{
			char *service_id = strtok(NULL, delimit);

			if (service_id != NULL) {
				entry.service_id = name_to_num(service_id);

				if (!strcmp(service_id, "CIPA"))
					puts("CIPA Rule");
			}
		}
		{
			char *rate_group = strtok(NULL, delimit);

			if (rate_group)
				entry.rating_group = name_to_num(rate_group);
		}
		{
			char *tarriff_group = strtok(NULL, delimit);

			if (tarriff_group)
				strcpy(entry.tarriff_group, tarriff_group);
		}
		{
			char *tarriff_time = strtok(NULL, delimit);

			if (tarriff_time)
				strcpy(entry.tarriff_time, tarriff_time);
		}

		entry.precedence = 0x1ffffffe;
		memset(entry.rule_name, 0, sizeof(entry.rule_name));
		/* Add default rule */
		entry.rule_id = ++num_adc_rule;
		if (adc_entry_add(dp_id, entry) < 0)
			rte_exit(EXIT_FAILURE, "ADC entry add fail !!!");
		print_adc_rule(&entry);
	}
}

void simu_cp(void)
{
	uint32_t sess_id = 1;
	struct dp_id dp_id;
	int i = 0;
	struct rte_cfgfile *file = rte_cfgfile_load(SIMU_CP_FILE, 0);
	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				SIMU_CP_FILE);

	uint32_t enb_ip = 0;
#ifdef NG4T_SIMU
	uint32_t max_ue_ran = 0;
	uint32_t max_enb_ran = 0;
	uint32_t enb_ip_idx = 0;
#endif
	uint32_t enb_teid = 0;
	uint32_t ue_ip_s = 0;
	uint32_t ue_ip_s_range = 0;
	uint32_t as_ip_s = 0;
	uint32_t max_entries = 0;
	uint32_t max_rules = 0;
	uint32_t max_ul_rules = 0;
	uint32_t max_dl_rules = 0;
	uint32_t max_ue_sess = 0;
	uint32_t max_mtr_profile_entries = 0;
	uint32_t default_bearer = 0;
	uint32_t dedicated_bearer = 0;
	const char *file_entry;
	char *end;
	struct in_addr addr;

#ifdef NG4T_SIMU
	file_entry = rte_cfgfile_get_entry(file, "0", "ng4t_max_ue_ran");
	if (file_entry)
		max_ue_ran =  (uint32_t) strtoll(file_entry, &end, 16);

	file_entry = rte_cfgfile_get_entry(file, "0", "ng4t_max_enb_ran");
	if (file_entry)
		max_enb_ran =  (uint32_t) strtoll(file_entry, &end, 16);
#endif
	file_entry = rte_cfgfile_get_entry(file, "0", "enodeb_ip");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		enb_ip = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "ue_ip_start");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		ue_ip_s = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "ue_ip_start_range");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		ue_ip_s_range = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "as_ip_start");
	if (file_entry) {
		if (inet_aton(file_entry, &addr) == 0) {
			fprintf(stderr, "Invalid address\n");
			exit(EXIT_FAILURE);
		}
		as_ip_s = ntohl(addr.s_addr);
	}

	file_entry = rte_cfgfile_get_entry(file, "0", "max_entries");
	if (file_entry)
		max_entries =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "max_rules");
	if (file_entry)
		max_rules =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "max_ul_rules");
	if (file_entry)
		max_ul_rules =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "max_dl_rules");
	if (file_entry)
		max_dl_rules =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "max_ue_sess");
	if (file_entry)
		max_ue_sess =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0",
										"max_meter_profile_entries");
	if (file_entry)
		max_mtr_profile_entries =  (uint32_t) strtoll(file_entry,
				&end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "default_bearer");
	if (file_entry)
		default_bearer =  (uint32_t) strtoll(file_entry, &end, 10);

	file_entry = rte_cfgfile_get_entry(file, "0", "dedicated_bearer");
	if (file_entry)
		dedicated_bearer =  (uint32_t) strtoll(file_entry, &end, 10);

	/* Create & add entry in SDF filter Table*/
	struct pkt_filter sdf_filter_entry;
	dp_id.id = 12345;
	sprintf(dp_id.name, "SDF_FILTER_TABLE");
	for (i = 0; i < max_rules; i++) {
		sdf_filter_entry.pcc_rule_id = i + 1;
		sdf_filter_entry.precedence = 0x1fffffff - (i + 1);
		/* buf1 is 5 tuple rule */
		if (i < max_ul_rules)
			sprintf(sdf_filter_entry.u.rule_str,
				"16.0.0.0/8 "IPV4_ADDR"/32 0 : 65535 0 : 65535 0x0/0x0\n",
				IPV4_ADDR_HOST_FORMAT(as_ip_s+i));
		else
			sprintf(sdf_filter_entry.u.rule_str,
				""IPV4_ADDR"/32 16.0.0.0/8 0 : 65535 0 : 65535 0x0/0x0\n",
				IPV4_ADDR_HOST_FORMAT(as_ip_s+i-max_ul_rules));

		if (sdf_filter_entry_add(dp_id, sdf_filter_entry) < 0)
			rte_exit(EXIT_FAILURE,"SDF filter entry add fail !!!");
	}
	sdf_filter_entry.pcc_rule_id = max_rules + 1;
	sdf_filter_entry.precedence = 0x1fffffff - (max_rules + 1);
	sprintf(sdf_filter_entry.u.rule_str,
				"0.0.0.0/0 0.0.0.0/0 25000 : 27000 25000 : 27000 0x0/0x0\n");
	if (sdf_filter_entry_add(dp_id, sdf_filter_entry) < 0)
		rte_exit(EXIT_FAILURE, "SDF filter entry add fail !!!");

	sdf_filter_entry.pcc_rule_id = max_rules + 2;
	sdf_filter_entry.precedence = 0x1fffffff - (max_rules + 2);
	sprintf(sdf_filter_entry.u.rule_str,
				"0.0.0.0/0 0.0.0.0/0 1200 : 1300 0 : 100 0x0/0x0\n");

	if (sdf_filter_entry_add(dp_id, sdf_filter_entry) < 0)
		rte_exit(EXIT_FAILURE, "SDF filter entry add fail !!!");


#ifdef ADC_UPFRONT
	/* Create & add entry in ADC Rule Table*/
	sprintf(dp_id.name, "ADC_RULE_TABLE");

	parse_adc_rules(dp_id);
#endif /* ADC_UPFRONT*/
	/* Create & update Meter Profile table*/
	struct mtr_entry mtr_entry;
	sprintf(dp_id.name, "METER_TABLE");

	/* The CIR is set in Bytes per sec. Before configuring please convert
	 * MBR from kbps to Byte/sec.
	 */
	mtr_entry.metering_method = SRTCM_COLOR_BLIND;
	mtr_entry.mtr_param.cbs = 2048;
	mtr_entry.mtr_param.ebs = 2048;

	/* For UL:
	 * CIR is defined as (PPS x (Out Packet Size - Ethernet Hdr Size))
	 * PPS is defined as : (MBR in bps) / (8 * Out Pkt Size)
	 * For DL:
	 * CIR is defined as (PPS x (In Packet Size - Ethernet Hdr Size))
	 * PPS is defined as : (MBR in bps) / (8 * Out Pkt Size)
	 */

	mtr_entry.mtr_param.cir = 696 * 74;    /* UL: Rate = 512kbps */
	mtr_entry.mtr_profile_index = UL_SDF_MTR_IDX;
	if (meter_profile_entry_add(dp_id, mtr_entry) < 0)
		rte_exit(EXIT_FAILURE, "Meter profile entry add fail !!!");

	mtr_entry.mtr_param.cir = 391 * 110;    /* DL: Rate = 512kbps */
	mtr_entry.mtr_profile_index = DL_SDF_MTR_IDX;
	if (meter_profile_entry_add(dp_id, mtr_entry) < 0)
		rte_exit(EXIT_FAILURE, "Meter profile entry add fail !!!");

	mtr_entry.mtr_param.cir = 391 * 110 * 4;    /*  APN: Rate = 2Mbps */
	mtr_entry.mtr_profile_index = APN_MTR_IDX;
	if (meter_profile_entry_add(dp_id, mtr_entry) < 0)
		rte_exit(EXIT_FAILURE, "Meter profile entry add fail !!!");

	/* Create & add entry in PCC Rule Table*/
	struct pcc_rules pcc_info;
	pcc_info.gate_status = OPEN;
	pcc_info.rating_group = 12345;
	pcc_info.report_level = 0;
	pcc_info.monitoring_key = 0;
	pcc_info.charging_mode = 0;
	pcc_info.drop_pkt_count = 0;
	pcc_info.service_id = 0;
	pcc_info.mute_notify = 0;
	pcc_info.session_cont = 0;
	pcc_info.rule_status = 0;
	pcc_info.redirect_info.info = 0;
	pcc_info.metering_method = 0;
	pcc_info.precedence = 0;
	memset(pcc_info.sponsor_id, 0, sizeof(pcc_info.sponsor_id));
	memset(pcc_info.rule_name, 0, sizeof(pcc_info.rule_name));
	sprintf(dp_id.name, "PCC_RULE_TABLE");
	/* PCC entry for default rule */
	pcc_info.rule_id = max_rules + 1;
	pcc_info.qos.ul_mtr_profile_index = 1;
	pcc_info.qos.dl_mtr_profile_index = 1;
	pcc_entry_add(dp_id, pcc_info);

	pcc_info.rule_id = max_rules + 2;
	pcc_entry_add(dp_id, pcc_info);

	for (i = 0; i < max_rules; i++) {
		pcc_info.rule_id = i + 1;
		if (i < max_ul_rules)
			pcc_info.qos.ul_mtr_profile_index = UL_SDF_MTR_IDX;
		else
			pcc_info.qos.dl_mtr_profile_index = DL_SDF_MTR_IDX;
		if (pcc_entry_add(dp_id, pcc_info) < 0 )
			rte_exit(EXIT_FAILURE,"PCC entry add fail !!!");
	}

	/* Create Bearer Session Information*/
	int s;
	sprintf(dp_id.name, "BEAR_SESS_TABLE");
	if (dedicated_bearer == 0) {
		/* Default Bearer Config*/
		for (s = 0; s < max_ue_sess; s++) {
			struct session_info si;

			memset(&si, 0, sizeof(struct session_info));
			sess_id = s + 1;
			/* Generate enb_teid & enb_ip_idx */
#ifdef NG4T_SIMU
			simu_enb_ipv4(s, default_bearer, max_ue_ran, max_enb_ran,
							&enb_teid, &enb_ip_idx);
			enb_ip = enb_ip + enb_ip_idx;
#elif defined NSB_SIMU
			generate_teid(s, default_bearer, max_ue_sess, &enb_teid);
			enb_ip = enb_ip;
#endif

			si.ul_apn_mtr_idx = APN_MTR_IDX;
			si.dl_apn_mtr_idx = APN_MTR_IDX;
			si.ipcan_dp_bearer_cdr.charging_id = 10;
			si.ipcan_dp_bearer_cdr.pdn_conn_charging_id = 10;
			si.ue_addr.iptype = IPTYPE_IPV4;
			si.ue_addr.u.ipv4_addr = ue_ip_s + s;

			si.ul_s1_info.sgw_teid = s + 1;
			si.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			si.ul_s1_info.enb_addr.u.ipv4_addr = enb_ip;
			si.num_ul_pcc_rules = max_ul_rules + 1;
			si.ul_pcc_rule_id[0] = max_rules + 1;

			for (i = 0; i < max_ul_rules ; i++)
				si.ul_pcc_rule_id[i + 1] = i + 1;

#ifdef ADC_UPFRONT
			/* update adc rules */
			si.num_adc_rules = num_adc_rule;
			for (i = 0; i < si.num_adc_rules; i++)
				si.adc_rule_id[i] = i + 1;
#endif /* ADC_UPFRONT */

			si.sess_id = (sess_id << 4) + default_bearer;
			if (session_create(dp_id, si) < 0)
				rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

			/* Modify the session */
			si.dl_s1_info.enb_teid = enb_teid;
			si.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			si.dl_s1_info.enb_addr.u.ipv4_addr = enb_ip;
			si.num_dl_pcc_rules = max_dl_rules + 1;
			si.dl_pcc_rule_id[0] = max_rules + 2;

			for (i = 0; i < max_dl_rules ; i++)
				si.dl_pcc_rule_id[i + 1] = i + max_ul_rules + 1;


			if (session_modify(dp_id, si) < 0)
				rte_exit(EXIT_FAILURE,"Bearer Session modify fail !!!");
#ifdef DDN_TEST
			if (s == (max_ue_sess - 1)) {
				si.dl_s1_info.enb_teid = 0;

				if (session_modify(dp_id, si) < 0)
					rte_exit(EXIT_FAILURE, "Bearer Session"
							" modify fail !!!");

				sleep(60);
				si.dl_s1_info.enb_teid = enb_teid;

				if (session_modify(dp_id, si) < 0)
					rte_exit(EXIT_FAILURE, "Bearer "
						"Session modify fail !!!");
			}
#endif /*DDN_TEST */
		}
	} else {
		/* Default Bearer Config*/
		for (s = 0; s < max_ue_sess; s++) {
			struct session_info si;

			memset(&si, 0, sizeof(struct session_info));
			sess_id = s + 1;
			/* Generate enb_teid & enb_ip_idx */
#ifdef NG4T_SIMU
			simu_enb_ipv4(s, default_bearer, max_ue_ran, max_enb_ran,
							&enb_teid, &enb_ip_idx);
			enb_ip = enb_ip + enb_ip_idx;
#elif defined NSB_SIMU
			generate_teid(s, default_bearer, max_ue_sess, &enb_teid);
			enb_ip = enb_ip;
#endif

			si.ul_apn_mtr_idx = APN_MTR_IDX;
			si.dl_apn_mtr_idx = APN_MTR_IDX;
			si.ipcan_dp_bearer_cdr.charging_id = 10;
			si.ipcan_dp_bearer_cdr.pdn_conn_charging_id = 10;
			si.ue_addr.iptype = IPTYPE_IPV4;
			si.ue_addr.u.ipv4_addr = ue_ip_s + s;

			si.ul_s1_info.sgw_teid = s + 1;
			si.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			si.ul_s1_info.enb_addr.u.ipv4_addr = enb_ip;
			si.num_ul_pcc_rules = max_ul_rules/2;

			for (i = 0; i < max_ul_rules/2 ; i++)
				si.ul_pcc_rule_id[i] = i + 1;

			si.sess_id = (sess_id << 4) + default_bearer;
			if (session_create(dp_id, si) < 0)
				rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

			/* Modify the session */
			si.dl_s1_info.enb_teid = enb_teid;
			si.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			si.dl_s1_info.enb_addr.u.ipv4_addr = enb_ip;
			si.num_dl_pcc_rules = max_dl_rules / 2;

			for (i = 0; i < max_dl_rules / 2 ; i++)
				si.dl_pcc_rule_id[i] = i + max_ul_rules + 1;

			if (session_modify(dp_id, si) < 0)
				rte_exit(EXIT_FAILURE,"Bearer Session modify fail !!!");
			/*session_delete(sess_id);*/
		}
		/* Dedicated Bearer Config*/
		for (s = 0; s < max_ue_sess; s++) {
			struct session_info si;

			memset(&si, 0, sizeof(struct session_info));
			sess_id = s + 1;
			/* Generate enb_teid & enb_ip_idx */
#ifdef NG4T_SIMU
			simu_enb_ipv4(s, dedicated_bearer, max_ue_ran, max_enb_ran,
							&enb_teid, &enb_ip_idx);
			enb_ip = enb_ip + enb_ip_idx;
#elif defined NSB_SIMU
			generate_teid(s, dedicated_bearer, max_ue_sess, &enb_teid);
			enb_ip = enb_ip;
#endif

			si.ul_apn_mtr_idx = APN_MTR_IDX;
			si.dl_apn_mtr_idx = APN_MTR_IDX;
			si.ipcan_dp_bearer_cdr.charging_id = 10;
			si.ipcan_dp_bearer_cdr.pdn_conn_charging_id = 10;
			si.ue_addr.iptype = IPTYPE_IPV4;
			si.ue_addr.u.ipv4_addr = ue_ip_s + s;

			si.ul_s1_info.sgw_teid = s + 1;
			si.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			si.ul_s1_info.enb_addr.u.ipv4_addr = enb_ip;
			si.num_ul_pcc_rules = max_ul_rules/2;

			for (i = 0; i < max_ul_rules/2 ; i++)
				si.ul_pcc_rule_id[i] = i + 1 + max_ul_rules/2;

			si.sess_id = (sess_id<<4) + dedicated_bearer;
			if (session_create(dp_id, si) < 0)
				rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

			/* Modify the session */
			si.dl_s1_info.enb_teid = enb_teid;
			si.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
			si.dl_s1_info.enb_addr.u.ipv4_addr = enb_ip;
			si.num_dl_pcc_rules = max_dl_rules/2;

			for (i = 0; i < max_dl_rules/2 ; i++)
				si.dl_pcc_rule_id[i] = i + max_ul_rules + 1
					+ max_dl_rules/2;

			if (session_modify(dp_id, si) < 0)
				rte_exit(EXIT_FAILURE,"Bearer Session modify fail !!!");
		}
	}
	printf("Simulted simu_cp.cfg config done\n");

	struct msg_ue_cdr ue_cdr;
	ue_cdr.session_id = (1 << 4) + 5;
	ue_cdr.type = CDR_TYPE_BEARER;
	ue_cdr.action = 0;
	sleep(10);
	printf("Simu export CDR for sess id %"PRIu64"\n", ue_cdr.session_id);
	ue_cdr_flush(dp_id, ue_cdr);
	sleep(10);
	ue_cdr.type = CDR_TYPE_ALL;
	ue_cdr.action = 1;
	printf("Simu export CDR for sess id %"PRIu64"\n", ue_cdr.session_id);
	ue_cdr_flush(dp_id, ue_cdr);

}
#endif				/* SIMU_CP */


