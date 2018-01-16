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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_debug.h>

#include "gtpv2c.h"
#include "gtpv2c_ie.h"
#include "gtpv2c_set_ie.h"
#include "ue.h"
#include "interface.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER1

struct in_addr s11_mme_ip;
struct sockaddr_in s11_mme_sockaddr;

struct in_addr s11_sgw_ip;
in_port_t s11_port;
struct sockaddr_in s11_sgw_sockaddr;
uint8_t s11_rx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t s11_tx_buf[MAX_GTPV2C_UDP_LEN];

struct in_addr s5s8_sgwc_ip;
in_port_t s5s8_sgwc_port;
struct sockaddr_in s5s8_sgwc_sockaddr;

struct in_addr s5s8_pgwc_ip;
in_port_t s5s8_pgwc_port;
struct sockaddr_in s5s8_pgwc_sockaddr;
uint8_t s5s8_rx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t s5s8_tx_buf[MAX_GTPV2C_UDP_LEN];

struct in_addr s1u_sgw_ip;
struct in_addr s5s8_sgwu_ip;
struct in_addr s5s8_pgwu_ip;

gtpv2c_ie *
get_first_ie(gtpv2c_header *gtpv2c_h)
{
	if (gtpv2c_h) {
		gtpv2c_ie *first_ie = IE_BEGIN(gtpv2c_h);
		if (NEXT_IE(first_ie) <= GTPV2C_IE_LIMIT(gtpv2c_h))
			return first_ie;
	}
	return NULL;
}


gtpv2c_ie *
get_next_ie(gtpv2c_ie *gtpv2c_ie_ptr, gtpv2c_ie *limit)
{
	if (gtpv2c_ie_ptr) {
		gtpv2c_ie *first_ie = NEXT_IE(gtpv2c_ie_ptr);
		if (NEXT_IE(first_ie) <= limit)
			return first_ie;
	}
	return NULL;
}


void
set_gtpv2c_header(gtpv2c_header *gtpv2c_tx, uint8_t type,
	uint8_t has_teid, uint32_t seq)
{
	gtpv2c_tx->gtpc.version = GTP_VERSION_GTPV2C;
	gtpv2c_tx->gtpc.piggyback = 0;
	gtpv2c_tx->gtpc.type = type;
	gtpv2c_tx->gtpc.teidFlg = has_teid;
	gtpv2c_tx->gtpc.spare = 0;

	gtpv2c_tx->teid_u.has_teid.seq = seq;

	gtpv2c_tx->gtpc.length = has_teid ?
			htons(sizeof(gtpv2c_tx->teid_u.has_teid)) :
			htons(sizeof(gtpv2c_tx->teid_u.no_teid));
}


void
set_gtpv2c_teid_header(gtpv2c_header *gtpv2c_tx, uint8_t type,
	uint32_t teid, uint32_t seq)
{
	set_gtpv2c_header(gtpv2c_tx, type, 1, seq);
	gtpv2c_tx->teid_u.has_teid.teid = teid;
}


void
set_gtpv2c_echo(gtpv2c_header *gtpv2c_tx, uint8_t type, uint32_t seq)
{
	set_gtpv2c_header(gtpv2c_tx, type, 0, seq);
	set_recovery_ie(gtpv2c_tx, IE_INSTANCE_ZERO);
}

