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

#ifndef _GTPU_H_
#define _GTPU_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of GTPU header parsing and constructor.
 */
#include "util.h"

#define GTPU_VERSION		0x01
#define GTP_PROTOCOL_TYPE_GTP	0x01
#ifdef GTPU_HDR_SEQNB
#define GTPU_SEQPRESENT	0x01
/* GTPU_STATIC_SEQNB 0x00001122::On Wire 22 11 00 00
 * Last two SEQNB bytes should be 00 00
 * */
#define GTPU_STATIC_SEQNB 0x00000000
#endif	/* GTPU_HDR_SEQNB */

#define GTP_GPDU		0xff

/**
 * Gpdu header structure .
 */

#pragma pack(1)
struct gtpu_hdr {
	uint8_t pdn:1;		/**< n-pdn number present ? */
	uint8_t seq:1;		/**< sequence no. */
	uint8_t ex:1;		/**< next extersion hdr present? */
	uint8_t spare:1;	/**< reserved */
	uint8_t pt:1;		/**< protocol type */
	uint8_t version:3;	/**< version */
	uint8_t msgtype;	/**< message type */
	uint16_t msglen;	/**< message length */
	uint32_t teid;		/**< tunnel endpoint id */
#ifdef GTPU_HDR_SEQNB
	uint32_t seqnb;		/**< sequence number */
#endif	/* GTPU_HDR_SEQNB */
};
#pragma pack()

/**
 * Function to return pointer to gtpu headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	pointer to udp headers
 */
static inline struct gtpu_hdr *get_mtogtpu(struct rte_mbuf *m)
{
	return (struct gtpu_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) +
			ETH_HDR_SIZE + IPv4_HDR_SIZE + UDP_HDR_SIZE);
}

/**
 * Function for decapsulation of gtpu headers.
 *
 * @param m
 *	mbuf pointer
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int decap_gtpu_hdr(struct rte_mbuf *m);

/**
 * Function for encapsulation of gtpu headers.
 *
 * @param m
 *	mbuf pointer
 * @param teid
 *	tunnel endpoint id to be set in gtpu header.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int encap_gtpu_hdr(struct rte_mbuf *m, uint32_t teid);

/**
 * Function to get inner dst ip of tunneled packet.
 *
 * @param m
 *	mbuf of the incoming packet.
 *
 * @return
 *	 inner dst ip
 */
uint32_t gtpu_inner_src_ip(struct rte_mbuf *m);

#endif	/* _GTPU_H_ */
