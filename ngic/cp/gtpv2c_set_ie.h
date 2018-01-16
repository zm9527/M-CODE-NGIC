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

#ifndef GTPV2C_SET_IE_H
#define GTPV2C_SET_IE_H

/**
 * @file
 *
 * Helper functions to add Information Elements and their specific data to
 * a message buffer containing a GTP header.
 */

#include "gtpv2c.h"
#include "gtpv2c_ie.h"
#include "ue.h"

#define MAX_GTPV2C_LENGTH (MAX_GTPV2C_UDP_LEN-sizeof(struct gtpc_t))

/**
 * Copies existing information element to gtp message
 * within transmission buffer with the GTP header '*header'
 *
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param src_ie
 *   Existing Information element to copy into message
 * @return
 *   size of information element copied into message
 */
uint16_t
set_ie_copy(gtpv2c_header *header, gtpv2c_ie *src_ie);


/**
 * Creates and populates cause information element with accepted value
 * within transmission buffer with the GTP header '*header'
 *
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   size of information element created in message
 */
uint16_t
set_cause_accepted_ie(gtpv2c_header *header,
	enum ie_instance instance);

/**
 * Creates and populates allocation/retention priority information element
 * with the GTP header '*header'
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param bearer
 *   eps bearer data structure that contains priority data
 * @return
 *   size of information element created in message
 */
uint16_t
set_ar_priority_ie(gtpv2c_header *header, enum ie_instance instance,
		eps_bearer *bearer);


/**
 * Creates and populates F-TEID information element with ipv4 value
 * within transmission buffer with the GTP header '*header'
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param interface
 *   value indicating interface as defined by 3gpp 29.274 clause 8.22
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ipv4
 *   ipv4 address of interface
 * @param teid
 *   Tunnel End-point IDentifier of interface
 * @return
 *   size of information element created in message
 */
uint16_t
set_ipv4_fteid_ie(gtpv2c_header *header,
	enum gtpv2c_interfaces interface, enum ie_instance instance,
	struct in_addr ipv4, uint32_t teid);

/**
 * Creates & populates 'PDN Address Allocation' information element with ipv4
 * address of User Equipment
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ipv4
 *   ipv4 address of user equipment
 * @return
 *   size of information element created in message
 */
uint16_t
set_ipv4_paa_ie(gtpv2c_header *header, enum ie_instance instance,
	struct in_addr ipv4);

/**
 * Returns ipv4 UE address from  'PDN Address Allocation' information element
 * address of User Equipment
 *
 * @param ie
 *   gtpv2c_ie information element
 * @return
 *   ipv4 address of user equipment
 */
struct in_addr
get_ipv4_paa_ipv4(gtpv2c_ie *ie);

/**
 * Creates & populates 'Access Point Name' restriction information element
 * according to 3gpp 29.274 clause 8.57
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param apn_restriction
 *   value indicating the restriction according to 3gpp 29.274 table 8.57-1
 * @return
 *   size of information element created in message
 */
uint16_t
set_apn_restriction_ie(gtpv2c_header *header,
	enum ie_instance instance, uint8_t apn_restriction);

/**
 * Creates & populates 'Eps Bearer Identifier' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ebi
 *   value indicating the EBI according to 3gpp 29.274 clause 8.8
 * @return
 *   size of information element created in message
 */
uint16_t
set_ebi_ie(gtpv2c_header *header, enum ie_instance instance,
	uint8_t ebi);

/**
 * Creates & populates 'Procedure Transaction ' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param pti
 *   Procedure transaction value from 3gpp 29.274 clause 8.35
 * @return
 *   size of information element created in message
 */
uint16_t
set_pti_ie(gtpv2c_header *header, enum ie_instance instance,
	uint8_t pti);

/**
 * Creates & populates 'Bearer Quality of Service' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param bearer
 *   eps bearer data structure that contains qos data
 * @return
 *   size of information element created in message
 */
uint16_t
set_bearer_qos_ie(gtpv2c_header *header, enum ie_instance instance,
	eps_bearer *bearer);

/**
 * Creates & populates 'Traffic Flow Template' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param bearer
 *   eps bearer data structure that contains tft data
 * @return
 *   size of information element created in message
 */
uint16_t
set_bearer_tft_ie(gtpv2c_header *header, enum ie_instance instance,
	eps_bearer *bearer);

/**
 * Creates & populates 'recovery/restart counter' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   size of information element created in message
 */
uint16_t
set_recovery_ie(gtpv2c_header *header, enum ie_instance instance);


/* Group Information Element Setter & Builder Functions */

/**
 * Modifies group_ie information element's length field, adding the length
 * from grouped_ie_length
 *
 * @param group_ie
 *   group information element (such as bearer context)
 * @param grouped_ie_length
 *   grouped information element contained within 'group_ie' information
 *   element
 * @return
 *   size of information element created in message
 */
void
add_grouped_ie_length(gtpv2c_ie *group_ie, uint16_t grouped_ie_length);

/**
 * Creates & populates bearer context group information element within
 * transmission buffer at *header
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   bearer context created in 'header'
 */
gtpv2c_ie *
create_bearer_context_ie(gtpv2c_header *header,
	enum ie_instance instance);

#endif /* GTPV2C_SET_IE_H */
