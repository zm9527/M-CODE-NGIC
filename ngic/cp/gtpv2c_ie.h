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

#ifndef IE_H
#define IE_H

/**
 * @file
 *
 * Information Element definitions and helper macros.
 *
 * Information Elements defined according to 3GPP TS 29.274, clause 8. IEs are
 * defined with bit-field structures for the x86_64 architecture and are not
 * cross compatible. Preprocessor definitions and enum typed values are defined
 * according to their respective 3GPP definitions.
 *
 */

#include <inttypes.h>
#include <stdlib.h>
#include <netinet/in.h>

#define IPV4_IE_LENGTH                                        (4)
#define IPV6_IE_LENGTH                                        (16)


/* Information Element type values according to 3GPP TS 29.274 Table 8.1-1 */
#define IE_RESERVED                                           (0)
#define IE_IMSI                                               (1)
#define IE_CAUSE                                              (2)
#define IE_RECOVERY                                           (3)
#define IE_APN                                                (71)
#define IE_AMBR                                               (72)
#define IE_EBI                                                (73)
#define IE_IP_ADDRESS                                         (74)
#define IE_MEI                                                (75)
#define IE_MSISDN                                             (76)
#define IE_INDICATION                                         (77)
#define IE_PCO                                                (78)
#define IE_PAA                                                (79)
#define IE_BEARER_QOS                                         (80)
#define IE_FLOW_QOS                                           (81)
#define IE_RAT_TYPE                                           (82)
#define IE_SERVING_NETWORK                                    (83)
#define IE_BEARER_TFT                                         (84)
#define IE_TAD                                                (85)
#define IE_ULI                                                (86)
#define IE_FTEID                                              (87)
#define IE_TMSI                                               (88)
#define IE_GLOBAL_CN_ID                                       (89)
#define IE_S103PDF                                            (90)
#define IE_S1UDF                                              (91)
#define IE_DELAY_VALUE                                        (92)
#define IE_BEARER_CONTEXT                                     (93)
#define IE_CHARGING_ID                                        (94)
#define IE_CHARGING_CHARACTERISTICS                           (95)
#define IE_TRACE_INFORMATION                                  (96)
#define IE_BEARER_FLAGS                                       (97)
#define IE_PDN_TYPE                                           (99)
#define IE_PROCEDURE_TRANSACTION_ID                           (100)
#define IE_DRX_PARAMETER                                      (101)
#define IE_UE_NETWORK_CAPABILITY                              (102)
#define IE_PDN_CONNECTION                                     (109)
#define IE_PDU_NUMBERS                                        (110)
#define IE_PTMSI                                              (111)
#define IE_PTMSI_SIGNATURE                                    (112)
#define IE_HIP_COUNTER                                        (113)
#define IE_UE_TIME_ZONE                                       (114)
#define IE_TRACE_REFERENCE                                    (115)
#define IE_COMPLETE_REQUEST_MESSAGE                           (116)
#define IE_GUTI                                               (117)
#define IE_F_CONTAINER                                        (118)
#define IE_F_CAUSE                                            (119)
#define IE_SELECTED_PLMN_ID                                   (120)
#define IE_TARGET_IDENTIFICATION                              (121)
#define IE_PACKET_FLOW_ID                                     (123)
#define IE_RAB_CONTEXT                                        (124)
#define IE_SOURCE_RNC_PDCP_CONTEXT_INFO                       (125)
#define IE_UDP_SOURCE_PORT_NUMBER                             (126)
#define IE_APN_RESTRICTION                                    (127)
#define IE_SELECTION_MODE                                     (128)
#define IE_SOURCE_IDENTIFICATION                              (129)
#define IE_CHANGE_REPORTING_ACTION                            (131)
#define IE_FQ_CSID                                            (132)
#define IE_CHANNEL_NEEDED                                     (133)
#define IE_EMLPP_PRIORITY                                     (134)
#define IE_NODE_TYPE                                          (135)
#define IE_FQDN                                               (136)
#define IE_TI                                                 (137)
#define IE_MBMS_SESSION_DURATION                              (138)
#define IE_MBMS_SERIVCE_AREA                                  (139)
#define IE_MBMS_SESSION_IDENTIFIER                            (140)
#define IE_MBMS_FLOW_IDENTIFIER                               (141)
#define IE_MBMS_IP_MULTICAST_DISTRIBUTION                     (142)
#define IE_MBMS_IP_DISTRIBUTION_ACK                           (143)
#define IE_RFSP_INDEX                                         (144)
#define IE_UCI                                                (145)
#define IE_CSG_INFORMATION_REPORTING_ACTION                   (146)
#define IE_CSG_ID                                             (147)
#define IE_CSG_MEMBERSHIP_INDICATION                          (148)
#define IE_SERVICE_INDICATOR                                  (149)
#define IE_ALLOCATION_RETENTION_PRIORITY                      (155)
#define IE_PRIVATE_EXTENSION                                  (255)

/**
 * Partial list of cause values from 3GPP TS 29.274, Table 8.4-1 containing
 * values currently used by Control Plane.
 */
enum cause_value {
	GTPV2C_CAUSE_REQUEST_ACCEPTED = 16,
	GTPV2C_CAUSE_REQUEST_ACCEPTED_PARTIALLY = 17,
	GTPV2C_CAUSE_NEW_PDN_TYPE_NETWORK_PREFERENCE = 18,
	GTPV2C_CAUSE_NEW_PDN_TYPE_SINGLE_ADDR_BEARER = 19,
	GTPV2C_CAUSE_CONTEXT_NOT_FOUND = 64,
	GTPV2C_CAUSE_INVALID_MESSAGE_FORMAT = 65,
	GTPV2C_CAUSE_INVALID_LENGTH = 67,
	GTPV2C_CAUSE_SERVICE_NOT_SUPPORTED = 68,
	GTPV2C_CAUSE_MANDATORY_IE_INCORRECT = 69,
	GTPV2C_CAUSE_MANDATORY_IE_MISSING = 70,
	GTPV2C_CAUSE_SYSTEM_FAILURE = 72,
	GTPV2C_CAUSE_NO_RESOURCES_AVAILABLE = 73,
	GTPV2C_CAUSE_MISSING_UNKNOWN_APN = 78,
	GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED = 83,
	GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED = 84,
	GTPV2C_CAUSE_REQUEST_REJECTED = 94,
	GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING = 100,
	GTPV2C_CAUSE_CONDITIONAL_IE_MISSING = 103,
};

#define PDN_IP_TYPE_IPV4                                      (1)
#define PDN_IP_TYPE_IPV6                                      (2)
#define PDN_IP_TYPE_IPV4V6                                    (3)

/**
 * Partial list of acceptable instance values to use for the instance field
 * with the gtpv2c_ie structure.
 */
enum ie_instance {
	IE_INSTANCE_ZERO = 0,
	IE_INSTANCE_ONE = 1,
	IE_INSTANCE_TWO = 2,
	IE_INSTANCE_THREE = 3,
	IE_INSTANCE_FOUR = 4,
	IE_INSTANCE_FIVE = 5,
	IE_INSTANCE_SIX = 6
};

#pragma pack(1)

/**
 * Information Element structure as defined by 3GPP TS 29.274, clause 8.2.1, as
 * shown by Figure 8.2-1. IE specific data or content of grouped IE follows
 * directly in memory from this structure. IE specific data is defined by
 * structures ending with the _ie postfix in this file.
 *
 * IE Type extension is not currently supported.
 */
typedef struct gtpv2c_ie_t {
	uint8_t type;
	uint16_t length;
	uint8_t instance :4;
	uint8_t spare :4;
} gtpv2c_ie;

/**
 * IE specific data for Cause as defined by 3GPP TS 29.274, clause 8.4 for the
 * IE type value 2.
 */
typedef struct cause_ie_t {
	struct cause_ie_hdr_t {
		uint8_t cause_value;
		uint8_t cause_source :1;
		uint8_t bearer_context_error :1;
		uint8_t pdn_connection_error :1;
		uint8_t spare_0 :5;
	} cause_ie_hdr;
	/* if gtpv2c_ie->length=2, the following fields are not active,
	 *  otherwise gtpv2c_ie->length=6
	 */
	uint8_t offending_ie_type;
	uint16_t offending_ie_length;
	uint8_t instance :4;
	uint8_t spare_1 :4;
} cause_ie;

/**
 * IE specific data for Aggregate Maximum Bit Rate (AMBR) as defined by
 * 3GPP TS 29.274, clause 8.7 for the IE type value 72.
 */
typedef struct ambr_ie_t {
	uint32_t ambr_uplink;
	uint32_t ambr_downlink;
} ambr_ie;

/**
 * IE specific data for EPS Bearer ID (EBI) as defined by
 * 3GPP TS 29.274, clause 8.8 for the IE type value 73.
 */
typedef struct eps_bearer_id_ie_t {
	uint8_t ebi :4;
	uint8_t spare :4;
} eps_bearer_id_ie;

/**
 * IE specific data for Indication as defined by
 * 3GPP TS 29.274, clause 8.12 for the IE type value 77.
 */
typedef struct indication_ie_t {
	/* first octet */
	uint8_t sgwci :1; /* SGW Change Indication                           */
	uint8_t israi :1; /* Idle mode Signal Reduction Activation Indication*/
	uint8_t isrsi :1; /* Idle mode Signal Reduction Supported Indication */
	uint8_t oi :1;    /* Operation Indication                            */
	uint8_t dfi :1;   /* Direct Forwarding Indication                    */
	uint8_t hi :1;    /* Handover Indication                             */
	uint8_t dtf :1;   /* Direct Tunnel Flag                              */
	uint8_t daf :1;   /* Dual Address Bearer Flag                        */
	/* second octet */
	uint8_t msv :1;   /* MS Validated                                    */
	uint8_t si :1;    /* Scope Indication                                */
	uint8_t pt :1;    /* Protocol Type                                   */
	uint8_t ps :1;    /* Piggybacking Supported                          */
	uint8_t crsi :1;  /* Change Reporting Support Indication             */
	uint8_t cfsi :1;  /* Change F-TEID Support Indication                */
	uint8_t uimsi :1; /* Unauthenticated IMSI                            */
	uint8_t sqci :1;  /* Subscribed QoS Change Indication                */
	/* third octet */
	uint8_t ccrsi :1; /* CSG Change Reporting Support Indication         */
	uint8_t israu :1; /* ISR is activated for the UE                     */
	uint8_t mbmdt :1; /* Management Based MDT allowed flag               */
	uint8_t s4af :1;  /* Static IPv4 Address Flag                        */
	uint8_t s6af :1;  /* Static IPv6 Address Flag                        */
	uint8_t srni :1;  /* SGW Restoration Needed Indication               */
	uint8_t pbic :1;  /* Propagate BBAI Information Change               */
	uint8_t retloc :1;/* Retrieve Location Indication Flag               */
	/* fourth octet */
	uint8_t cpsr :1;  /* CS to PS SRVCC indication                       */
	uint8_t clii :1;  /* Change of Location Information Indication       */
	uint8_t spare :6;
} indication_ie;

/**
 * IE specific data for PDN Address Allocation (PAA) as defined by
 * 3GPP TS 29.274, clause 8.14 for the IE type value 79.
 */
typedef struct paa_ie_t {
	struct paa_ie_hdr_t {
		uint8_t pdn_type :3;
		uint8_t spare :5;
	} paa_ie_hdr;
	union ip_type_union_t {
		struct in_addr ipv4;
		struct ipv6_t {
			uint8_t prefix_length;
			struct in6_addr ipv6;
		} ipv6;
		struct paa_ipv4v6_t {
			uint8_t prefix_length;
			struct in6_addr ipv6;
			struct in_addr ipv4;
		} paa_ipv4v6;
	} ip_type_union;
} paa_ie;

/**
 * IE specific data segment for Quality of Service (QoS).
 *
 * Definition used by bearer_qos_ie and flow_qos_ie.
 */
typedef struct qos_segment_t {
	/** QoS class identifier - defined by 3GPP TS 23.203 */
	uint8_t qci;

	/** Uplink Maximum Bit Rate in kilobits (1000bps) - for non-GBR
	 * Bearers this field to be set to zero*/
	uint8_t ul_mbr[5];
	/** Downlink Maximum Bit Rate in kilobits (1000bps) - for non-GBR
	 * Bearers this field to be set to zero*/
	uint8_t dl_mbr[5];
	/** Uplink Guaranteed Bit Rate in kilobits (1000bps) - for non-GBR
	 * Bearers this field to be set to zero*/
	uint8_t ul_gbr[5];
	/** Downlink Guaranteed Bit Rate in kilobits (1000bps) - for non-GBR
	 * Bearers this field to be set to zero*/
	uint8_t dl_gbr[5];
} qos_segment;

/**
 * IE specific data for Bearer Quality of Service (QoS) as defined by
 * 3GPP TS 29.274, clause 8.15 for the IE type value 80.
 */
typedef struct ar_priority_ie_t {
	uint8_t preemption_vulnerability :1;
	uint8_t spare1 :1;
	uint8_t priority_level :4;
	uint8_t preemption_capability :1;
	uint8_t spare2 :1;
} ar_priority_ie;

/**
 * IE specific data for Bearer Quality of Service (QoS) as defined by
 * 3GPP TS 29.274, clause 8.15 for the IE type value 80.
 */
typedef struct bearer_qos_ie_t {
	/* First Byte: Allocation/Retention Priority (ARP) */
	ar_priority_ie arp;
	qos_segment qos;
} bearer_qos_ie;

#define BEARER_QOS_IE_PREMPTION_DISABLED (1)
#define BEARER_QOS_IE_PREMPTION_ENABLED  (0)

/* IEI = IE_FLOW_QOS = 81 */
/**
 * IE specific data for Flow Quality of Service (QoS) as defined by
 * 3GPP TS 29.274, clause 8.16 for the IE type value 81.
 */
typedef struct flow_qos_ie_t {
	qos_segment qos;
} flow_qos_ie;

/**
 * IE specific data for Bearer Traffic Flow Template (TFT) as defined by
 * 3GPP TS 24.008, clause 10.5.6.12 for the IE type value 84.
 */
typedef struct bearer_tft_ie_t {
	/* For the TFT_OP_DELETE_EXISTING operation and TFT_OP_NO_OP,
	 * num_pkt_filters shall be 0'' */
	uint8_t num_pkt_filters :4;
	uint8_t parameter_list :1; /* Refereed to e-bit in spec */
	uint8_t tft_op_code :3;
} bearer_tft_ie;

/* for use in bearer_tft.tft_op_code */
#define TFT_OP_CREATE_NEW                (1)
#define TFT_OP_DELETE_EXISTING           (2)
#define TFT_OP_ADD_FILTER_EXISTING       (3)
#define TFT_OP_REPLACE_FILTER_EXISTING   (4)
#define TFT_OP_DELETE_FILTER_EXISTING    (5)
#define TFT_OP_NO_OP                     (6)

/**
 * Packet filter list when the TFT operation is TFT_OP_DELETE_EXISTING
 * From Figure 10.5.144a/3GPP TS 24.008
 */
typedef struct delete_pkt_filter_t {
	uint8_t pkt_filter_id :4;
	uint8_t spare :4;
} delete_pkt_filter;

/**
 * Packet filter component from Table 10.5.162/3GPP TS 24.008
 */
typedef struct packet_filter_component_t {
	uint8_t type;
	union type_union_u {
		struct ipv4_t {
			struct in_addr ipv4;
			struct in_addr mask;
			uint8_t next_component;
		} ipv4;
		struct port_t {
			uint16_t port;
			uint8_t next_component;
		} port;
		struct port_range_t {
			uint16_t port_low;
			uint16_t port_high;
			uint8_t next_component;
		} port_range;
		struct proto_t {
			uint8_t proto;
			uint8_t next_component;
		} proto;
	} type_union;
} packet_filter_component;

/**
 * Packet filter list from Figure 10.5.144b/3GPP TS 24.008 for use when TFT
 * operation is TFT_OP_CREATE_NEW
 *
 * For future use with operations TFT_OP_ADD_FILTER_EXISTING and
 * TFT_OP_REPLACE_FILTER_EXISTING - not currently supported by Control Plane
 */
typedef struct create_pkt_filter_t {
	uint8_t pkt_filter_id :4;
	uint8_t direction :2;
	uint8_t spare :2;
	uint8_t precedence;
	uint8_t pkt_filter_length;
} create_pkt_filter;

/* for use in create_pkt_filter.direction */
#define TFT_DIRECTION_DOWNLINK_ONLY      (1)
#define TFT_DIRECTION_UPLINK_ONLY        (2)
#define TFT_DIRECTION_BIDIRECTIONAL      (3)

/* Packet filter component type identifiers. Following create_pkt_filter,
 * num_pkt_filters packet filter contents consist of a pair consisting of
 * (component type id, value) where value length is dependent upon id
 *
 * Note: The term local refers to the MS (UE)
 * and the term remote refers to an external network entity */
#define IPV4_REMOTE_ADDRESS         0x10             /* 0b00010000 */
#define IPV4_LOCAL_ADDRESS          0x11             /* 0b00010001 */
#define PROTOCOL_ID_NEXT_HEADER     0x30             /* 0b00110000 */
#define SINGLE_LOCAL_PORT           0x40             /* 0b01000000 */
#define LOCAL_PORT_RANGE            0x41             /* 0b01000001 */
#define SINGLE_REMOTE_PORT          0x50             /* 0b01010000 */
#define REMOTE_PORT_RANGE           0x51             /* 0b01010001 */
/* Unsupported packet filter components
 * #define IPV6_REMOTE_ADDRESS        0b00100000
 * #define IPV6_REMOTE_ADDRESS_PREFIX 0b00100001
 * #define IPV6_LOCAL_ADDRESS_PREFIX  0b00100011
 * #define SECURITY_PARAMETER_INDEX   0b01100000
 * #define TRAFFIC_CLASS_TOS          0b01110000
 * #define FLOW_LABEL_TYPE            0b10000000
 */

static const uint8_t PACKET_FILTER_COMPONENT_SIZE[REMOTE_PORT_RANGE + 1] = {
	[IPV4_REMOTE_ADDRESS] = sizeof(struct ipv4_t),
	[IPV4_LOCAL_ADDRESS] = sizeof(struct ipv4_t),
	[PROTOCOL_ID_NEXT_HEADER] = sizeof(struct proto_t),
	[SINGLE_LOCAL_PORT] = sizeof(struct port_t),
	[LOCAL_PORT_RANGE] = sizeof(struct port_range_t),
	[SINGLE_REMOTE_PORT] = sizeof(struct port_t),
	[REMOTE_PORT_RANGE] = sizeof(struct port_range_t),
};

#define AUTHORIZATION_TOKEN              (1)
#define FLOW_IDENTIFIER                  (2)
#define PACKET_FILTER_IDENTIFIER         (3)

/**
 * IE specific data for Traffic Aggregation Description (TAD) for IE type 85.
 *
 * TFT is reused for TAD, where use of parameters such as packet filter
 * identifiers may differ. See NOTE 3 in 3GPP TS 24.008, clause 10.5.6.12, as
 * well as 3GPP TS 24.301.
 */
typedef struct bearer_tft_ie_t traffic_aggregation_description;


/**
 * IE specific data for Fully qualified Tunnel Endpoint ID (F-TEID) as defined
 * by 3GPP TS 29.274, clause 8.22 for the IE type value 87.
 */
typedef struct fteid_ie_t {
	struct fteid_ie_hdr_t {
		uint8_t interface_type :6;
		uint8_t v6 :1;
		uint8_t v4 :1;
		uint32_t teid_or_gre;
	} fteid_ie_hdr;
	union ip_t {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		struct ipv4v6_t {
			struct in_addr ipv4;
			struct in6_addr ipv6;
		} ipv4v6;
	} ip_u;
} fteid_ie;

/**
 * IE specific data for Delay Value as definedby 3GPP TS 29.274, clause 8.27
 * for the IE type value 92.
 */
typedef struct delay_ie_t {
	uint8_t delay_value;
} delay_ie;

/**
 * IE specific data for Charging Characteristics as defined by
 * 3GPP TS 29.274, clause 8.30 for the IE type value 95.
 *
 * Charging characteristics information element is defined in 3GPP TS 32.251
 *
 * For the encoding of this information element see 3GPP TS 32.298
 */
typedef struct charging_characteristics_ie_t {
	uint8_t b0 :1;
	uint8_t b1 :1;
	uint8_t b2 :1;
	uint8_t b3 :1;
	uint8_t b4 :1;
	uint8_t b5 :1;
	uint8_t b6 :1;
	uint8_t b7 :1;
	uint8_t b8 :1;
	uint8_t b9 :1;
	uint8_t b10 :1;
	uint8_t b11 :1;
	uint8_t b12 :1;
	uint8_t b13 :1;
	uint8_t b14 :1;
	uint8_t b15 :1;
} charging_characteristics_ie;


/**
 * IE specific data for Packet Data Network (PDN) Type as defined by
 * 3GPP TS 29.274, clause 8.34 for the IE type value 99.
 */
typedef struct pdn_type_ie_t {
	uint8_t ipv4 :1;
	uint8_t ipv6 :1;
	uint8_t spare :6;
} pdn_type_ie;

#pragma pack()

#define IE_TYPE_PTR_FROM_GTPV2C_IE(ptr_type, gtpv2c_ie_ptr) \
		((ptr_type *)((gtpv2c_ie_ptr) + 1))

/* returns offset of APN encoding according to 3gpp 23.003 9.1*/
#define APN_PTR_FROM_APN_IE(gtpv2c_ie_ptr)    \
		IE_TYPE_PTR_FROM_GTPV2C_IE(char, gtpv2c_ie_ptr)

#endif /* IE_H */

