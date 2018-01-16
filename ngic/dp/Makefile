# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

MAKEFLAGS += -j

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk
include $(NG_CORE)/config/ng-core_cfg.mk

#DIRS-y += pipeline
# binary name
APP = ngic_dataplane
# all source are stored in SRCS-y
SRCS-y := main.c\
	pkt_handler.c\
	cdr.c\
	master_cdr.c\
	session_cdr.c\
	config.c\
	init.c\
	dataplane.c\
	gtpu.c\
	ether.c\
	ipv4.c\
	util.c\
	acl.c\
	meter.c\
	adc_table.c\
	pcc_table.c\
	sess_table.c\
	commands.c\
	stats.c\
	ddn_utils.c\
	pipeline/epc_load_balance.o\
	pipeline/epc_packet_framework.o\
	pipeline/epc_tx.o\
	pipeline/epc_rx.o\
	pipeline/epc_worker.o\
	pipeline/epc_arp_icmp.o\
	pipeline/epc_spns_dns.o\
	$(SRCDIR)/../interface/interface.o\
	$(SRCDIR)/../cp_dp_api/vepc_cp_dp_api.o\
	$(SRCDIR)/../test/simu_cp/nsb/nsb_test_util.o\
	$(SRCDIR)/../test/simu_cp/simu_cp.o\
	$(SRCDIR)/../interface/ipc/dp_ipc_api.o\
	$(SRCDIR)/../interface/udp/vepc_udp.o\

CFLAGS += -I$(SRCDIR)/
CFLAGS += -I$(SRCDIR)/../interface
CFLAGS += -I$(SRCDIR)/../interface/ipc
CFLAGS += -I$(SRCDIR)/../interface/udp
CFLAGS += -I$(SRCDIR)/../interface/sdn
CFLAGS += -I$(SRCDIR)/../interface/zmq
CFLAGS += -I$(SRCDIR)/../cp_dp_api
CFLAGS += -I$(SRCDIR)/../test/simu_cp
CFLAGS += -I$(SRCDIR)/../test/simu_cp/nsb
CFLAGS += -I$(SRCDIR)/pipeline
CFLAGS += -I$(SRCDIR)/../cp
CFLAGS += -I$(SRCDIR)/../lib/libsponsdn

CFLAGS += -Wno-psabi # suppress "The ABI for passing parameters with 64-byte alignment has changed in GCC 4.6"


CFLAGS += -DLDB_DP	# should be included for dataplane.

ifneq (,$(findstring SDN_ODL_BUILD, $(CFLAGS)))
	SRCS-y += $(SRCDIR)/../interface/zmq/zmqsub.o
	SRCS-y += $(SRCDIR)/../interface/zmq/zmqpub.o
	LDFLAGS += -L/usr/local/lib -lzmq
endif
CFLAGS += -O3
#CFLAGS += -g -O0

# Un-comment below line to read fake cp config.
#CFLAGS += -DSIMU_CP

# ASR- Un-comment below line to enable GTPU HEADER Sequence Number option.
#CFLAGS += -DGTPU_HDR_SEQNB

# ASR- Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_PIPELINE_STAGE

# Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_ADC_STAGE

# Un-comment below line to enable PCC, ADC, CDR, FILTERING, METERING pipeline stages.
#CFLAGS += -DINCLUDE_MTR_STAGE

# Un-comment below line to enable NIC and pipeline stats.
#CFLAGS += -DSTATS

# Un-comment below line to get stats from command line (for test harness)
#CFLAGS += -DCMDLINE_STATS

# Un-comment below line to clear STATS after reading.
#CFLAGS += -DSTATS_CLR

# Un-comment below line to enable pipeline out stats, STATS flag should be enabled.
#CFLAGS += -DOSTATS

# Un-comment below line to enable DNS stats.
CFLAGS += -DDNS_STATS

# Un-comment below line to enable core RX and core TX. All
# processing stages will be skipped.
#CFLAGS += -DRX_TX

# Un-comment below line to skip RX Meta access
#CFLAGS += -DSKIP_RX_META

# Un-comment below line to enable core RX, core LB and core TX. All
# processing stages will be skipped.
#CFLAGS += -DRX_LB_TX

# Un-comment below line to enable SDF Metering
#CFLAGS += -DSDF_MTR

# Un-comment below line to enable APN Metering
#CFLAGS += -DAPN_MTR

# Un-comment below line to enable ADC upfront.
CFLAGS += -DADC_UPFRONT

# Un-comment below line to enable hyperscan DPI.
CFLAGS += -DHYPERSCAN_DPI

# Un-comment below line to enable Rating group CDRs.
#CFLAGS += -DRATING_GRP_CDR

# Un-comment below line to skip LB rte_hash_crc_4byte
# and enable LB based on UE ip last byte.
#CFLAGS += -DSKIP_LB_HASH_CRC

# set SGI port action handler equal to S1U action handler.
#CFLAGS += -DSKIP_LB_GTPU_AH

# Un-comment below line to read acl rules from file.
#CFLAGS += -DACL_READ_CFG

# Un-comment below line if you have 16 x 1GB hugepages.
#CFLAGS += -DHUGE_PAGE_16GB

# Un-comment below line to print ADC, PCC, METER and SDF rule entry
# passed from FPC-SDN in add entry operation.
# Note : This flag works with Log level 'DEBUG'
#CFLAGS += -DPRINT_NEW_RULE_ENTRY

# Un-comment below line to configure DP Tables from DP app.
CFLAGS += -DDP_TABLE_CONFIG

CFLAGS += -DSTATIC_ARP

#un-comment below line to generate pcap on east-west interfaces
#CFLAGS += -DPCAP_GEN

CFLAGS += -Werror
CFLAGS += -Wunused-variable
CFLAGS_config.o := -D_GNU_SOURCE

# workaround for a gcc bug with noreturn attribute
#  http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_dataplane.o += -Wno-return-type
endif

LDFLAGS += -L$(RTE_SRCDIR)/../lib/libsponsdn/libsponsdn/x86_64-native-linuxapp-gcc/ -lsponsdn

LDFLAGS += -L$(HYPERSCANDIR)/build/lib

LDFLAGS += -lexpressionutil -lhs -lhs_runtime -lstdc++ -lm -lcrypto

LDFLAGS += -lrte_pmd_af_packet

LDFLAGS += -lpcap

include $(RTE_SDK)/mk/rte.extapp.mk
