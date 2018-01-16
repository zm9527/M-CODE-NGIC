#! /bin/bash
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

source ../config/dp_config.cfg
source ../config/cdr.cfg

APP_PATH="./build"
APP="ngic_dataplane"
LOG_LEVEL=1
COREMASK="0xfe"

if [ "${SPGW_CFG}" == "01" ]; then

	ARGS="-c $COREMASK -n 4 --socket-mem $MEMORY,0	\
				--file-prefix dp	\
				-w $S1U_PORT -w $S5S8_SGWU_PORT --	\
				--s1u_ip $S1U_IP	\
				--s1u_mac $S1U_MAC	\
				--s5s8_sgwu_ip $S5S8_SGWU_IP	\
				--s5s8_sgwu_mac $S5S8_SGWU_MAC	\
				--num_workers $NUM_WORKER 	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--spgw_cfg $SPGW_CFG"

elif [ "${SPGW_CFG}" == "02" ]; then

	ARGS="-c $COREMASK -n 4 --socket-mem $MEMORY,0 	\
				--file-prefix dp	\
				-w $S5S8_PGWU_PORT -w $SGI_PORT	--	\
				--s5s8_pgwu_ip $S5S8_PGWU_IP	\
				--s5s8_pgwu_mac $S5S8_PGWU_MAC	\
				--sgi_ip $SGI_IP	\
				--sgi_mac $SGI_MAC	\
				--num_workers $NUM_WORKER	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--spgw_cfg $SPGW_CFG"

elif [ "${SPGW_CFG}" == "03" ]; then

	ARGS="-c $COREMASK -n 4 --socket-mem $MEMORY,0 	\
				--file-prefix dp	\
				-w $S1U_PORT -w $SGI_PORT --	\
				--s1u_ip $S1U_IP	\
				--s1u_mac $S1U_MAC	\
				--sgi_ip $SGI_IP	\
				--sgi_mac $SGI_MAC	\
				--num_workers $NUM_WORKER	\
				--log $LOG_LEVEL	\
				--numa $NUMA	\
				--spgw_cfg $SPGW_CFG"
fi


if [ -n "${S1U_GW_IP}" ]; then
	ARGS="$ARGS --s1u_gw_ip $S1U_GW_IP"
	if [ -n "${S1U_MASK}" ]; then
		ARGS="$ARGS --s1u_mask $S1U_MASK"
	fi
fi

if [ -n "${SGI_GW_IP}" ]; then
	ARGS="$ARGS --sgi_gw_ip $SGI_GW_IP"
	if [ -n "${SGI_MASK}" ]; then
		ARGS="$ARGS --sgi_mask $SGI_MASK"
	fi
fi

if [ -n "${CDR_PATH}" ]; then
	ARGS="$ARGS --cdr_path $CDR_PATH"
fi

if [ -n "${MASTER_CDR}" ]; then
	ARGS="$ARGS --master_cdr $MASTER_CDR"
fi

echo $ARGS | sed -e $'s/--/\\\n\\t--/g'

USAGE=$"Usage: run.sh [ debug | log ]
	debug:	executes $APP under gdb
	log:	executes $APP with logging enabled to date named file under
		$APP_PATH/logs. Requires Control-C to exit even if $APP exits"

if [ -z "$1" ]; then

	$APP_PATH/$APP $ARGS

elif [ "$1" == "log" ]; then

	if [ "$#" -eq "2" ]; then
		FILE="${FILE/.log/.$2.log}"
		echo "logging as $FILE"
	fi
	trap "killall $APP; exit" SIGINT
	stdbuf -oL -eL $APP_PATH/$APP $ARGS </dev/null &>$FILE & tail -f $FILE
	#valgrind --tool=memcheck --leak-check=full --log-file="sgwu_dp1.logs" $APP_PATH/$APP $ARGS

elif [ "$1" == "debug" ]; then

	GDB_EX="-ex 'set print pretty on' "
	echo $GDB_EX
	gdb $GDB_EX --args $APP_PATH/$APP $ARGS

else
	echo "$USAGE"
fi
