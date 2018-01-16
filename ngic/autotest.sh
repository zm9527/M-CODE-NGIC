#!/bin/bash
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

function trace_line() {
  caller
}

if [ $# -eq 1 ]; then
	if [ "$1" == "debug" ]; then
		trap trace_line debug
	fi
fi

#only variables you should have to change are here
NGIC_DIR=/home/jacooper/ng-core-review-head
NG40_DIR=/home/lte1/nfv-ran-sprint/test
NG40_HOST=ranc
#end user modifications

if [[ $(ps -A | grep ngic_c) ]] ; then
	pkill -f ngic_controlplane
fi
if [[ $(ps -A | grep ngic_d) ]] ; then
	pkill -f ngic_dataplane
fi

#get source directory and export initial values
source $NGIC_DIR/config/dp_config.cfg
source $NGIC_DIR/config/cp_config.cfg

#get (and make) log directory
THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
LOG_DIR=$THIS_DIR/logs
if [ ! -d "$LOG_DIR" ]; then
	mkdir $LOG_DIR
fi

DATE=$(date +"%Y-%m-%d_%H-%M")
if [ -d "$LOG_DIR/$DATE" ]; then
	if find $LOG_DIR/$DATE -mindepth 1 -print -quit | grep -q . ; then
		echo "$LOG_DIR/$DATE exists with contents. Delete contents [yY] {rm -rf $LOG_DIR/$DATE/*} or quit ^[yY]"
		read -sn1 input
		if [ $input == 'y' -o $input == 'Y' ] ; then
			echo "Deleting contents"
			rm -rf $LOG_DIR/$DATE/*
		else
			echo "exiting"
			exit
		fi
	fi
else
	mkdir $LOG_DIR/$DATE
fi
echo "Logging all test results in $LOG_DIR/$DATE"


check_parameters() {
	NUM_PARAMS=$1
	DESIRED_PARAMS=$2
	if [ $# -ne 2 ]; then echo "invalid arguments in ${FUNCNAME[0]}"; exit; fi
	if [ $DESIRED_PARAMS -ne $NUM_PARAMS ]; then echo "invalid arguments in ${FUNCNAME[1]}"; exit; fi
}

#verify source builds
verify_source_build() {
	echo "Verifing current executable - Please wait."
	pushd $NGIC_DIR > /dev/null
	source setenv.sh
	cd $NGIC_DIR
	make clean &> /dev/null  && make  &> $LOG_DIR/$DATE/build.log
	if [[ $? -ne 0 ]] ; then echo "Compilation Errors - Code base must compile prior to verification - check $LOG_DIR/$DATE/build.log" ; fi
	cd $NGIC_DIR/cp
	make clean &> /dev/null  && make -j &>> $LOG_DIR/$DATE/build.log
	if [[ $? -ne 0 ]] ; then echo "CP Compilation Errors - Code base must compile prior to verification - check $LOG_DIR/$DATE/build.log" ; fi
	cd $NGIC_DIR/dp
	make clean &> /dev/null  && make -j &>> $LOG_DIR/$DATE/build.log
	if [[ $? -ne 0 ]] ; then echo "DP Compilation Errors - Code base must compile prior to verification - check $LOG_DIR/$DATE/build.log" ; fi
	popd > /dev/null
}

#establish current working status of codebase. This way we can see exactly to which version of the code the current logs refer.
touch $LOG_DIR/$DATE/.$(git --git-dir $NGIC_DIR/.git rev-parse HEAD)
git --git-dir $NGIC_DIR/.git diff > $LOG_DIR/$DATE/run_state.patch

#establish system configuration
cp /proc/cmdline $LOG_DIR/$DATE/cmdline
cp /proc/cpuinfo $LOG_DIR/$DATE/cpuinfo

#begin tests

#if these are still running, kill with -9
if [[ $(ps -A | grep ngic_c) ]] ; then
	pkill -f ngic_controlplane
	sleep 0.5
	pkill -9 -f ngic_controlplane
fi
if [[ $(ps -A | grep ngic_d) ]] ; then
	pkill -f ngic_dataplane
	sleep 0.5
	pkill -9 -f ngic_dataplane
fi

#test 1: tc_userplane_mpps 1.4 Mpps @ 1K rate w/ 250K UEs, 1 worker core

run_testcase() {
	TESTCASE=$1
	TC_CFG=$2
	NUM_WORKERS=$3
	TC_LOG=$TC_CFG

	if  [ $# -ne 3 ]; then
		echo "run_testcase parameter error - insufficient parameters"
		return -1
	elif [ ! -f $THIS_DIR/$TC_CFG.cfg ] ; then
		echo "run_testcase parameter error: $THIS_DIR/$TC_CFG.cfg does not exist"
		return -1
	elif [ -f $LOG_DIR/$DATE/$TC_CFG.cfg ]; then
		TC_NUM=1
		while [ -e $LOG_DIR/$DATE/${TC_CFG}_$TC_NUM.cfg ]; do
			i=$((i+1))
		done
		TC_LOG+="_$TC_NUM"
	else
		ssh $NG40_HOST stat $NG40_DIR/$TESTCASE &> /dev/null
		if [[ $? -ne 0 ]] ; then
			echo "$NG40_HOST:$NG40_DIR/$TESTCASE does not exist"
			return -1
		fi
	fi

	echo "starting data plane... log @ $LOG_DIR/$DATE/$TC_LOG.dp.log"
	cd $NGIC_DIR/dp
	setsid stdbuf -oL -eL \
		$NGIC_DIR/dp/build/ngic_dataplane -c 0xfff800000 -n 4 --socket-mem 0,4096 \
		--file-prefix dp -w $PORT0 -w $PORT1 -- \
		--s1u_ip $S1U_IP --s1u_mac $S1U_MAC     \
		--sgi_ip $SGI_IP --sgi_mac $SGI_MAC     \
		--num_workers $NUM_WORKERS --log 1 \
		</dev/null &> $LOG_DIR/$DATE/$TC_LOG.dp.log &

	echo "starting control plane... log @ $LOG_DIR/$DATE/$TC_LOG.cp.log"
	cd $NGIC_DIR/cp
	setsid stdbuf -oL -eL \
		$NGIC_DIR/cp/build/ngic_controlplane -c 0x3 -n 4 --socket-mem 1024,0 --file-prefix cp --no-pci -- \
		-s $S11_SGW_IP   \
		-m $S11_MME_IP   \
		-w $S1U_SGW_IP   \
		-i $IP_POOL_IP   \
		-p $IP_POOL_MASK \
		-a $APN \
		</dev/null &> $LOG_DIR/$DATE/$TC_LOG.cp.log &

	echo "starting ng40test... log @ $LOG_DIR/$DATE/$TC_LOG.ng40.log"
	scp $THIS_DIR/$TC_CFG.cfg $NG40_HOST:$NG40_DIR/verify.cfg &> /dev/null
	cp $THIS_DIR/$TC_CFG.cfg $LOG_DIR/$DATE/$TC_LOG.cfg
	#setsid stdbuf -oL -eL \
		ssh -t -t $NG40_HOST \
		"cd $NG40_DIR; ng40test $TESTCASE verify.cfg; rm verify.cfg; exit" \
		</dev/null &> $LOG_DIR/$DATE/$TC_LOG.ng40.log

	#get additonal log files
	scp $NG40_HOST:$NG40_DIR/log/$(ssh $NG40_HOST "ls -tr $NG40_DIR/log/ | tail -n 1") $LOG_DIR/$DATE/$TC_LOG.ng40.short.log
	cp $NGIC_DIR/dp/cdr/$(ls -tr $NGIC_DIR/dp/cdr/ | tail -n 1) $LOG_DIR/$DATE/$TC_LOG.$(ls -tr $NGIC_DIR/dp/cdr/ | tail -n 1)

	kill $(jobs -p)
	for i in {0..100}; do
		sleep .1
		if [[ ! $(jobs -p) ]]; then break; fi
		kill -9 $(jobs -p)
		sleep .15
	done
	return 0
}

##################################################################################
#v4: adding ng40 configuration file generation here

#Some common errors that would result in ng40 error or undefined behavoir
verify_parameters() {
	if [ ! -z $duration ] && [ ! -z $activebearerTimeinms ]; then
		if (( duration < ( $activebearerTimeinms / 1000 ) )); then
			echo "Parameter check failed. Active bearer time (in ms) exceeds duration in seconds"
			exit
		fi
	fi
	if [ ! -z $pps ] && [ ! -z $numran ]; then
		if (( ( pps / numran ) > 2000000 )); then 
			echo "Total pps exceeds 2Mpps per ran assembly"
			exit
		fi
	fi
	if (( $totalrate > 4800 )); then
		echo "Total signaling rate exceeds 4800"
		exit
	fi

}

write_config() {
	check_parameters $# 1
	verify_parameters
	TESTNAME=$1
	FILENAME=$THIS_DIR/$TESTNAME.cfg

	#overwrite file contents
	echo "set \$sgw_path $NGIC_DIR" > $FILENAME
	if [ ! -z $enableWebapp ]; then echo "set \$enableWebapp $enableWebapp" >> $FILENAME; fi
	if [ ! -z $checksgw ]; then echo "set \$checksgw "false"" >> $FILENAME; fi
	if [ ! -z $checksgwcdrs ]; then echo "set \$checksgwcdrs $checksgwcdrs" >> $FILENAME; fi

	if [ ! -z $numran ]; then echo "set \$numran $numran" >> $FILENAME; fi
	echo "set \$subs $subs" >> $FILENAME
	echo "set \$totalrate $totalrate" >> $FILENAME

	#for those tests with traffic
	if [ ! -z $duration ]; then echo "set \$duration $duration" >> $FILENAME; fi
	if [ ! -z $activebearerTimeinms ]; then echo "set \$activebearerTimeinms $activebearerTimeinms" >> $FILENAME; fi
	if [ ! -z $pps ]; then echo "set \$pps $pps" >> $FILENAME; fi
	if [ ! -z $bps ]; then echo "set \$bps $bps" >> $FILENAME; fi

	#for those tests with other parameters defined
	if [ ! -z $testcasename ]; then echo "set \$testcasename $testcasename"; >> $FILENAME; fi
	if [ ! -z $testcaseparameter ]; then echo "set \$testcaseparameter $testcaseparameter"; >> $FILENAME; fi
}

# for use with tc_userplane_mpps.ntl and tc_pcc_tft_mpps.ntl test cases
write_mpps_config() {
	check_parameters $# 8
	local TESTNAME=$1
	local subs=$2
	local totalrate=$3
	local numran=$4
	local pps=$5
	local bps=$6
	local duration=$7
	local activebearerTimeinms=$8

	local enableWebapp="false"
	local checksgw="false"
	write_config $TESTNAME

	echo $TESTNAME
}



#syntax:
#run_testcase (tc_userplane_mpps.ngl | tc_pcc_tft_mpps.ntl) (./cfg | $(write_mpps_config $TESTNAME $NUM_UES $S11_RATE $NUM_RANS $PPS $BPS $TST_DURATION $ACTIVE_BEARER_TM_IN_MS)) $NUM_WORKERS

if [ $# -eq 1 ]; then 
	if [ "$1" == "short" ]; then 
	for j in {900000,1000000,1100000}; do
		run_testcase tc_userplane_mpps.ntl $(write_mpps_config tc_userplane_mpps_25000_1K_${j}_1wk 25000 2000 4 $j 9800000000 50 18700) 1
		run_testcase tc_pcc_tft_mpps.ntl   $(write_mpps_config tc_pcc_tft_mpps_12500_1K_${j}_1wk   12500 1000 4 $j 9800000000 50 18700) 1
	done
	for j in {3900000,4000000,4100000}; do
		run_testcase tc_userplane_mpps.ntl $(write_mpps_config tc_userplane_mpps_25000_1K_${j}_1wk 25000 2000 4 $j 9800000000 50 18700) 4
	done
	fi
else
	for j in {900000,1000000,1100000}; do
		run_testcase tc_userplane_mpps.ntl $(write_mpps_config tc_userplane_mpps_250000_1K_${j}_1wk 250000 1000 4 $j 9800000000 500 187000) 1
		run_testcase tc_pcc_tft_mpps.ntl   $(write_mpps_config tc_pcc_tft_mpps_125000_1K_${j}_1wk   125000 1000 4 $j 9800000000 500 187000) 1
	done
	for j in {3900000,4000000,4100000}; do
		run_testcase tc_userplane_mpps.ntl $(write_mpps_config tc_userplane_mpps_250000_1K_${j}_1wk 250000 1000 4 $j 9800000000 500 187000) 4
	done
fi


