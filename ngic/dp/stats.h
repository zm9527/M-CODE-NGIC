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

#ifndef _STATS_H_
#define _STATS_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane nic and pipeline stats.
 */
#include <rte_pipeline.h>
/**
 * Function to display IN stats of a pipeline.
 *
 * @param p
 *	rte pipeline.
 * @param port_id
 *	port id.
 *
 * @return
 *	None
 */
void display_pip_istats(struct rte_pipeline *p, char *name, uint8_t port_id);

/**
 * Function to display IN stats for all pipelines.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_pip_ictrs(void);

/**
 * Function to display OUT stats of a pipeline.
 *
 * @param p
 *	rte pipeline.
 * @param name
 *	pipeline name
 * @param port_id
 *	port id.
 *
 * @return
 *	None
 */
void display_pip_ostats(struct rte_pipeline *p, char *name, uint8_t port_id);

/**
 * Function to display OUT stats for all pipelines.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_pip_octrs(void);

/**
 * Function to display NIC stats.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_nic_stats(void);

/**
 * Function to display action handler stats of each pipeline.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_ah_ctrs(void);

/**
 * Function to display instrumentation data of workers.
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
void display_instmnt_wrkr(void);

/**
 * Core to print the pipeline stats.
 *
 * @param
 *	Unused
 *
 * @return
 *	None
 */
void epc_stats_core(__rte_unused void *args);

#endif /*_STATS_H_ */
