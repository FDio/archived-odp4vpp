/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <odp_api.h>

#define SHM_PKT_POOL_BUF_SIZE  1856
#define SHM_PKT_POOL_NB_PKTS   10240
#define SHM_PKT_POOL_NAME      "packet_pool"
#define APPL_MODE_PKT_BURST    0
#define APPL_MODE_PKT_QUEUE    1
#define APPL_MODE_PKT_SCHED    2

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8 *host_if_name;
  volatile u32 *lockp;
  uword if_index;
  odp_pktio_t pktio;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 next_rx_frame;
  u32 next_tx_frame;
  u32 per_interface_next_index;
  u8 is_admin_up;
  u32 mode;
} odp_packet_if_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  odp_packet_if_t *interfaces;
  /* rx buffer cache */
  u32 **rx_buffers;
  u32 input_cpu_first_index;
  u32 input_cpu_count;
  /* hash of host interface names */
  mhash_t if_index_by_host_if_name;
  odp_instance_t instance;
  odp_pool_t pool;
  u32 if_count;
} odp_packet_main_t;

odp_packet_main_t odp_packet_main;
extern vnet_device_class_t odp_packet_device_class;
extern vlib_node_registration_t odp_packet_input_node;

u32 odp_packet_create_if (vlib_main_t * vm, u8 * host_if_name,
			   u8 * hw_addr_set, u32 * sw_if_index, u32 mode);
u32 odp_packet_delete_if (vlib_main_t * vm, u8 * host_if_name);

u32 drop_err_pkts(odp_packet_t pkt_tbl[], u32 len);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
