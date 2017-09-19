/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define SHM_PKT_BUF_SIZE       1598
#define SHM_PKT_POOL_BUF_SIZE  1856
#define SHM_PKT_POOL_NB_PKTS   10240
#define SHM_PKT_POOL_NAME      "packet_pool"
#define APPL_MODE_PKT_BURST    0
#define APPL_MODE_PKT_QUEUE    1
#define APPL_MODE_PKT_SCHED    2

#define MAX_WORKERS 32
#define MAX_QUEUES (MAX_WORKERS + 1)

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
  odp_queue_t rxq[MAX_QUEUES];
  odp_pktin_queue_t inq[MAX_QUEUES];
  odp_pktout_queue_t outq[MAX_QUEUES];
  odp_queue_t txq[MAX_QUEUES];
  u16 rx_queues;
  u16 tx_queues;
} odp_packet_if_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  odp_packet_if_t *interfaces;
  u32 input_cpu_first_index;
  u32 input_cpu_count;
  /* hash of host interface names */
  mhash_t if_index_by_host_if_name;
  odp_instance_t instance;
  odp_pool_t pool;
  u32 if_count;
  u32 thread_cnt;
  odph_odpthread_t thread_tbl[MAX_WORKERS];
} odp_packet_main_t;

extern odp_packet_main_t *odp_packet_main;
extern vnet_device_class_t odp_packet_device_class;
extern vlib_node_registration_t odp_packet_input_node;

u32 odp_packet_create_if (vlib_main_t * vm, u8 * host_if_name,
			  u8 * hw_addr_set, u32 * sw_if_index, u32 mode,
			  u32 rx_queues);
u32 odp_packet_delete_if (vlib_main_t * vm, u8 * host_if_name);

u32 drop_err_pkts (odp_packet_t pkt_tbl[], u32 len);

always_inline odp_packet_t
odp_packet_from_vlib_buffer (vlib_buffer_t * b)
{
  odp_packet_t packet;
  packet = (odp_packet_t)(b->l2_priv_data);
  if (packet == NULL)
    clib_error("ODP packet pointer was not set properly!\n");

  return packet;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
