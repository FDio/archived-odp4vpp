/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <vlib/buffer.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define SHM_PKT_POOL_BUF_SIZE  (VLIB_BUFFER_DATA_SIZE)
#define SHM_PKT_POOL_NB_PKTS   10240
#define SHM_PKT_POOL_NAME      "packet_pool"

#define APPL_MODE_PKT_BURST    0
#define APPL_MODE_PKT_QUEUE    1
#define APPL_MODE_PKT_SCHED_ATOMIC    2
#define APPL_MODE_PKT_SCHED_ORDERED   3
#define APPL_MODE_PKT_SCHED_PARALLEL  4
#define APPL_MODE_PKT_TM       2

#define MAX_WORKERS 32
#define MAX_QUEUES (MAX_WORKERS + 1)

typedef struct
{
  u16 num_tx_queues;
  u16 num_rx_queues;
  u8 tx_mode;
  u8 rx_mode;
} odp_if_mode_t;

typedef struct
{
  u8 *name;
  odp_if_mode_t mode;
  u8 hw_addr[6];
  u8 set_hw_addr;
} odp_if_config_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8 *host_if_name;
  uword if_index;
  odp_pktio_t pktio;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 next_rx_frame;
  u32 next_tx_frame;
  u32 per_interface_next_index;
  u8 is_admin_up;
  odp_queue_t rxq[MAX_QUEUES];
  odp_pktin_queue_t inq[MAX_QUEUES];
  odp_pktout_queue_t outq[MAX_QUEUES];
  odp_queue_t txq[MAX_QUEUES];
  odp_if_mode_t m;
  odp_schedule_group_t sched_group;
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
extern u32 rx_sched_wait;
extern u32 tx_burst_size;
extern u32 num_pkts_in_pool;
extern odp_if_mode_t def_if_mode;
extern u8 enable_odp_crypto;

u32 odp_packet_create_if (vlib_main_t * vm, u8 * host_if_name,
			  u8 * hw_addr_set, u32 * sw_if_index,
			  odp_if_mode_t * mode);
u32 odp_packet_delete_if (vlib_main_t * vm, u8 * host_if_name);

u32 drop_err_pkts (odp_packet_t pkt_tbl[], u32 len);

always_inline odp_packet_t
odp_packet_from_vlib_buffer (vlib_buffer_t * b)
{
  odp_packet_t packet;
  packet = (odp_packet_t) (b->l2_priv_data);
  if (packet == NULL)
    clib_error ("ODP packet pointer was not set properly!\n");

  return packet;
}

always_inline vlib_buffer_t *
vlib_buffer_from_odp_packet (odp_packet_t p)
{
  return (vlib_buffer_t *) odp_packet_user_area (p);
}

always_inline void
odp_adjust_data_pointers (vlib_buffer_t * b0, odp_packet_t pkt)
{
  int diff;

  diff = ((uintptr_t) (b0->data + b0->current_data) -
	  (uintptr_t) odp_packet_data (pkt));
  if (diff > 0)
    odp_packet_pull_head (pkt, diff);
  else if (diff < 0)
    odp_packet_push_head (pkt, -diff);

  diff = b0->current_length - odp_packet_len (pkt);
  if (diff)
    {
      if (diff > 0)
	odp_packet_push_tail (pkt, diff);
      else
	odp_packet_pull_tail (pkt, -diff);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
