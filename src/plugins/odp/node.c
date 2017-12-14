/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <linux/if_packet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <odp/odp_packet.h>

#define foreach_odp_packet_input_error

typedef enum
{
#define _(f,s) ODP_PACKET_INPUT_ERROR_##f,
  foreach_odp_packet_input_error
#undef _
    ODP_PACKET_INPUT_N_ERROR,
} odp_packet_input_error_t;

static char *odp_packet_input_error_strings[] = {
#define _(n,s) s,
  foreach_odp_packet_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  odp_packet_t pkt;
} odp_packet_input_trace_t;

static u8 *
format_odp_packet_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  odp_packet_input_trace_t *t = va_arg (*args, odp_packet_input_trace_t *);

  s = format (s, "odp_packet: hw_if_index %d next-index %d",
	      t->hw_if_index, t->next_index);

  return s;
}

int
odp_packet_queue_mode (odp_pktio_t pktio, u32 mode, odp_packet_t pkt_tbl[])
{
  u32 num_evts = 0, num_pkts = 0;
  int i;
  odp_queue_t inq;
  odp_event_t evt_tbl[VLIB_FRAME_SIZE];
  u64 sched_wait = odp_schedule_wait_time (ODP_TIME_MSEC_IN_NS * 100);

  if (pktio == ODP_PKTIO_INVALID)
    {
      clib_warning ("odp_pktio_lookup() failed");
      return -1;
    }

  inq = ODP_QUEUE_INVALID;
  if ((mode == APPL_MODE_PKT_QUEUE) &&
      (odp_pktin_event_queue (pktio, &inq, 1) != 1))
    {
      clib_warning ("Error:no input queue");
      return -1;
    }

  while (num_evts < VLIB_FRAME_SIZE)
    {
      if (inq != ODP_QUEUE_INVALID)
	i = odp_queue_deq_multi (inq, &evt_tbl[num_evts],
				 VLIB_FRAME_SIZE - num_evts);
      else
	i = odp_schedule_multi (NULL, sched_wait, &evt_tbl[num_evts],
				VLIB_FRAME_SIZE - num_evts);
      if (i <= 0)
	break;
      num_evts += i;
    }

  /* convert events to packets, discarding any non-packet events */
  for (i = 0; i < num_evts; ++i)
    {
      if (odp_event_type (evt_tbl[i]) == ODP_EVENT_PACKET)
	pkt_tbl[num_pkts++] = odp_packet_from_event (evt_tbl[i]);
      else
	odp_event_free (evt_tbl[i]);
    }

  return num_pkts;
}

int
odp_packet_burst_mode (odp_pktio_t pktio, odp_pktin_queue_t pktin,
		       odp_packet_t pkt_tbl[])
{
  u32 num_pkts = 0;
  int ret;

  if (odp_pktin_queue (pktio, &pktin, 1) != 1)
    {
      clib_warning ("odp_pktio_open() failed: no pktin queue");
      return -1;
    }

  while (num_pkts < VLIB_FRAME_SIZE)
    {
      ret = odp_pktin_recv (pktin, &pkt_tbl[num_pkts],
			    VLIB_FRAME_SIZE - num_pkts);
      if (ret <= 0)
	break;
      num_pkts += ret;
    }

  return num_pkts;
}

always_inline int
vlib_buffer_is_ip4 (vlib_buffer_t * b)
{
  ethernet_header_t *h = (ethernet_header_t *) vlib_buffer_get_current (b);
  return (h->type == clib_host_to_net_u16 (ETHERNET_TYPE_IP4));
}

always_inline int
vlib_buffer_is_ip6 (vlib_buffer_t * b)
{
  ethernet_header_t *h = (ethernet_header_t *) vlib_buffer_get_current (b);
  return (h->type == clib_host_to_net_u16 (ETHERNET_TYPE_IP6));
}

always_inline int
vlib_buffer_is_mpls (vlib_buffer_t * b)
{
  ethernet_header_t *h = (ethernet_header_t *) vlib_buffer_get_current (b);
  return (h->type == clib_host_to_net_u16 (ETHERNET_TYPE_MPLS));
}

always_inline u32
odp_rx_next_from_etype (void *mb, vlib_buffer_t * b0)
{
  if (PREDICT_TRUE (vlib_buffer_is_ip4 (b0)))
    return VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
  else if (PREDICT_TRUE (vlib_buffer_is_ip6 (b0)))
    return VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
  else if (PREDICT_TRUE (vlib_buffer_is_mpls (b0)))
    return VNET_DEVICE_INPUT_NEXT_MPLS_INPUT;
  else
    return VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
}

always_inline uword
odp_packet_device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, odp_packet_if_t * oif)
{
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  odp_pktin_queue_t pktin = { 0 };
  odp_packet_t pkt_tbl[VLIB_FRAME_SIZE];
  u32 pkts = 0, pkts_ok = 0;

  if ((oif->mode == (APPL_MODE_PKT_QUEUE)) ||
      (oif->mode == (APPL_MODE_PKT_SCHED)))
    {
      pkts = odp_packet_queue_mode (oif->pktio, oif->mode, pkt_tbl);
    }
  else
    {
      pkts = odp_packet_burst_mode (oif->pktio, pktin, pkt_tbl);
    }

  if (pkts > 0)
    {
      u32 n_left_to_next, i = 0;
      u32 next0 = next_index;
      pkts_ok = drop_err_pkts (pkt_tbl, pkts);
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while ((i < pkts_ok) && (n_left_to_next))
	{
	  u32 bi0 = 0;
	  vlib_buffer_t *b0;

	  b0 = (vlib_buffer_t *) odp_packet_user_area (pkt_tbl[i]);
	  bi0 = vlib_get_buffer_index (vm, b0);
	  b0->l2_priv_data = pkt_tbl[i];

	  b0->current_length = odp_packet_len (pkt_tbl[i]);
	  b0->current_data = 0;
	  b0->total_length_not_including_first_buffer = 0;
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = oif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  if (PREDICT_FALSE (oif->per_interface_next_index != ~0))
	    next0 = oif->per_interface_next_index;
	  else
	    next0 = odp_rx_next_from_etype (pkt_tbl[i], b0);

	  vlib_buffer_advance (b0, device_input_next_node_advance[next0]);

	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      odp_packet_input_trace_t *tr;
	      vlib_trace_buffer (vm, node, next0, b0, 0);
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = oif->hw_if_index;
	    }

	  n_left_to_next--;
	  to_next[0] = bi0;
	  to_next += 1;

	  /* enque and take next packet */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += odp_packet_len (pkt_tbl[i]);
	  i++;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

  vlib_increment_combined_counter (vnet_get_main ()->
				   interface_main.combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX,
				   vlib_get_thread_index (), oif->hw_if_index,
				   n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

static uword
odp_packet_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame)
{
  u32 n_rx_packets = 0;
  odp_packet_main_t *om = odp_packet_main;
  odp_packet_if_t *oif;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    oif = pool_elt_at_index (om->interfaces, dq->dev_instance);
    if (oif->is_admin_up)
      n_rx_packets += odp_packet_device_input_fn (vm, node, frame, oif);
  }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_packet_input_node) = {
  .function = odp_packet_input_fn,
  .name = "odp-packet-input",
  .sibling_of = "device-input",
  .format_trace = format_odp_packet_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = ODP_PACKET_INPUT_N_ERROR,
  .error_strings = odp_packet_input_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (odp_packet_input_node, odp_packet_input_fn)
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
