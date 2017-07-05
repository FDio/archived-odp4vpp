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

#include <linux/if_packet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
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

always_inline void
buffer_add_to_chain (vlib_main_t * vm, u32 bi, u32 first_bi, u32 prev_bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_t *first_b = vlib_get_buffer (vm, first_bi);
  vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_bi);

  /* update first buffer */
  first_b->total_length_not_including_first_buffer += b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = 0;


}

always_inline int
odp_packet_queue_mode (odp_pktio_t pktio, u32 mode, odp_packet_t pkt_tbl[])
{
  u32 num_evts = 0, num_pkts = 0, i = 0;
  odp_queue_t inq;
  odp_event_t evt_tbl[VLIB_FRAME_SIZE];
  u64 sched_wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS * 100);

  if (pktio == ODP_PKTIO_INVALID)
    {
      clib_warning("odp_pktio_lookup() failed");
      return -1;
    }

  inq = ODP_QUEUE_INVALID;
  if ((mode == APPL_MODE_PKT_QUEUE) &&
      (odp_pktin_event_queue(pktio, &inq, 1) != 1))
    {
      clib_warning("Error:no input queue");
      return -1;
    }

  if (inq != ODP_QUEUE_INVALID)
        num_evts = odp_queue_deq_multi(inq, evt_tbl, VLIB_FRAME_SIZE);
  else
        num_evts = odp_schedule_multi(NULL, sched_wait, evt_tbl, VLIB_FRAME_SIZE);

  /* convert events to packets, discarding any non-packet events */
  for (i = 0; i < num_evts; ++i)
    {
       if (odp_event_type(evt_tbl[i]) == ODP_EVENT_PACKET)
            pkt_tbl[num_pkts++] = odp_packet_from_event(evt_tbl[i]);
        else
            odp_event_free(evt_tbl[i]);
    }

  return num_pkts;

}

always_inline int
odp_packet_burst_mode (odp_pktio_t pktio, odp_pktin_queue_t pktin, odp_packet_t pkt_tbl[])
{
  u32 num_pkts;

  if (odp_pktin_queue(pktio, &pktin, 1) != 1)
    {
      clib_warning("odp_pktio_open() failed: no pktin queue");
      return -1;
    }

  num_pkts = odp_pktin_recv(pktin, pkt_tbl, VLIB_FRAME_SIZE);

  return num_pkts;

}

always_inline uword
odp_packet_device_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame, odp_packet_if_t *oif)
{
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  uword n_trace = vlib_get_trace_count (vm, node);
  odp_packet_main_t *om = &odp_packet_main;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  u32 n_free_bufs;
  u32 thread_index = vlib_get_thread_index();
  odp_pktin_queue_t pktin = { 0 };
  odp_packet_t pkt,pkt_tbl[VLIB_FRAME_SIZE];
  u32 pkts = 0, pkts_ok = 0;
  u32 n_buffer_bytes = vlib_buffer_free_list_buffer_size (vm,
                             VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  if (oif->per_interface_next_index != ~0)
   next_index = oif->per_interface_next_index;

  n_free_bufs = vec_len (om->rx_buffers[thread_index]);
  if (PREDICT_FALSE (n_free_bufs < VLIB_FRAME_SIZE))
    {
      vec_validate (om->rx_buffers[thread_index],
		    VLIB_FRAME_SIZE + n_free_bufs - 1);
      n_free_bufs +=
	vlib_buffer_alloc (vm, &om->rx_buffers[thread_index][n_free_bufs],
			   VLIB_FRAME_SIZE);
      _vec_len (om->rx_buffers[thread_index]) = n_free_bufs;

    }

  if ((oif->mode ==( APPL_MODE_PKT_QUEUE)) ||
      (oif->mode ==(APPL_MODE_PKT_SCHED)))
    {
      pkts = odp_packet_queue_mode(oif->pktio, oif->mode, pkt_tbl);
    }
  else
    {
      pkts = odp_packet_burst_mode(oif->pktio, pktin, pkt_tbl);
    }

  if (pkts > 0)
    {
      u32 n_left_to_next,i = 0;
      u32 next0 = next_index;
      pkts_ok = drop_err_pkts(pkt_tbl, pkts);
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

     while((i < pkts_ok) && (n_left_to_next) && (n_free_bufs))
       {
            vlib_buffer_t *first_b0 = 0;
            u32 offset = 0;
            u32 bi0 = 0, first_bi0 = 0, prev_bi0;
            uint8_t *data_buf;
            pkt = pkt_tbl[i];
            u32 data_len = odp_packet_len(pkt);
            data_buf = malloc(data_len);
            memset(data_buf, 0, data_len);
            odp_packet_copy_to_mem(pkt, 0, data_len, data_buf);

            while (data_len && n_free_bufs)
              {
                   vlib_buffer_t *b0;
                   /* grab free buffer */
                   u32 last_empty_buffer =
                   vec_len (om->rx_buffers[thread_index]) - 1;
                   prev_bi0 = bi0;
                   bi0 = om->rx_buffers[thread_index][last_empty_buffer];
                   b0 = vlib_get_buffer (vm, bi0);
                   _vec_len (om->rx_buffers[thread_index]) = last_empty_buffer;
                   n_free_bufs--;
                   /* copy data */
                   u32 bytes_to_copy =
                   data_len > n_buffer_bytes ? n_buffer_bytes : data_len;
                   b0->current_data = 0;
                   clib_memcpy (vlib_buffer_get_current (b0),
                   (u8 *) data_buf + offset,
                    bytes_to_copy);

                    /* fill buffer header */
                   b0->current_length = bytes_to_copy;

                   if (offset == 0)
                     {
		       b0->total_length_not_including_first_buffer = 0;
		       b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
		       vnet_buffer (b0)->sw_if_index[VLIB_RX] =
		       oif->sw_if_index;
		       vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
		       first_bi0 = bi0;
		       first_b0 = vlib_get_buffer (vm, first_bi0);
	             }
                   else
                     {
                       buffer_add_to_chain (vm, bi0, first_bi0, prev_bi0);
                     }

		   offset += bytes_to_copy;
		   data_len -= bytes_to_copy;
           }
          /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      odp_packet_input_trace_t *tr;
	      vlib_trace_buffer (vm, node, next0, first_b0, 0);
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = oif->hw_if_index;
	    }

          /* redirect if feature path enabled */
	  vnet_feature_start_device_input_x1 (oif->sw_if_index, &next0,
						  first_b0);

          /* enque and take next packet */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, first_bi0,
					       next0);

          /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += odp_packet_len(pkt);
	  to_next[0] = first_bi0;
	  to_next += 1;
          n_left_to_next--;
          free(data_buf);
          odp_packet_free(pkt_tbl[i]);
          i++;
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);

     }

  vlib_increment_combined_counter(vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_get_thread_index (), oif->hw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;

}

static uword
odp_packet_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{

  int i;
  u32 n_rx_packets = 0;
  u32 thread_index = vlib_get_thread_index ();
  odp_packet_main_t *om = &odp_packet_main;
  odp_packet_if_t *oif;

  for (i = 0; i < vec_len (om->interfaces); i++)
    {
      oif = vec_elt_at_index (om->interfaces, i);

      if (oif->is_admin_up &&
         (i % om->input_cpu_count) ==
         (thread_index - om->input_cpu_first_index))
        {
           n_rx_packets += odp_packet_device_input_fn (vm, node, frame, oif);
        }
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
