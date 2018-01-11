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
#include <odp/odp_packet.h>

#define foreach_odp_packet_tx_func_error               \
_(FRAME_NOT_READY, "tx frame not ready")              \
_(TXRING_EAGAIN,   "tx sendto temporary failure")     \
_(TXRING_FATAL,    "tx sendto fatal failure")         \
_(TXRING_OVERRUN,  "tx ring overrun")

typedef enum
{
#define _(f,s) ODP_PACKET_TX_ERROR_##f,
  foreach_odp_packet_tx_func_error
#undef _
    ODP_PACKET_TX_N_ERROR,
} odp_packet_tx_func_error_t;

static char *odp_packet_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_odp_packet_tx_func_error
#undef _
};

static_always_inline void
odp_prefetch_buffer_by_index (vlib_main_t * vm, u32 bi)
{
  vlib_buffer_t *b;
  odp_packet_t pkt;
  b = vlib_get_buffer (vm, bi);
  pkt = odp_packet_from_vlib_buffer (b);
  CLIB_PREFETCH (pkt, CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, LOAD);
}

static u8 *
format_odp_packet_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  odp_packet_main_t *om = odp_packet_main;
  odp_packet_if_t *oif = pool_elt_at_index (om->interfaces, i);

  s = format (s, "odp-%s", oif->host_if_name);
  return s;
}

static u8 *
format_odp_packet_device (u8 * s, va_list * args)
{
  s = format (s, "odp interface");
  return s;
}

static u8 *
format_odp_packet_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

#define NEXT_BUFFER(b0, bi, j)	\
	  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)	\
	    bi[j++] = b0->next_buffer;			\
	  else if (n_left)				\
	    {						\
	    bi[j++] = *buffers++;			\
	    n_left--;					\
	    }

static_always_inline int
odp_buffer_recycle (vlib_main_t * vm, odp_packet_main_t * om,
		    odp_packet_t * pkt, vlib_buffer_t * b, u32 bi,
		    u32 ** recycle)
{
  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_RECYCLE) == 0))
    return 1;

  odp_packet_t new = odp_packet_copy (*pkt, om->pool);
  vec_add1 (*recycle, bi);

  if (PREDICT_FALSE (new == ODP_PACKET_INVALID))
    {
      b->flags |= VLIB_BUFFER_REPL_FAIL;
      return 0;
    }

  *pkt = new;
  return 1;
}

static uword
odp_packet_interface_tx (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  odp_packet_main_t *om = odp_packet_main;
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  odp_packet_if_t *oif = pool_elt_at_index (om->interfaces, rd->dev_instance);
  uword queue_index = vlib_get_thread_index () % oif->m.num_tx_queues;
  u32 mode = oif->m.tx_mode;
  u32 burst_size = (tx_burst_size ? tx_burst_size : VLIB_FRAME_SIZE);
  union
  {
    odp_packet_t pkt[burst_size];
    odp_event_t evt[burst_size];
  } tbl;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 bi[4];
  u32 sent, count = 0, todo = 0;
  u32 *recycle = NULL;

  while (n_left > 0 || todo > 0)
    {
      int ret;

      for (; (todo < 4) && (n_left > 0); todo++, n_left--)
	bi[todo] = *buffers++;

      while ((todo == 4) && (count + 3 < burst_size))
	{
	  odp_packet_t pkt0, pkt1, pkt2, pkt3;

	  b0 = vlib_get_buffer (vm, bi[0]);
	  b1 = vlib_get_buffer (vm, bi[1]);
	  b2 = vlib_get_buffer (vm, bi[2]);
	  b3 = vlib_get_buffer (vm, bi[3]);

	  pkt0 = odp_packet_from_vlib_buffer (b0);
	  pkt1 = odp_packet_from_vlib_buffer (b1);
	  pkt2 = odp_packet_from_vlib_buffer (b2);
	  pkt3 = odp_packet_from_vlib_buffer (b3);

	  odp_adjust_data_pointers (b0, pkt0);
	  odp_adjust_data_pointers (b1, pkt1);
	  odp_adjust_data_pointers (b2, pkt2);
	  odp_adjust_data_pointers (b3, pkt3);

	  if (mode == APPL_MODE_PKT_QUEUE)
	    {
	      if (odp_buffer_recycle (vm, om, &pkt0, b0, bi[0], &recycle))
		tbl.evt[count++] = odp_packet_to_event (pkt0);
	      if (odp_buffer_recycle (vm, om, &pkt1, b1, bi[1], &recycle))
		tbl.evt[count++] = odp_packet_to_event (pkt1);
	      if (odp_buffer_recycle (vm, om, &pkt2, b2, bi[2], &recycle))
		tbl.evt[count++] = odp_packet_to_event (pkt2);
	      if (odp_buffer_recycle (vm, om, &pkt3, b3, bi[3], &recycle))
		tbl.evt[count++] = odp_packet_to_event (pkt3);
	    }
	  else
	    {
	      if (odp_buffer_recycle (vm, om, &pkt0, b0, bi[0], &recycle))
		tbl.pkt[count++] = pkt0;
	      if (odp_buffer_recycle (vm, om, &pkt1, b1, bi[1], &recycle))
		tbl.pkt[count++] = pkt1;
	      if (odp_buffer_recycle (vm, om, &pkt2, b2, bi[2], &recycle))
		tbl.pkt[count++] = pkt2;
	      if (odp_buffer_recycle (vm, om, &pkt3, b3, bi[3], &recycle))
		tbl.pkt[count++] = pkt3;
	    }

	  todo = 0;
	  NEXT_BUFFER (b0, bi, todo);
	  NEXT_BUFFER (b1, bi, todo);
	  NEXT_BUFFER (b2, bi, todo);
	  NEXT_BUFFER (b3, bi, todo);
	}

      while (todo && (count < burst_size))
	{
	  odp_packet_t pkt;

	  b0 = vlib_get_buffer (vm, bi[todo - 1]);

	  pkt = odp_packet_from_vlib_buffer (b0);

	  odp_adjust_data_pointers (b0, pkt);

	  if (odp_buffer_recycle (vm, om, &pkt, b0, bi[todo - 1], &recycle))
	    {
	      if (mode == APPL_MODE_PKT_QUEUE)
		tbl.evt[count++] = odp_packet_to_event (pkt);
	      else
		tbl.pkt[count++] = pkt;
	    }

	  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    bi[todo - 1] = b0->next_buffer;
	  else if (n_left)
	    {
	      bi[todo - 1] = *buffers++;
	      n_left--;
	    }
	  else
	    todo--;
	}

      sent = 0;
      while (count > 0)
	{
	  switch (mode)
	    {
	    case APPL_MODE_PKT_BURST:
	      ret = odp_pktout_send (oif->outq[queue_index], &tbl.pkt[sent],
				     count);
	      break;
	    case APPL_MODE_PKT_QUEUE:
	      ret = odp_queue_enq_multi (oif->txq[queue_index],
					 &tbl.evt[sent], count);
	      break;
	    case APPL_MODE_PKT_TM:
	    default:
	      ret = 0;
	      clib_error ("Invalid mode\n");
	    }

	  if (odp_unlikely (ret < 0))
	    {
	      /* Drop one packet and try again */
	      odp_packet_free (tbl.pkt[sent]);
	      count--;
	      sent++;
	    }
	  else
	    {
	      count -= ret;
	      sent += ret;
	    }
	}
    }

  /* Recycle replicated buffers */
  if (PREDICT_FALSE (recycle != NULL))
    {
      vlib_buffer_free (vm, recycle, vec_len (recycle));
      vec_free (recycle);
    }

  return (frame->n_vectors - n_left);
}

static void
odp_packet_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				    u32 node_index)
{
  odp_packet_main_t *om = odp_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  odp_packet_if_t *oif = pool_elt_at_index (om->interfaces, hw->dev_instance);

  if (node_index == ~0)
    {
      oif->per_interface_next_index = node_index;
      return;
    }

  oif->per_interface_next_index = vlib_node_add_next (vlib_get_main (),
						      odp_packet_input_node.
						      index, node_index);
}

static void
odp_packet_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
odp_packet_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				    u32 flags)
{
  odp_packet_main_t *om = odp_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  odp_packet_if_t *oif = pool_elt_at_index (om->interfaces, hw->dev_instance);
  u32 hw_flags;

  oif->is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (oif->is_admin_up)
    hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
  else
    hw_flags = 0;

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return 0;
}

static clib_error_t *
odp_packet_subif_add_del_function (vnet_main_t * vnm,
				   u32 hw_if_index,
				   struct vnet_sw_interface_t *st, int is_add)
{
/* Nothing for now */
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (odp_packet_device_class) = {
  .name = "odp-packet",
  .tx_function = odp_packet_interface_tx,
  .format_device_name = format_odp_packet_device_name,
  .format_device = format_odp_packet_device,
  .format_tx_trace = format_odp_packet_tx_trace,
  .tx_function_n_errors = ODP_PACKET_TX_N_ERROR,
  .tx_function_error_strings = odp_packet_tx_func_error_strings,
  .rx_redirect_to_node = odp_packet_set_interface_next_node,
  .clear_counters = odp_packet_clear_hw_interface_counters,
  .admin_up_down_function = odp_packet_interface_admin_up_down,
  .subif_add_del_function = odp_packet_subif_add_del_function,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (odp_packet_device_class,
				   odp_packet_interface_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
