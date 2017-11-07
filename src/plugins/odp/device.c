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


static u8 *
format_odp_packet_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  odp_packet_main_t *om = &odp_packet_main;
  odp_packet_if_t *oif = vec_elt_at_index (om->interfaces, i);

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

static uword
odp_packet_interface_tx (vlib_main_t * vm,
			 vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  odp_packet_main_t *om = &odp_packet_main;
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  odp_packet_if_t *oif = pool_elt_at_index (om->interfaces, rd->dev_instance);
  odp_pktout_queue_t pktout;
  odp_packet_t pkt_tbl[VLIB_FRAME_SIZE];
  u32 sent = 0, count = 0;

  if (PREDICT_FALSE (oif->lockp != 0))
    {
      while (__sync_lock_test_and_set (oif->lockp, 1))
	;
    }

  if (odp_pktout_queue (oif->pktio, &pktout, 1) != 1)
    {
      return -1;
    }

  while (n_left > 0)
    {
      u32 len;
      vlib_buffer_t *b0;
      n_left--;
      u32 bi = buffers[0];
      buffers++;

      do
	{
	  b0 = vlib_get_buffer (vm, bi);
	  len = b0->current_length;
	  pkt_tbl[count] = odp_packet_alloc (om->pool, len);

	  if (pkt_tbl[count] == ODP_PACKET_INVALID)
	    {
	      clib_warning ("odp packet alloc failed");
	    }

	  clib_memcpy ((u8 *) (odp_packet_data (pkt_tbl[count])),
		       vlib_buffer_get_current (b0), len);
	  count++;
	}
      while ((bi = b0->next_buffer) && (count < VLIB_FRAME_SIZE));
    }

  CLIB_MEMORY_BARRIER ();

  sent = odp_pktout_send (pktout, pkt_tbl, count);
  sent = sent > 0 ? sent : 0;

  if (odp_unlikely (sent < count))
    {
      do
	{
	  odp_packet_free (pkt_tbl[sent]);
	}
      while (++sent < count);
    }

  if (PREDICT_FALSE (oif->lockp != 0))
    *oif->lockp = 0;

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);

  return frame->n_vectors;
}

static void
odp_packet_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				    u32 node_index)
{
  odp_packet_main_t *om = &odp_packet_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  odp_packet_if_t *oif = pool_elt_at_index (om->interfaces, hw->dev_instance);

  if (node_index == ~0)
    {
      oif->per_interface_next_index = node_index;
      return;
    }

  oif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), odp_packet_input_node.index,
			node_index);

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
  odp_packet_main_t *om = &odp_packet_main;
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
