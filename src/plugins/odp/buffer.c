/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * Allocate/free ODP buffers.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <odp/odp_packet.h>

/* Allocate a given number of buffers into given array.
   Returns number actually allocated which will be either zero or
   number requested. */
u32
odp_packet_buffer_alloc (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  odp_packet_main_t *om = odp_packet_main;
  u32 len = SHM_PKT_BUF_SIZE, total = 0;
  odp_packet_t pkt;

  do
    {
      pkt = odp_packet_alloc (om->pool, len);
      if (pkt == ODP_PACKET_INVALID)
	break;

      buffers[total] =
	vlib_get_buffer_index (vm, vlib_buffer_from_odp_packet (pkt));
      ((vlib_buffer_t *) odp_packet_user_area (pkt))->l2_priv_data = pkt;
    }
  while (++total < n_buffers);

  return total;
}


static_always_inline void
odp_buffer_free_inline (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
			u32 follow_next)
{
  odp_packet_t pkt;
  u32 count = 0, bi;
  vlib_buffer_t *buffer;

  do
    {
      bi = buffers[count];
      do
	{
	  buffer = vlib_get_buffer (vm, bi);
	  pkt = odp_packet_from_vlib_buffer (buffer);
	  odp_packet_free (pkt);
	  if (follow_next == 0)
	    break;
	  bi = buffer->next_buffer;
	}
      while (buffer->flags & VLIB_BUFFER_NEXT_PRESENT);
      count++;
    }
  while (count < n_buffers);
}

static void
odp_packet_buffer_free (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  odp_buffer_free_inline (vm, buffers, n_buffers, 1);
}

static void
odp_packet_buffer_free_no_next (vlib_main_t * vm, u32 * buffers,
				u32 n_buffers)
{
  odp_buffer_free_inline (vm, buffers, n_buffers, 0);
}

static void
odp_packet_template_init (vlib_main_t * vm,
			  void *vt,
			  void *packet_data,
			  uword n_packet_data_bytes,
			  uword min_n_buffers_each_physmem_alloc, u8 * name)
{
  vlib_packet_template_t *t = (vlib_packet_template_t *) vt;

  vlib_worker_thread_barrier_sync (vm);
  memset (t, 0, sizeof (t[0]));

  vec_add (t->packet_data, packet_data, n_packet_data_bytes);

  vlib_worker_thread_barrier_release (vm);
}


static vlib_buffer_callbacks_t odp_callbacks = {
  .vlib_buffer_alloc_cb = &odp_packet_buffer_alloc,
  .vlib_buffer_free_cb = &odp_packet_buffer_free,
  .vlib_buffer_free_no_next_cb = &odp_packet_buffer_free_no_next,
  .vlib_packet_template_init_cb = &odp_packet_template_init,
};

static clib_error_t *
odp_buffer_init (vlib_main_t * vm)
{
  vlib_buffer_cb_register (vm, &odp_callbacks);
  return 0;
}

VLIB_INIT_FUNCTION (odp_buffer_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
