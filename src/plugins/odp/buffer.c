/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 */
/*
 * buffer.c: allocate/free network buffers.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Allocate/free network buffers.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <odp/odp_packet.h>

/* Delete buffer free list. */
static void
odp_packet_buffer_delete_free_list (vlib_main_t * vm, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;
  u32 merge_index;
  int i;

  ASSERT (vlib_get_thread_index () == 0);

  f = vlib_buffer_get_free_list (vm, free_list_index);

  merge_index = vlib_buffer_get_free_list_with_size (vm, f->n_data_bytes);
  if (merge_index != ~0 && merge_index != free_list_index)
    {
      vlib_buffer_merge_free_lists (pool_elt_at_index
				    (bm->buffer_free_list_pool, merge_index),
				    f);
    }

  /* Delete free list */
  for (i = 0; i < vec_len (f->buffers); i++)
    {
      u32 flags, bi = f->buffers[i];
      do
	{
	  vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
	  odp_packet_t pkt = odp_packet_from_vlib_buffer (buffer);
	  flags = buffer->flags;
	  bi = buffer->next_buffer;

	  odp_packet_free (pkt);
	}
      while (flags & VLIB_BUFFER_NEXT_PRESENT);
    }
  vec_free (f->name);
  vec_free (f->buffers);

  /* Poison it. */
  memset (f, 0xab, sizeof (f[0]));

  pool_put (bm->buffer_free_list_pool, f);

  for (i = 1; i < vec_len (vlib_mains); i++)
    {
      bm = vlib_mains[i]->buffer_main;
      f = vlib_buffer_get_free_list (vlib_mains[i], free_list_index);;
      memset (f, 0xab, sizeof (f[0]));
      pool_put (bm->buffer_free_list_pool, f);
    }
}

/* Make sure free list has at least given number of free buffers. */
static uword
fill_free_list (vlib_main_t * vm,
		vlib_buffer_free_list_t * fl, uword min_free_buffers)
{
  vlib_buffer_t *b;
  int n, i;
  u32 n_remaining, n_alloc, n_this_chunk;
  odp_packet_main_t *om = odp_packet_main;

  /* Already have enough free buffers on free list? */
  n = min_free_buffers - vec_len (fl->buffers);
  if (n <= 0)
    return min_free_buffers;

  /* Always allocate round number of buffers. */
  n = round_pow2 (n, CLIB_CACHE_LINE_BYTES / sizeof (u32));

  /* Always allocate new buffers in reasonably large sized chunks. */
  n = clib_max (n, fl->min_n_buffers_each_physmem_alloc);

  n_remaining = n;
  n_alloc = 0;
  while (n_remaining > 0)
    {
      odp_packet_t pkts[n_remaining];

      n_this_chunk =
	odp_packet_alloc_multi (om->pool, fl->n_data_bytes, pkts,
				n_remaining);
      if (n_this_chunk <= 0)
	break;

      fl->n_alloc += n_this_chunk;
      n_alloc += n_this_chunk;
      n_remaining -= n_this_chunk;

      for (i = 0; i < n_this_chunk; i++)
	{
	  b = vlib_buffer_from_odp_packet (pkts[i]);
	  b->l2_priv_data = pkts[i];
	  u32 bi = vlib_get_buffer_index (vm, b);

	  vec_add1_aligned (fl->buffers, bi, CLIB_CACHE_LINE_BYTES);

	  if (CLIB_DEBUG > 0)
	    vlib_buffer_set_known_state (vm, bi, VLIB_BUFFER_KNOWN_FREE);

	  /* Initialize all new buffers. */
	  vlib_buffer_init_for_free_list (b, fl);
	  if (fl->buffer_init_function)
	    fl->buffer_init_function (vm, fl, &bi, 1);
	}
    }

  return n_alloc;
}

static u32
alloc_from_free_list (vlib_main_t * vm,
		      vlib_buffer_free_list_t * free_list,
		      u32 * alloc_buffers, u32 n_alloc_buffers)
{
  u32 *dst, *src;
  uword len;
  uword n_filled;

  dst = alloc_buffers;

  n_filled = fill_free_list (vm, free_list, n_alloc_buffers);
  if (n_filled == 0)
    return 0;

  len = vec_len (free_list->buffers);
  ASSERT (len >= n_alloc_buffers);

  src = free_list->buffers + len - n_alloc_buffers;
  clib_memcpy (dst, src, n_alloc_buffers * sizeof (u32));

  _vec_len (free_list->buffers) -= n_alloc_buffers;

  return n_alloc_buffers;
}

/* Allocate a given number of buffers into given array.
   Returns number actually allocated which will be either zero or
   number requested. */
u32
odp_packet_buffer_alloc (vlib_main_t * vm, u32 * buffers, u32 n_buffers)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;

  f = pool_elt_at_index (bm->buffer_free_list_pool,
			 VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  return alloc_from_free_list (vm, f, buffers, n_buffers);
}

u32
odp_packet_buffer_alloc_from_free_list (vlib_main_t * vm,
					u32 * buffers,
					u32 n_buffers, u32 free_list_index)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *f;

  f = pool_elt_at_index (bm->buffer_free_list_pool, free_list_index);

  return alloc_from_free_list (vm, f, buffers, n_buffers);
}

static_always_inline void
odp_buffer_free_inline (vlib_main_t * vm,
			u32 * buffers, u32 n_buffers, u32 follow_buffer_next)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *fl;
  u32 fi;
  int i;
  u32 (*cb) (vlib_main_t * vm, u32 * buffers, u32 n_buffers,
	     u32 follow_buffer_next);

  cb = bm->buffer_free_callback;

  if (PREDICT_FALSE (cb != 0))
    n_buffers = (*cb) (vm, buffers, n_buffers, follow_buffer_next);

  if (!n_buffers)
    return;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b;
      u32 bi = buffers[i];

      b = vlib_get_buffer (vm, bi);

      fl = vlib_buffer_get_buffer_free_list (vm, b, &fi);

      /* The only current use of this callback: multicast recycle */
      if (PREDICT_FALSE (fl->buffers_added_to_freelist_function != 0))
	{
	  int j;

	  vlib_buffer_add_to_free_list
	    (vm, fl, buffers[i], (b->flags & VLIB_BUFFER_RECYCLE) == 0);

	  for (j = 0; j < vec_len (bm->announce_list); j++)
	    {
	      if (fl == bm->announce_list[j])
		goto already_announced;
	    }
	  vec_add1 (bm->announce_list, fl);
	already_announced:
	  ;
	}
      else
	{
	  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_RECYCLE) == 0))
	    {
	      u32 flags, next;
	      odp_packet_t pkt;

	      do
		{
		  vlib_buffer_t *nb = vlib_get_buffer (vm, bi);
		  flags = nb->flags;
		  next = nb->next_buffer;
		  pkt = odp_packet_from_vlib_buffer (nb);

		  if (nb->n_add_refs)
		    nb->n_add_refs--;
		  else
		    odp_packet_free (pkt);

		  bi = next;
		}
	      while (follow_buffer_next
		     && (flags & VLIB_BUFFER_NEXT_PRESENT));
	    }
	}
    }
  if (vec_len (bm->announce_list))
    {
      vlib_buffer_free_list_t *fl;
      for (i = 0; i < vec_len (bm->announce_list); i++)
	{
	  fl = bm->announce_list[i];
	  fl->buffers_added_to_freelist_function (vm, fl);
	}
      _vec_len (bm->announce_list) = 0;
    }
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
  .vlib_buffer_alloc_from_free_list_cb =
    &odp_packet_buffer_alloc_from_free_list,
  .vlib_buffer_free_cb = &odp_packet_buffer_free,
  .vlib_buffer_free_no_next_cb = &odp_packet_buffer_free_no_next,
  .vlib_packet_template_init_cb = &odp_packet_template_init,
  .vlib_buffer_delete_free_list_cb = &odp_packet_buffer_delete_free_list,
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
