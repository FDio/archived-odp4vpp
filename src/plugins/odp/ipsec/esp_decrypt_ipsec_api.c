/*
 * esp_decrypt.c : IPSec ESP decrypt node
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <odp/ipsec/ipsec.h>
#include <odp/ipsec/esp.h>
#include <odp/odp_packet.h>

#include <assert.h>

#define foreach_esp_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_next
#undef _
    ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;


#define foreach_esp_decrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packed dropped)")         \
 _(DECRYPTION_FAILED, "ESP decryption failed")      \
 _(INTEG_ERROR, "Integrity check failed")           \
 _(REPLAY, "SA replayed packet")                    \
 _(NOT_IP, "Not IP packet (dropped)")


typedef enum
{
#define _(sym,str) ESP_DECRYPT_ERROR_##sym,
  foreach_esp_decrypt_error
#undef _
    ESP_DECRYPT_N_ERROR,
} esp_decrypt_error_t;

static char *esp_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_error
#undef _
};

typedef struct
{
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_decrypt_trace_t;

vlib_node_registration_t odp_ipsec_esp_decrypt_node;
vlib_node_registration_t odp_ipsec_esp_decrypt_post_node;

/* packet trace format function */
static u8 *
format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);

  s = format (s, "(ODP IPsec API) esp: crypto %U integrity %U",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

static uword
esp_decrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  odp_crypto_main_t *ocm = &odp_crypto_main;
  u32 thread_index = vlib_get_thread_index ();

  ipsec_alloc_empty_buffers (vm, im);

  u32 *empty_buffers = im->empty_buffers[thread_index];

  odp_crypto_worker_main_t *cwm =
    vec_elt_at_index (ocm->workers, thread_index);

  if (PREDICT_FALSE (vec_len (empty_buffers) < n_left_from))
    {
      vlib_node_increment_counter (vm, odp_ipsec_esp_decrypt_node.index,
				   ESP_DECRYPT_ERROR_NO_BUFFER, n_left_from);
      goto free_buffers_and_exit;
    }

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      u32 buffers_passed = 0;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *i_b0, *o_b0;
	  ipsec_sa_t *sa0;
	  u32 sa_index0 = ~0;
	  sa_data_t *sa_sess_data;
	  u8 ip_hdr_size = sizeof (ip4_header_t);
	  ip4_header_t *ih4 = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, bi0);

	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  ih4 = (ip4_header_t *) (i_b0->data + sizeof (ethernet_header_t));
	  if (PREDICT_TRUE
	      ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
	    {
	      ip_hdr_size = sizeof (ip6_header_t);
	    }

	  sa0->total_data_size += i_b0->current_length;

	  sa_sess_data = pool_elt_at_index (cwm->sa_sess_d[0], sa_index0);
	  if (PREDICT_FALSE (!(sa_sess_data->is_odp_sa_present)))
	    {
	      int ret = create_odp_sa (sa0, sa_sess_data, 0, 0);

	      if (ret)
		{
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  if (ip_hdr_size == sizeof (ip6_header_t))
	    next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
	  else
	    next0 = ESP_DECRYPT_NEXT_IP4_INPUT;

	  odp_packet_t pkt = odp_packet_from_vlib_buffer (i_b0);
	  odp_packet_t out_pkt;

	  odp_ipsec_in_param_t oiopt;
	  oiopt.num_sa = 1;
	  oiopt.sa = &sa_sess_data->odp_sa;

	  odp_packet_l3_offset_set (pkt, i_b0->current_data - ip_hdr_size);

	  to_next[0] = bi0;
	  to_next += 1;

	  int processed = 1;

	  int ret = odp_ipsec_in (&pkt, 1, &out_pkt, &processed, &oiopt);

	  o_b0 = vlib_buffer_from_odp_packet (out_pkt);

	  if (ret < 1)
	    {
	      clib_error ("(in) IPsec packet not processed\n");
	      goto trace;
	    }

	  /* add the change of the ODP data offset
	     and the offset to IP within the packet data */
	  o_b0->current_data =
	    (i16) ((intptr_t) odp_packet_data (out_pkt) -
		   (intptr_t) o_b0->data +
		   (intptr_t) odp_packet_l3_offset (out_pkt));
	  o_b0->current_length =
	    odp_packet_len (out_pkt) - sizeof (ethernet_header_t);

	  vnet_buffer (o_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  vnet_buffer (o_b0)->unused[0] = next0;

	trace:
	  if (PREDICT_FALSE (o_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      o_b0->flags |= VLIB_BUFFER_IS_TRACED;
	      o_b0->trace_index = o_b0->trace_index;
	      esp_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, o_b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	  buffers_passed += 1;
	}
      if (buffers_passed > 0)
	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, odp_ipsec_esp_decrypt_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_ipsec_esp_decrypt_node) = {
  .function = esp_decrypt_node_fn,
  .name = "odp-ipsec-esp-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_DECRYPT_NEXT_##s] = n,
    foreach_esp_decrypt_next
#undef _
  },
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
