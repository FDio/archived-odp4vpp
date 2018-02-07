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

vlib_node_registration_t odp_crypto_esp_decrypt_node;
vlib_node_registration_t odp_crypto_esp_decrypt_post_node;

/* packet trace format function */
static u8 *
format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);

  s = format (s, "odp-crypto esp: crypto %U integrity %U",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

/* packet trace format function */
static u8 *
format_esp_decrypt_post_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "odp-crypto post esp (decrypt)");
  return s;
}

static uword
odp_crypto_esp_decrypt_node_fn (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  esp_main_t *em = &odp_esp_main;
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
      vlib_node_increment_counter (vm, odp_crypto_esp_decrypt_node.index,
				   ESP_DECRYPT_ERROR_NO_BUFFER, n_left_from);
      goto free_buffers_and_exit;
    }

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  esp_header_t *esp0;
	  ipsec_sa_t *sa0;
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0, *oh4 = 0;
	  ip6_header_t *ih6 = 0, *oh6 = 0;
	  u8 tunnel_mode = 1;
	  u8 transport_ip6 = 0;
	  sa_data_t *sa_sess_data;
	  odp_crypto_op_param_t crypto_op_params;
	  odp_bool_t posted = 0;
	  odp_crypto_op_result_t result;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  esp0 = vlib_buffer_get_current (b0);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  seq = clib_host_to_net_u32 (esp0->seq);

	  /* anti-replay check */
	  if (sa0->use_anti_replay)
	    {
	      int rv = 0;

	      if (PREDICT_TRUE (sa0->use_esn))
		rv = esp_replay_check_esn (sa0, seq);
	      else
		rv = esp_replay_check (sa0, seq);

	      if (PREDICT_FALSE (rv))
		{
		  clib_warning ("anti-replay SPI %u seq %u", sa0->spi, seq);
		  vlib_node_increment_counter (vm,
					       odp_crypto_esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_REPLAY, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  sa0->total_data_size += b0->current_length;
	  int icv_size = em->esp_integ_algs[sa0->integ_alg].trunc_size;

	  sa_sess_data = pool_elt_at_index (cwm->sa_sess_d[0], sa_index0);
	  if (PREDICT_FALSE (!(sa_sess_data->sess)))
	    {
	      int ret = create_sess (sa0, sa_sess_data, 0);

	      if (ret)
		{
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  crypto_op_params.session = sa_sess_data->sess;
	  crypto_op_params.ctx = NULL;
	  crypto_op_params.aad.ptr = NULL;
	  crypto_op_params.aad.length = 0;
	  crypto_op_params.pkt = odp_packet_from_vlib_buffer (b0);
	  crypto_op_params.out_pkt = crypto_op_params.pkt;
	  crypto_op_params.override_iv_ptr = sa_sess_data->iv_data;

	  if (PREDICT_TRUE (sa0->integ_alg != IPSEC_INTEG_ALG_NONE))
	    {
	      b0->current_length -= icv_size;

	      crypto_op_params.auth_range.offset = (u32) b0->current_data;
	      crypto_op_params.auth_range.length = b0->current_length;

	      crypto_op_params.hash_result_offset =
		(u32) (b0->current_data + b0->current_length);
	      crypto_op_params.auth_range.length = b0->current_length;
	    }

	  if (PREDICT_TRUE (sa0->use_anti_replay))
	    {
	      if (PREDICT_TRUE (sa0->use_esn))
		esp_replay_advance_esn (sa0, seq);
	      else
		esp_replay_advance (sa0, seq);
	    }

	  to_next[0] = bi0;
	  to_next += 1;

	  if (sa0->crypto_alg >= IPSEC_CRYPTO_ALG_AES_CBC_128 &&
	      sa0->crypto_alg <= IPSEC_CRYPTO_ALG_AES_CBC_256)
	    {
	      const int BLOCK_SIZE = 16;
	      const int IV_SIZE = 16;
	      esp_footer_t *f0;
	      u8 ip_hdr_size = 0;

	      ih4 = (ip4_header_t *) (b0->data + sizeof (ethernet_header_t));
	      if (PREDICT_TRUE
		  ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
		{
		  ip_hdr_size = sizeof (ip6_header_t);
		  ih6 =
		    (ip6_header_t *) (b0->data + sizeof (ethernet_header_t));
		}
	      else
		{
		  ip_hdr_size = sizeof (ip4_header_t);
		}

	      int blocks =
		(b0->current_length - sizeof (esp_header_t) -
		 IV_SIZE) / BLOCK_SIZE;

	      /* transport mode */
	      if (PREDICT_FALSE (!sa0->is_tunnel && !sa0->is_tunnel_ip6))
		{
		  tunnel_mode = 0;
		  if (PREDICT_TRUE
		      ((ih4->ip_version_and_header_length & 0xF0) != 0x40))
		    {
		      if (PREDICT_TRUE
			  ((ih4->ip_version_and_header_length & 0xF0) ==
			   0x60))
			{
			  transport_ip6 = 1;
			  oh6 = (ip6_header_t *) ((uintptr_t)
						  vlib_buffer_get_current (b0)
						  + sizeof (esp_header_t) +
						  IV_SIZE -
						  sizeof (ip6_header_t));
			}
		      else
			{
			  vlib_node_increment_counter (vm,
						       odp_crypto_esp_decrypt_node.index,
						       ESP_DECRYPT_ERROR_NOT_IP,
						       1);
			  goto trace;
			}
		    }
		  else
		    {
		      oh4 =
			(ip4_header_t *) ((uintptr_t)
					  vlib_buffer_get_current (b0) +
					  sizeof (esp_header_t) + IV_SIZE -
					  sizeof (ip4_header_t));
		    }
		}

	      crypto_op_params.cipher_range.offset =
		(u32) b0->current_data + sizeof (esp_header_t) + IV_SIZE;
	      crypto_op_params.cipher_range.length = BLOCK_SIZE * blocks;
	      crypto_op_params.override_iv_ptr =
		(u8 *) vlib_buffer_get_current (b0) + sizeof (esp_header_t);

	      int ret =
		odp_crypto_operation (&crypto_op_params, &posted, &result);

	      if (ret != 0)
		{
		  clib_error ("Crypto operation not sucessful\n");
		  goto trace;
		}

	      if (PREDICT_FALSE (!posted && !result.ok))
		{
		  vlib_node_increment_counter (vm,
					       odp_crypto_esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_INTEG_ERROR,
					       1);
		  goto trace;
		}

	      b0->current_data =
		sizeof (esp_header_t) + IV_SIZE + sizeof (ethernet_header_t);
	      b0->current_length = (blocks * BLOCK_SIZE) - 2;
	      if (tunnel_mode)
		b0->current_data += ip_hdr_size;
	      else
		b0->current_length += ip_hdr_size;

	      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      f0 =
		((esp_footer_t *) ((u8 *) vlib_buffer_get_current (b0) +
				   b0->current_length));
	      b0->current_length -= f0->pad_length;

	      /* tunnel mode */
	      if (PREDICT_TRUE (tunnel_mode))
		{
		  if (PREDICT_TRUE (f0->next_header == IP_PROTOCOL_IP_IN_IP))
		    {
		      next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
		      oh4 = vlib_buffer_get_current (b0);
		    }
		  else if (f0->next_header == IP_PROTOCOL_IPV6)
		    next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		  else
		    {
		      clib_warning ("next header: 0x%x", f0->next_header);
		      vlib_node_increment_counter (vm,
						   odp_crypto_esp_decrypt_node.index,
						   ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						   1);
		      goto trace;
		    }
		}
	      /* transport mode */
	      else
		{
		  if (PREDICT_FALSE (transport_ip6))
		    {
		      memmove (oh6, ih6, sizeof (ip6_header_t));

		      next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		      oh6->protocol = f0->next_header;
		      oh6->payload_length =
			clib_host_to_net_u16 (vlib_buffer_length_in_chain
					      (vm,
					       b0) - sizeof (ip6_header_t));
		    }
		  else
		    {
		      memmove (oh4, ih4, sizeof (ip4_header_t));

		      next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
		      oh4->ip_version_and_header_length = 0x45;
		      oh4->fragment_id = 0;
		      oh4->flags_and_fragment_offset = 0;
		      oh4->protocol = f0->next_header;
		      oh4->length =
			clib_host_to_net_u16 (vlib_buffer_length_in_chain
					      (vm, b0));
		      oh4->checksum = ip4_header_checksum (oh4);
		    }
		}

	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	      vnet_buffer (b0)->post_crypto.next_index = (u8) next0;
	    }

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  if (!posted)
	    {
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	    }
	  else
	    {
	      to_next -= 1;
	      n_left_to_next += 1;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, odp_crypto_esp_decrypt_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_crypto_esp_decrypt_node) = {
  .function = odp_crypto_esp_decrypt_node_fn,
  .name = "odp-crypto-esp-decrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (odp_crypto_esp_decrypt_node,
			      odp_crypto_esp_decrypt_node_fn)
     static uword esp_decrypt_post_node_fn (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0 = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  to_next[0] = bi0;
	  to_next += 1;

	  next0 = vnet_buffer (b0)->post_crypto.next_index;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    vlib_add_trace (vm, node, b0, 0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }
  vlib_node_increment_counter (vm, odp_crypto_esp_decrypt_post_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_crypto_esp_decrypt_post_node) = {
  .function = esp_decrypt_post_node_fn,
  .name = "odp-crypto-esp-decrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_post_trace,
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
