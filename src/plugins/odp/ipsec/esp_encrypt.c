/*
 * esp_encrypt.c : IPSec ESP encrypt node
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

#define foreach_esp_encrypt_next                   \
_(DROP, "error-drop")                              \
_(IP4_LOOKUP, "ip4-lookup")                        \
_(IP6_LOOKUP, "ip6-lookup")                        \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(NO_BUFFER, "No buffer (packet dropped)")         \
 _(DECRYPTION_FAILED, "ESP encryption failed")      \
 _(SEQ_CYCLED, "sequence number cycled")


typedef enum
{
#define _(sym,str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
    ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

static char *esp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_error
#undef _
};

typedef struct
{
  u32 spi;
  u32 seq;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

vlib_node_registration_t odp_crypto_esp_encrypt_node;
vlib_node_registration_t odp_crypto_esp_encrypt_post_node;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "odp-crypto esp: spi %u seq %u crypto %U integrity %U",
	      t->spi, t->seq,
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

/* packet trace format function */
static u8 *
format_esp_encrypt_post_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "odp-crypto post esp (encrypt)");
  return s;
}


static uword
odp_crypto_esp_encrypt_node_fn (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  odp_crypto_main_t *ocm = &odp_crypto_main;
  u32 thread_index = vlib_get_thread_index ();
  esp_main_t *em = &odp_esp_main;

  ipsec_alloc_empty_buffers (vm, im);

  u32 *empty_buffers = im->empty_buffers[thread_index];

  odp_crypto_worker_main_t *cwm =
    vec_elt_at_index (ocm->workers, thread_index);

  if (PREDICT_FALSE (vec_len (empty_buffers) < n_left_from))
    {
      vlib_node_increment_counter (vm, odp_crypto_esp_encrypt_node.index,
				   ESP_ENCRYPT_ERROR_NO_BUFFER, n_left_from);
      clib_warning ("no enough empty buffers. discarding frame");
      goto free_buffers_and_exit;
    }

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, ip_version_traffic_class_and_flow_label;
	  vlib_buffer_t *b0 = 0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip4_and_esp_header_t *ih0, *oh0 = 0;
	  ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
	  ip4_header_t old_ip4_hdr;
	  ip6_header_t old_ip6_hdr;
	  ethernet_header_t old_eth_hdr;
	  esp_footer_t *f0;
	  u8 is_ipv6;
	  u8 ip_hdr_size;
	  u8 next_hdr_type;
	  u32 ip_proto = 0;
	  u8 transport_mode = 0;
	  sa_data_t *sa_sess_data;
	  odp_bool_t posted = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm,
					   odp_crypto_esp_encrypt_node.index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      to_next[0] = bi0;
	      to_next += 1;
	      goto trace;
	    }

	  sa0->total_data_size += b0->current_length;

	  ih0 = vlib_buffer_get_current (b0);

	  old_eth_hdr = *((ethernet_header_t *)
			  ((u8 *) vlib_buffer_get_current (b0) -
			   sizeof (ethernet_header_t)));

	  sa_sess_data = pool_elt_at_index (cwm->sa_sess_d[1], sa_index0);
	  if (PREDICT_FALSE (!(sa_sess_data->sess)))
	    {
	      int ret = create_sess (sa0, sa_sess_data, 1);

	      if (ret)
		{
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  if (PREDICT_FALSE
	      ((ih0->ip4.ip_version_and_header_length & 0xF0) == 0x60))
	    {
	      ip_hdr_size = sizeof (ip6_header_t);
	      is_ipv6 = 1;
	      old_ip6_hdr = *((ip6_header_t *) vlib_buffer_get_current (b0));
	      ih6_0 = vlib_buffer_get_current (b0);
	      ip_version_traffic_class_and_flow_label =
		ih6_0->ip6.ip_version_traffic_class_and_flow_label;
	      ip_proto = ih6_0->ip6.protocol;
	    }
	  else
	    {
	      ip_hdr_size = sizeof (ip4_header_t);
	      is_ipv6 = 0;
	      old_ip4_hdr = *((ip4_header_t *) vlib_buffer_get_current (b0));
	      ip_proto = old_ip4_hdr.protocol;
	    }

	  odp_packet_t pkt = odp_packet_from_vlib_buffer (b0);

	  const int IV_SIZE = 16;
	  int push_head_by = sizeof (esp_header_t) + IV_SIZE;

	  if (sa0->is_tunnel)
	    push_head_by += ip_hdr_size;
	  vlib_buffer_advance (b0, -push_head_by);

	  odp_adjust_data_pointers (b0, pkt);

	  to_next[0] = bi0;
	  to_next += 1;

	  /* is ipv6 */
	  if (PREDICT_FALSE (is_ipv6))
	    {
	      next_hdr_type = IP_PROTOCOL_IPV6;
	      oh6_0 = vlib_buffer_get_current (b0);

	      oh6_0->ip6.ip_version_traffic_class_and_flow_label =
		ip_version_traffic_class_and_flow_label;
	      oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
	      oh6_0->ip6.hop_limit = 254;
	      oh6_0->ip6.src_address.as_u64[0] =
		old_ip6_hdr.src_address.as_u64[0];
	      oh6_0->ip6.src_address.as_u64[1] =
		old_ip6_hdr.src_address.as_u64[1];
	      oh6_0->ip6.dst_address.as_u64[0] =
		old_ip6_hdr.dst_address.as_u64[0];
	      oh6_0->ip6.dst_address.as_u64[1] =
		old_ip6_hdr.dst_address.as_u64[1];
	      oh6_0->esp.spi = clib_net_to_host_u32 (sa0->spi);
	      oh6_0->esp.seq = clib_net_to_host_u32 (sa0->seq);

	      next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	    }
	  else
	    {
	      next_hdr_type = IP_PROTOCOL_IP_IN_IP;
	      oh0 = vlib_buffer_get_current (b0);

	      oh0->ip4.ip_version_and_header_length = 0x45;
	      oh0->ip4.tos = old_ip4_hdr.tos;
	      oh0->ip4.fragment_id = 0;
	      oh0->ip4.flags_and_fragment_offset = 0;
	      oh0->ip4.ttl = 254;
	      oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
	      oh0->ip4.src_address.as_u32 = old_ip4_hdr.src_address.as_u32;
	      oh0->ip4.dst_address.as_u32 = old_ip4_hdr.dst_address.as_u32;
	      oh0->esp.spi = clib_net_to_host_u32 (sa0->spi);
	      oh0->esp.seq = clib_net_to_host_u32 (sa0->seq);

	      next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	    }

	  if (PREDICT_TRUE
	      (!is_ipv6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
	    {
	      oh0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
	      oh0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else if (is_ipv6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
	    {
	      oh6_0->ip6.src_address.as_u64[0] =
		sa0->tunnel_src_addr.ip6.as_u64[0];
	      oh6_0->ip6.src_address.as_u64[1] =
		sa0->tunnel_src_addr.ip6.as_u64[1];
	      oh6_0->ip6.dst_address.as_u64[0] =
		sa0->tunnel_dst_addr.ip6.as_u64[0];
	      oh6_0->ip6.dst_address.as_u64[1] =
		sa0->tunnel_dst_addr.ip6.as_u64[1];

	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }
	  else
	    {
	      next_hdr_type = ip_proto;
	      if (vnet_buffer (b0)->sw_if_index[VLIB_TX] != ~0)
		{
		  transport_mode = 1;
		  ethernet_header_t *ieh0, *oeh0;
		  ieh0 = &old_eth_hdr;
		  oeh0 =
		    (ethernet_header_t *) ((uintptr_t)
					   vlib_buffer_get_current (b0) -
					   sizeof (ethernet_header_t));
		  clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
		  next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
		}
	      vlib_buffer_advance (b0, ip_hdr_size);
	    }

	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	    {
	      b0->current_length -= push_head_by;
	      const int BLOCK_SIZE = 16;
	      int blocks = 1 + (b0->current_length + 1) / BLOCK_SIZE;

	      /* pad packet in input buffer */
	      u8 pad_bytes = BLOCK_SIZE * blocks - 2 - b0->current_length;
	      u8 i;
	      u8 *padding =
		vlib_buffer_get_current (b0) + b0->current_length +
		push_head_by;
	      b0->current_length = BLOCK_SIZE * blocks;
	      for (i = 0; i < pad_bytes; ++i)
		{
		  padding[i] = i + 1;
		}
	      f0 = vlib_buffer_get_current (b0) + b0->current_length - 2 +
		push_head_by;
	      f0->pad_length = pad_bytes;
	      f0->next_header = next_hdr_type;

	      b0->current_length = ip_hdr_size +
		BLOCK_SIZE * blocks + sizeof (esp_header_t) + IV_SIZE;

	      odp_crypto_op_param_t crypto_op_params;
	      odp_crypto_op_result_t result;

	      crypto_op_params.session = sa_sess_data->sess;
	      crypto_op_params.ctx = NULL;
	      crypto_op_params.pkt = pkt;
	      crypto_op_params.out_pkt = pkt;

	      crypto_op_params.override_iv_ptr = sa_sess_data->iv_data;

	      int odp_offset_to_esp = ip_hdr_size,
		odp_offset_to_payload =
		sizeof (esp_header_t) + IV_SIZE + ip_hdr_size;

	      crypto_op_params.cipher_range.offset = odp_offset_to_payload;
	      crypto_op_params.cipher_range.length = BLOCK_SIZE * blocks;

	      crypto_op_params.auth_range.offset = odp_offset_to_esp;
	      crypto_op_params.auth_range.length =
		b0->current_length - ip_hdr_size;

	      crypto_op_params.hash_result_offset =
		odp_offset_to_payload + BLOCK_SIZE * blocks;

	      clib_memcpy ((u8 *) vlib_buffer_get_current (b0) +
			   ((int) push_head_by - (int) IV_SIZE),
			   sa_sess_data->iv_data,
			   sizeof (sa_sess_data->iv_data));

	      int push_tail_by =
		b0->current_length - odp_packet_len (pkt) +
		sa_sess_data->digest_size;
	      odp_packet_push_tail (pkt, push_tail_by);

	      b0->current_length +=
		em->esp_integ_algs[sa0->integ_alg].trunc_size;

	      vnet_buffer (b0)->post_crypto.next_index = (u8) next0;

	      int ret =
		odp_crypto_operation (&crypto_op_params, &posted, &result);
	      if (ret != 0)
		{
		  clib_error ("Crypto operation not sucessful\n");
		  goto trace;
		}
	    }

	  if (PREDICT_FALSE (is_ipv6))
	    {
	      oh6_0->ip6.payload_length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
				      sizeof (ip6_header_t));
	    }
	  else
	    {
	      oh0->ip4.length =
		clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
	      oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
	    }

	  if (transport_mode)
	    {
	      b0->current_data -= sizeof (ethernet_header_t) + ip_hdr_size;
	      b0->current_length += sizeof (ethernet_header_t);
	    }
	  else
	    {
	      b0->current_data =
		(i16) - push_head_by + sizeof (ethernet_header_t);
	    }

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  if (!posted)
	    {
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					       to_next, n_left_to_next, bi0,
					       next0);
	    }
	  else
	    {
	      to_next -= 1;
	      n_left_to_next += 1;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, odp_crypto_esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_crypto_esp_encrypt_node) = {
  .function = odp_crypto_esp_encrypt_node_fn,
  .name = "odp-crypto-esp-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (odp_crypto_esp_encrypt_node,
			      odp_crypto_esp_encrypt_node_fn)
     static uword esp_encrypt_post_node_fn (vlib_main_t * vm,
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
  vlib_node_increment_counter (vm, odp_crypto_esp_encrypt_post_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_crypto_esp_encrypt_post_node) = {
  .function = esp_encrypt_post_node_fn,
  .name = "odp-crypto-esp-encrypt-post",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_post_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
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
