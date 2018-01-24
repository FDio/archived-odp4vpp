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

vlib_node_registration_t odp_ipsec_esp_encrypt_node;
vlib_node_registration_t odp_ipsec_esp_encrypt_post_node;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "(ODP) esp: spi %u seq %u crypto %U integrity %U",
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

  s = format (s, "POST ENCRYPT CRYPTO (ODP) esp");
  return s;
}

static uword
esp_encrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  odp_crypto_main_t *ocm = &odp_crypto_main;
  u32 thread_index = vlib_get_thread_index ();

  vnet_main_t *vnm = vnet_get_main ();
  odp_packet_main_t *om = odp_packet_main;
  vnet_interface_main_t *vint_main = &vnm->interface_main;

  ipsec_alloc_empty_buffers (vm, im);

  u32 *empty_buffers = im->empty_buffers[thread_index];

  odp_crypto_worker_main_t *cwm =
    vec_elt_at_index (ocm->workers, thread_index);

  if (PREDICT_FALSE (vec_len (empty_buffers) < n_left_from))
    {
      vlib_node_increment_counter (vm, odp_ipsec_esp_encrypt_node.index,
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
	  u32 bi0, next0;
	  vlib_buffer_t *i_b0, *o_b0;
	  vnet_sw_interface_t *sw;
	  vnet_hw_interface_t *hw;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip6_header_t *h6 = 0;
	  odp_packet_if_t *oif;
	  sa_data_t *sa_sess_data;
	  u32 flow_label;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, bi0);
	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  sa0->total_data_size += i_b0->current_length;

	  h6 = vlib_buffer_get_current (i_b0);

	  flow_label =
	    (0xFFFFF & h6->ip_version_traffic_class_and_flow_label);

	  sa_sess_data = pool_elt_at_index (cwm->sa_sess_d[1], sa_index0);

	  clib_memcpy (&vnet_buffer (i_b0)->post_crypto.dst_mac,
		       ((u8 *) vlib_buffer_get_current (i_b0) -
			sizeof (ethernet_header_t)),
		       sizeof (ethernet_header_t));

	  if (PREDICT_FALSE (!(sa_sess_data->is_odp_sa_present)))
	    {
	      int ret = create_odp_sa (sa0, sa_sess_data, flow_label, 1);

	      if (ret)
		{
		  to_next[0] = bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  to_next[0] = bi0;
	  to_next += 1;

	  if (!sa0->is_tunnel)
	    {
	      next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;
	    }
	  else
	    {
	      if (sa0->is_tunnel_ip6)
		next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
	      else
		next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
	      vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	    }

	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
	    {
	      odp_packet_t pkt = odp_packet_from_vlib_buffer (i_b0);
	      odp_packet_t out_pkt;
	      odp_ipsec_out_inline_param_t ipsec_inline_params;

	      odp_ipsec_out_param_t oiopt;
	      oiopt.num_sa = 1;
	      oiopt.num_opt = 0;
	      oiopt.opt = NULL;
	      oiopt.sa = &sa_sess_data->odp_sa;

	      odp_adjust_data_pointers (i_b0, pkt);

	      odp_packet_l3_offset_set (pkt, 0);

	      vnet_buffer (i_b0)->post_crypto.next_index = (u8) next0;

	      int processed = 1;

	      int ret;

	      if (is_inline && next0 == ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT)
		{
		  sw =
		    vnet_get_sw_interface (vnm,
					   vnet_buffer (i_b0)->sw_if_index
					   [VLIB_TX]);
		  hw = vnet_get_hw_interface (vnm, sw->hw_if_index);
		  oif = pool_elt_at_index (om->interfaces, hw->dev_instance);
		  ipsec_inline_params.pktio = oif->pktio;
		  ipsec_inline_params.outer_hdr.ptr =
		    (u8 *) & vnet_buffer (i_b0)->post_crypto.dst_mac;
		  ipsec_inline_params.outer_hdr.len =
		    sizeof (ethernet_header_t);
		  ret =
		    odp_ipsec_out_inline (&pkt, 1, &oiopt,
					  &ipsec_inline_params);
		  vlib_increment_combined_counter
		    (vint_main->combined_sw_if_counters +
		     VNET_INTERFACE_COUNTER_TX, thread_index,
		     vnet_buffer (i_b0)->sw_if_index[VLIB_TX], 1,
		     i_b0->current_length);
		}
              else if (is_async)
		ret = odp_ipsec_out_enq (&pkt, 1, &oiopt);
	      else
		ret = odp_ipsec_out (&pkt, 1, &out_pkt, &processed, &oiopt);

	      if (ret < 1)
		{
		  clib_error ("(out) IPsec packet not processed\n");
		  goto trace;
		}


	      if (!is_async
		  && !(is_inline
		       && next0 == ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT))
		{
		  o_b0 = vlib_buffer_from_odp_packet (out_pkt);


		  o_b0->current_data =
		    (i16) ((intptr_t) odp_packet_data (out_pkt) -
			   (intptr_t) o_b0->data +
			   (intptr_t) odp_packet_l3_offset (out_pkt));
		  o_b0->current_length = odp_packet_len (out_pkt);

		  if (!sa0->is_tunnel)
		    {
		      if (vnet_buffer (o_b0)->sw_if_index[VLIB_TX] != ~0)
			{
			  ethernet_header_t *ieh0, *oeh0;
			  ieh0 =
			    (ethernet_header_t *) &
			    vnet_buffer (i_b0)->post_crypto.dst_mac;
			  oeh0 =
			    (ethernet_header_t *) ((uintptr_t)
						   vlib_buffer_get_current
						   (o_b0) -
						   sizeof
						   (ethernet_header_t));
			  clib_memcpy (oeh0, ieh0,
				       sizeof (ethernet_header_t));
			}

		      o_b0->current_data -= sizeof (ethernet_header_t);
		      o_b0->current_length += sizeof (ethernet_header_t);
		    }

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi0, next0);
		}
	      else
		{
		  to_next -= 1;
		  n_left_to_next += 1;
		}
	    }
	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, i_b0, sizeof (*tr));
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq - 1;
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, odp_ipsec_esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

free_buffers_and_exit:
  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_ipsec_esp_encrypt_node) = {
  .function = esp_encrypt_node_fn,
  .name = "odp-ipsec-esp-encrypt",
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

VLIB_NODE_FUNCTION_MULTIARCH (odp_ipsec_esp_encrypt_node, esp_encrypt_node_fn)
     static uword
       esp_encrypt_post_node_fn (vlib_main_t * vm,
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

	  if (next0 == ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT)
	    {

	      ethernet_header_t *ieh0, *oeh0;
	      ieh0 = (ethernet_header_t *) & vnet_buffer (b0)->post_crypto.dst_mac;
	      oeh0 =
		(ethernet_header_t *) ((uintptr_t)
				       vlib_buffer_get_current (b0) -
				       sizeof (ethernet_header_t));
	      clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
	      b0->current_data -= sizeof (ethernet_header_t);
	      b0->current_length += sizeof (ethernet_header_t);
	    }


	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    vlib_add_trace (vm, node, b0, 0);
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, odp_ipsec_esp_encrypt_post_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_ipsec_esp_encrypt_post_node) = {
  .function = esp_encrypt_post_node_fn,
  .name = "odp-ipsec-esp-encrypt-post",
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
