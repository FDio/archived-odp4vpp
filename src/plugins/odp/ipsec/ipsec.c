/*
 * decap.c : IPSec tunnel support
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
#include <vnet/interface.h>

#include <odp/odp_packet.h>
#include <odp/ipsec/ipsec.h>
#include <odp/ipsec/esp.h>

static int
add_del_sa_sess (u32 sa_index, u8 is_add)
{
  odp_crypto_main_t *ocm = &odp_crypto_main;
  odp_crypto_worker_main_t *cwm;

  vec_foreach (cwm, ocm->workers)
  {
    sa_data_t *sa_sess_data;
    u8 is_outbound;

    for (is_outbound = 0; is_outbound < 2; is_outbound++)
      {
	if (is_add)
	  {
	    pool_get (cwm->sa_sess_d[is_outbound], sa_sess_data);
	    memset (sa_sess_data, 0, sizeof (sa_sess_data[0]));
	  }
	else
	  {

	    sa_sess_data =
	      pool_elt_at_index (cwm->sa_sess_d[is_outbound], sa_index);

	    if (sa_sess_data->sess)
	      {
		if (odp_crypto_session_destroy (sa_sess_data->sess))
		  {
		    clib_warning ("failed to free session");
		    return -1;
		  }
	      }

	    pool_put (cwm->sa_sess_d[is_outbound], sa_sess_data);
	  }
      }
  }

  return 0;
}

int
vpp_to_odp_auth_alg (int vpp_auth_alg)
{
  switch (vpp_auth_alg)
    {
    case IPSEC_INTEG_ALG_SHA_512_256:
      return ODP_AUTH_ALG_SHA512_HMAC;
    case IPSEC_INTEG_ALG_SHA_256_128:
      return ODP_AUTH_ALG_SHA256_HMAC;
    case IPSEC_INTEG_ALG_SHA1_96:
      return ODP_AUTH_ALG_SHA1_HMAC;
    default:
      return ODP_AUTH_ALG_NULL;
    }
}

int				// should flow_label be here?
create_odp_sa (ipsec_sa_t * sa, sa_data_t * sa_sess_data, int flow_label,
	       int is_outbound)
{
  odp_crypto_main_t *ocm = &odp_crypto_main;
  u32 thread_index = vlib_get_thread_index ();
  odp_crypto_worker_main_t *cwm =
    vec_elt_at_index (ocm->workers, thread_index);

  odp_ipsec_sa_param_t sa_params;
  odp_ipsec_sa_param_init (&sa_params);

  sa_params.dir =
    (is_outbound ? ODP_IPSEC_DIR_OUTBOUND : ODP_IPSEC_DIR_INBOUND);
  /* VPP does not currently support Authentication Headers (AH),
     Encapsulating Security Payload (ESP), neither does this code.
     Code needs modification, not only in this place. */
  sa_params.proto = ODP_IPSEC_ESP;
  sa_params.mode =
    (sa->is_tunnel ? ODP_IPSEC_MODE_TUNNEL : ODP_IPSEC_MODE_TRANSPORT);

  if (sa_params.mode == ODP_IPSEC_MODE_TUNNEL
      && sa_params.dir == ODP_IPSEC_DIR_OUTBOUND)
    {
      if (sa->is_tunnel_ip6)
	{
	  sa_sess_data->tunnel_src.ip6 = sa->tunnel_src_addr.ip6;
	  sa_sess_data->tunnel_dst.ip6 = sa->tunnel_dst_addr.ip6;
	  sa_params.outbound.tunnel.type = ODP_IPSEC_TUNNEL_IPV6;
	  sa_params.outbound.tunnel.ipv6.dst_addr =
	    &sa_sess_data->tunnel_dst.ip6;
	  sa_params.outbound.tunnel.ipv6.src_addr =
	    &sa_sess_data->tunnel_src.ip6;
	  sa_params.outbound.tunnel.ipv6.hlimit = 42;
	  sa_params.outbound.tunnel.ipv6.dscp = 0;
	  sa_params.outbound.tunnel.ipv6.flabel = flow_label;
	}
      else
	{
	  sa_sess_data->tunnel_src.ip4 = sa->tunnel_src_addr.ip4;
	  sa_sess_data->tunnel_dst.ip4 = sa->tunnel_dst_addr.ip4;
	  sa_params.outbound.tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
	  sa_params.outbound.tunnel.ipv4.dst_addr =
	    &sa_sess_data->tunnel_dst.ip4;
	  sa_params.outbound.tunnel.ipv4.src_addr =
	    &sa_sess_data->tunnel_src.ip4;
	  sa_params.outbound.tunnel.ipv4.ttl = 42;
	  sa_params.outbound.tunnel.ipv4.df = 42;
	}
    }

  sa_params.crypto.cipher_alg = ODP_CIPHER_ALG_AES_CBC;
  sa_params.crypto.cipher_key.data = sa->crypto_key;
  sa_params.crypto.cipher_key.length = sa->crypto_key_len;

  sa_params.crypto.auth_alg = vpp_to_odp_auth_alg (sa->integ_alg);
  sa_params.crypto.auth_key.data = sa->integ_key;
  sa_params.crypto.auth_key.length = sa->integ_key_len;

  sa_params.lifetime.soft_limit.packets = 0;
  sa_params.lifetime.hard_limit.packets = 0;

  sa_params.spi = sa->spi;

  sa_params.dest_queue =
    (is_outbound ? cwm->post_encrypt : cwm->post_decrypt);
  sa_params.context = NULL;
  sa_params.context_len = 0;

  sa_sess_data->odp_sa = odp_ipsec_sa_create (&sa_params);	// check if there are no errors

  if (sa_sess_data->odp_sa == ODP_IPSEC_SA_INVALID)
    return -1;

  sa_sess_data->is_odp_sa_present = 1;

  return 0;
}

int
create_sess (ipsec_sa_t * sa, sa_data_t * sa_sess_data, int is_outbound)
{
  odp_crypto_ses_create_err_t ses_create_rc;
  odp_crypto_session_param_t crypto_params;
  odp_crypto_session_param_init (&crypto_params);

  odp_crypto_main_t *ocm = &odp_crypto_main;
  u32 thread_index = vlib_get_thread_index ();
  odp_crypto_worker_main_t *cwm =
    vec_elt_at_index (ocm->workers, thread_index);

  esp_main_t *em = &odp_esp_main;
  int trunc_size = em->esp_integ_algs[sa->integ_alg].trunc_size;

  const int max_auth_capa_amount = 8;
  odp_crypto_auth_capability_t capa[max_auth_capa_amount];
  int actual_capa_amount;

  crypto_params.auth_cipher_text = 1;

  crypto_params.pref_mode = (is_async ? ODP_CRYPTO_ASYNC : ODP_CRYPTO_SYNC);
  crypto_params.compl_queue =
    (is_outbound ? cwm->post_encrypt : cwm->post_decrypt);
  crypto_params.output_pool = ODP_POOL_INVALID;

  if (sa->crypto_alg == IPSEC_CRYPTO_ALG_AES_CBC_128)
    {
      crypto_params.cipher_alg = ODP_CIPHER_ALG_AES_CBC;
      crypto_params.cipher_key.length = sa->crypto_key_len;
    }
  else
    {
      crypto_params.cipher_alg = ODP_CIPHER_ALG_NULL;
    }

  crypto_params.auth_alg = vpp_to_odp_auth_alg (sa->integ_alg);

  actual_capa_amount = odp_crypto_auth_capability (crypto_params.auth_alg,
						   capa,
						   max_auth_capa_amount);
  int picked_capa = -1;
  int i;

  for (i = 0; i < actual_capa_amount; i++)
    {
      if (capa[i].digest_len >= trunc_size &&
	  capa[i].key_len >= sa->crypto_key_len)
	{
	  picked_capa = i;
	  break;
	}
    }

  if (picked_capa == -1)
    {
      if (actual_capa_amount)
	clib_warning
	  ("Failed to get matching capabilities, algorithm appears to be supported "
	   "but key or digest length incompatible\n");
      else
	clib_warning
	  ("Failed to get matching capabilities, algorithm probably not supported\n");
      return -1;
    }

  sa_sess_data->key_size = capa[picked_capa].key_len;
  sa_sess_data->digest_size = capa[picked_capa].digest_len;
  crypto_params.auth_key.length = sa_sess_data->key_size;
  crypto_params.auth_digest_len = sa_sess_data->digest_size;

  memset (sa->integ_key + sa->integ_key_len, 0,
	  sa_sess_data->key_size - sa->integ_key_len);

  if (is_outbound)
    crypto_params.op = ODP_CRYPTO_OP_ENCODE;
  else
    crypto_params.op = ODP_CRYPTO_OP_DECODE;

  crypto_params.cipher_key.data = sa->crypto_key;
  crypto_params.auth_key.data = sa->integ_key;
  crypto_params.iv.data = sa_sess_data->iv_data;
  const int IV_LEN = 16;
  sa_sess_data->iv_len = IV_LEN;
  crypto_params.iv.length = IV_LEN;

  {
    int size = crypto_params.iv.length;
    int ret =
      odp_random_data (crypto_params.iv.data, size, ODP_RANDOM_CRYPTO);

    if (ret != size)
      {
	clib_error_return (0, "failed to get random from ODP");
	return -1;
      }
  }

  if (odp_crypto_session_create
      (&crypto_params, &sa_sess_data->sess, &ses_create_rc))
    {
      clib_warning ("Unable to create session\n");
      clib_warning ("%d\n", ses_create_rc);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (ODP_CRYPTO_SESSION_INVALID == sa_sess_data->sess)
    {
      clib_warning ("ODP_CRYPTO_SESSION_INVALID\n");
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  if (ODP_CRYPTO_SES_CREATE_ERR_NONE != ses_create_rc)
    {
      clib_warning ("Session creation returned some errors\n");
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  return 0;
}

clib_error_t *
odp_ipsec_check_support (ipsec_sa_t * sa)
{
  /* TODO check if the parameters present in the security association
     are supported by the odp_crypto/odp_ipsec, currently that that
     is partially checked during the creation of the crypto session,
     the odp_ipsec does not check it at all. */
  return 0;
}

clib_error_t *
ipsec_init (vlib_main_t * vm, u8 ipsec_api)
{
  if (!enable_odp_crypto && !ipsec_api)
    return 0;
  ipsec_main_t *im = &ipsec_main;
  odp_crypto_main_t *ocm = &odp_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_node_t *ipsec_node, *crypto_node, *error_node;
  odp_crypto_worker_main_t *cwm;

  memset (im, 0, sizeof (im[0]));

  im->vnet_main = vnet_get_main ();
  im->vlib_main = vm;

  im->spd_index_by_spd_id = hash_create (0, sizeof (uword));
  im->sa_index_by_sa_id = hash_create (0, sizeof (uword));
  im->spd_index_by_sw_if_index = hash_create (0, sizeof (uword));

  vec_validate_aligned (im->empty_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  error_node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  ASSERT (error_node);
  im->error_drop_node_index = error_node->index;


  ipsec_node = vlib_get_node_by_name (vm, (u8 *) "ipsec-output-ip4");
  ASSERT (ipsec_node);
  if (ipsec_api)
      crypto_node =
	vlib_get_node_by_name (vm, (u8 *) "odp-ipsec-esp-encrypt");
  else
      crypto_node =
	vlib_get_node_by_name (vm, (u8 *) "odp-crypto-esp-encrypt");
  ASSERT (crypto_node);
  im->esp_encrypt_node_index = crypto_node->index;
  im->esp_encrypt_next_index =
    vlib_node_add_next (vm, ipsec_node->index, crypto_node->index);

  ipsec_node = vlib_get_node_by_name (vm, (u8 *) "ipsec-input-ip4");
  ASSERT (ipsec_node);
  if (ipsec_api)
    crypto_node = vlib_get_node_by_name (vm, (u8 *) "odp-ipsec-esp-decrypt");
  else
      crypto_node =
	vlib_get_node_by_name (vm, (u8 *) "odp-crypto-esp-decrypt");
  ASSERT (crypto_node);
  im->esp_decrypt_node_index = crypto_node->index;
  im->esp_decrypt_next_index =
    vlib_node_add_next (vm, ipsec_node->index, crypto_node->index);

  im->cb.check_support_cb = odp_ipsec_check_support;
  im->cb.add_del_sa_sess_cb = add_del_sa_sess;

  vec_alloc (ocm->workers, tm->n_vlib_mains);
  _vec_len (ocm->workers) = tm->n_vlib_mains;

  for (cwm = ocm->workers + 1; cwm < vec_end (ocm->workers); cwm++)
    {
      cwm->post_encrypt = odp_queue_create (NULL, NULL);
      cwm->post_decrypt = odp_queue_create (NULL, NULL);
    }

  esp_init ();

  int i;
  for (i = 1; i < tm->n_vlib_mains; i++)
    vlib_node_set_state (vlib_mains[i], odp_crypto_input_node.index,
			 VLIB_NODE_STATE_POLLING);

  /* If there are no worker threads, enable polling
     crypto devices on the main thread, else
     assign the post crypt queues of the second
     thread to the main thread crypto sessions */
  if (tm->n_vlib_mains == 1)
    {
      ocm->workers[0].post_encrypt = odp_queue_create (NULL, NULL);
      ocm->workers[0].post_decrypt = odp_queue_create (NULL, NULL);
      vlib_node_set_state (vlib_mains[0], odp_crypto_input_node.index,
			   VLIB_NODE_STATE_POLLING);
    }
  else
    {
      ocm->workers[0].post_encrypt = ocm->workers[1].post_encrypt;
      ocm->workers[0].post_decrypt = ocm->workers[1].post_decrypt;
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
