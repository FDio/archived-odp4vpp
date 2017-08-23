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
create_sess (ipsec_sa_t * sa, sa_data_t * sa_sess_data, int is_outbound)
{
  odp_crypto_ses_create_err_t ses_create_rc;
  odp_crypto_session_param_t crypto_params;
  odp_crypto_session_param_init (&crypto_params);

  esp_main_t *em = &odp_esp_main;
  int trunc_size = em->esp_integ_algs[sa->integ_alg].trunc_size;

  const int max_auth_capa_amount = 8;
  odp_crypto_auth_capability_t capa[max_auth_capa_amount];
  int actual_capa_amount; 

  crypto_params.auth_cipher_text = 1;

  /* Synchronous mode */
  crypto_params.pref_mode = ODP_CRYPTO_SYNC;
  crypto_params.compl_queue = ODP_QUEUE_INVALID;
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

  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_SHA_512_256:
      crypto_params.auth_alg = ODP_AUTH_ALG_SHA512_HMAC;
      break;
    case IPSEC_INTEG_ALG_SHA_256_128:
      crypto_params.auth_alg = ODP_AUTH_ALG_SHA256_HMAC;
      break;
    case IPSEC_INTEG_ALG_SHA1_96:
      crypto_params.auth_alg = ODP_AUTH_ALG_SHA1_HMAC;
      break;
    default:
      crypto_params.auth_alg = ODP_AUTH_ALG_NULL;
      break;
    }

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
	  ("Failed to get matching capabilities, algorithm appears to be supported but key or digest length incompatible\n");
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
  // TODO maybe we should check what crypto is available or something?
  return 0;
}

clib_error_t *
ipsec_init (vlib_main_t * vm)
{
  if (!enable_odp_crypto)
    return 0;
  ipsec_main_t *im = &ipsec_main;
  odp_crypto_main_t *ocm = &odp_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_node_t *ipsec_node, *crypto_node, *error_node;

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
  crypto_node = vlib_get_node_by_name (vm, (u8 *) "odp-crypto-esp-encrypt");
  ASSERT (crypto_node);
  im->esp_encrypt_node_index = crypto_node->index;
  im->esp_encrypt_next_index =
    vlib_node_add_next (vm, ipsec_node->index, crypto_node->index);

  ipsec_node = vlib_get_node_by_name (vm, (u8 *) "ipsec-input-ip4");
  ASSERT (ipsec_node);
  crypto_node = vlib_get_node_by_name (vm, (u8 *) "odp-crypto-esp-decrypt");
  ASSERT (crypto_node);
  im->esp_decrypt_node_index = crypto_node->index;
  im->esp_decrypt_next_index =
    vlib_node_add_next (vm, ipsec_node->index, crypto_node->index);

  im->cb.check_support_cb = odp_ipsec_check_support;
  im->cb.add_del_sa_sess_cb = add_del_sa_sess;

  vec_alloc (ocm->workers, tm->n_vlib_mains);
  _vec_len (ocm->workers) = tm->n_vlib_mains;

  esp_init ();

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
