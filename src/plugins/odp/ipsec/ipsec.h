/*
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
#ifndef __ODP_IPSEC_H__
#define __ODP_IPSEC_H__

#include <odp_api.h>
#include <vnet/ipsec/ipsec.h>

typedef struct
{
  odp_crypto_session_t sess;
  u32 digest_size;
  u8 iv_data[16];
  u32 iv_len;
  u32 key_size;
} sa_data_t;

typedef struct
{
  sa_data_t *sa_sess_d[2];
  odp_queue_t post_encrypt, post_decrypt;
} odp_crypto_worker_main_t;

typedef struct
{
  odp_crypto_worker_main_t *workers;
} odp_crypto_main_t;

extern vlib_node_registration_t odp_crypto_input_node;
extern odp_crypto_main_t odp_crypto_main;
extern u8 enable_odp_crypto;

int create_sess (ipsec_sa_t * sa, sa_data_t * sess, int is_outbound);

clib_error_t *ipsec_init (vlib_main_t * vm);

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
