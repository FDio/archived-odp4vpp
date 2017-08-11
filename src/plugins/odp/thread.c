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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp/odp_packet.h>

static clib_error_t *
odp_launch_thread (void *fp, vlib_worker_thread_t * w, unsigned lcore_id)
{
  odp_packet_main_t *om = odp_packet_main;
  odp_cpumask_t thd_mask;
  odph_odpthread_params_t thr_params;

  if (om->thread_cnt == MAX_WORKERS)
    return clib_error_return (0, "Failed to launch thread %u", lcore_id);

  memset (&thr_params, 0, sizeof (thr_params));
  thr_params.start = fp;
  thr_params.arg = w;
  thr_params.thr_type = ODP_THREAD_WORKER;
  thr_params.instance = om->instance;
  odp_cpumask_zero (&thd_mask);
  odp_cpumask_set (&thd_mask, lcore_id);

  odph_odpthreads_create (&om->thread_tbl[om->thread_cnt], &thd_mask,
			  &thr_params);

  om->thread_cnt++;

  return 0;
}

static clib_error_t *
odp_thread_set_lcore (u32 thread, u16 lcore)
{

  return 0;
}

static vlib_thread_callbacks_t odp_callbacks = {
  .vlib_launch_thread_cb = &odp_launch_thread,
  .vlib_thread_set_lcore_cb = &odp_thread_set_lcore,
};

static clib_error_t *
odp_thread_init (vlib_main_t * vm)
{
  vlib_thread_cb_register (vm, &odp_callbacks);
  return 0;
}

VLIB_INIT_FUNCTION (odp_thread_init);

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
