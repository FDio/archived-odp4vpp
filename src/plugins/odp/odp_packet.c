/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <odp/odp_packet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

odp_packet_main_t *odp_packet_main;

static u32
odp_packet_eth_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hi,
			    u32 flags)
{
  /* nothing for now */
  return 0;
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
u32
drop_err_pkts (odp_packet_t pkt_tbl[], unsigned len)
{
  odp_packet_t pkt;
  unsigned pkt_cnt = len;
  unsigned i, j;

  for (i = 0, j = 0; i < len; ++i)
    {
      pkt = pkt_tbl[i];

      if (odp_unlikely (odp_packet_has_error (pkt)))
	{
	  odp_packet_free (pkt);	/* Drop */
	  pkt_cnt--;
	}
      else if (odp_unlikely (i != j++))
	{
	  pkt_tbl[j - 1] = pkt;
	}
    }

  return pkt_cnt;
}

static odp_pktio_t
create_pktio (const char *dev, odp_pool_t pool, u32 mode)
{
  odp_pktio_t pktio;
  int ret;
  odp_pktio_param_t pktio_param;
  odp_pktin_queue_param_t pktin_param;

  odp_pktio_param_init (&pktio_param);

  switch (mode)
    {
    case APPL_MODE_PKT_BURST:
      pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
      break;
    case APPL_MODE_PKT_QUEUE:
      pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
      break;
    case APPL_MODE_PKT_SCHED:
      pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
      break;
    default:
      clib_warning ("Invalid mode\n");
    }

  /* Open a packet IO instance */
  pktio = odp_pktio_open (dev, pool, &pktio_param);

  if (pktio == ODP_PKTIO_INVALID)
    {
      clib_warning ("Error: pktio create failed for %s", dev);
    }

  odp_pktin_queue_param_init (&pktin_param);

  if (mode == APPL_MODE_PKT_SCHED)
    pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

  if (odp_pktin_queue_config (pktio, &pktin_param))
    {
      clib_warning ("Error: pktin config failed");
    }

  if (odp_pktout_queue_config (pktio, NULL))
    {
      clib_warning ("Error: pktout config failed");
    }

  ret = odp_pktio_start (pktio);
  if (ret != 0)
    {
      clib_warning ("Error: unable to start");
    }

  return pktio;
}

int
odp_worker_thread_enable ()
{

  /*If worker threads are enabled, switch to polling mode */
  foreach_vlib_main ((
		       {
		       vlib_node_set_state (this_vlib_main,
					    odp_packet_input_node.index,
					    VLIB_NODE_STATE_POLLING);
		       }));
  return 0;
}

int
odp_worker_thread_disable ()
{
  foreach_vlib_main ((
		       {
		       vlib_node_set_state (this_vlib_main,
					    odp_packet_input_node.index,
					    VLIB_NODE_STATE_DISABLED);
		       }));

  return 0;
}

u32
odp_packet_create_if (vlib_main_t * vm, u8 * host_if_name, u8 * hw_addr_set,
		      u32 * sw_if_index, u32 mode)
{
  odp_packet_main_t *om = odp_packet_main;
  int ret = 0;
  odp_packet_if_t *oif = 0;
  u8 hw_addr[6];
  clib_error_t *error = 0;
  vnet_sw_interface_t *sw;
  vnet_main_t *vnm = vnet_get_main ();
  uword *p;
  u8 *host_if_name_dup = vec_dup (host_if_name);
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  p = mhash_get (&om->if_index_by_host_if_name, host_if_name);
  if (p)
    return VNET_API_ERROR_SUBIF_ALREADY_EXISTS;

  pool_get (om->interfaces, oif);
  oif->if_index = oif - om->interfaces;
  oif->host_if_name = host_if_name_dup;
  oif->per_interface_next_index = ~0;

  /* Create a pktio instance */
  oif->pktio = create_pktio ((char *) host_if_name, om->pool, mode);
  oif->mode = mode;
  om->if_count++;

  if (tm->n_vlib_mains > 1)
    {
      oif->lockp = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					   CLIB_CACHE_LINE_BYTES);
      memset ((void *) oif->lockp, 0, CLIB_CACHE_LINE_BYTES);
    }

  /*use configured or generate random MAC address */
  if (hw_addr_set)
    clib_memcpy (hw_addr, hw_addr_set, 6);
  else
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      clib_memcpy (hw_addr + 2, &rnd, sizeof (rnd));
      hw_addr[0] = 2;
      hw_addr[1] = 0xfe;
    }

  error = ethernet_register_interface (vnm, odp_packet_device_class.index,
				       oif->if_index, hw_addr,
				       &oif->hw_if_index,
				       odp_packet_eth_flag_change);

  if (error)
    {
      memset (oif, 0, sizeof (*oif));
      pool_put (om->interfaces, oif);
      clib_error_report (error);
      ret = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto error;
    }

  sw = vnet_get_hw_sw_interface (vnm, oif->hw_if_index);
  oif->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_set_flags (vnm, oif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  mhash_set_mem (&om->if_index_by_host_if_name, host_if_name_dup,
		 &oif->if_index, 0);
  if (sw_if_index)
    *sw_if_index = oif->sw_if_index;

  if (tm->n_vlib_mains > 1 && pool_elts (om->interfaces) == 1)
    {
      /*Fixme :Workers support commented for now as vlib_buffer not thread safe */
      //odp_worker_thread_enable ();
    }
  else
    {
      vlib_node_set_state (vm, odp_packet_input_node.index,
			   VLIB_NODE_STATE_POLLING);
    }
  return 0;

error:
  vec_free (host_if_name_dup);

  return ret;
}

u32
odp_packet_delete_if (vlib_main_t * vm, u8 * host_if_name)
{
  vnet_main_t *vnm = vnet_get_main ();
  odp_packet_main_t *om = odp_packet_main;
  odp_packet_if_t *oif = 0;
  uword *p;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  p = mhash_get (&om->if_index_by_host_if_name, host_if_name);

  if (p == NULL)
    {
      clib_warning ("Host interface %s does not exist", host_if_name);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  oif = pool_elt_at_index (om->interfaces, p[0]);
  vnet_hw_interface_set_flags (vnm, oif->hw_if_index, 0);

  om->if_count--;

  odp_pktio_stop (odp_pktio_lookup ((char *) host_if_name));
  odp_pktio_close (odp_pktio_lookup ((char *) host_if_name));

  vec_free (oif->host_if_name);
  oif->host_if_name = NULL;

  mhash_unset (&om->if_index_by_host_if_name, host_if_name, &oif->if_index);
  ethernet_delete_interface (vnm, oif->hw_if_index);

  pool_put (om->interfaces, oif);

  if (tm->n_vlib_mains > 1 && pool_elts (om->interfaces) == 0)
    {
      odp_pool_destroy (om->pool);
      /*Fixme :Workers support commented for now */
      // odp_worker_thread_disable ();
    }

  return 0;

}

static clib_error_t *
odp_packet_init (vlib_main_t * vm)
{
  odp_packet_main_t *om;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_thread_registration_t *tr;
  vlib_physmem_main_t *vpm = &vm->physmem_main;
  uword *p;
  odp_platform_init_t platform_params;
  odp_pool_param_t params;
  odp_pool_capability_t capa;
  odp_shm_t shm;
  odp_instance_t instance;

  memset (&platform_params, 0, sizeof (platform_params));
  platform_params.memory = 100;

  if (odp_init_global (&instance, NULL, &platform_params))
    clib_warning ("Error:ODP global init failed");

  if (odp_init_local (instance, ODP_THREAD_CONTROL) != 0)
    {
      clib_warning ("Error: ODP local init failed");
      odp_term_global (instance);

    }

  shm = odp_shm_reserve ("odp_packet_main", sizeof (odp_packet_main_t),
			 ODP_CACHE_LINE_SIZE, 0);
  odp_packet_main = odp_shm_addr (shm);
  if (odp_packet_main == NULL)
    {
      return clib_error_return (0, "Failed to initialize odp_packet");
    }

  om = odp_packet_main;
  memset (om, 0, sizeof (odp_packet_main_t));
  om->input_cpu_first_index = 0;
  om->input_cpu_count = 1;
  om->if_count = 0;
  om->instance = instance;

  odp_pool_capability (&capa);
  if (capa.pkt.min_headroom != VLIB_BUFFER_PRE_DATA_SIZE)
    {
      return clib_error_return (0,
				"Packet Headroom for VPP and ODP must be equal");
    }

  /* Create packet pool */
  odp_pool_param_init (&params);
  params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
  params.pkt.len = SHM_PKT_POOL_BUF_SIZE;
  params.type = ODP_POOL_PACKET;
  params.pkt.num = SHM_PKT_POOL_NB_PKTS;
  params.pkt.uarea_size = sizeof (vlib_buffer_t) - VLIB_BUFFER_PRE_DATA_SIZE;

  om->pool = odp_pool_create (SHM_PKT_POOL_NAME, &params);

  if (om->pool == ODP_POOL_INVALID)
    {
      return clib_error_return (0, "Packet pool create failed");
    }

  /* find out which cpus will be used for input */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  tr = p ? (vlib_thread_registration_t *) p[0] : 0;

  if (tr && tr->count > 0)
    {
      om->input_cpu_first_index = tr->first_index;
      om->input_cpu_count = tr->count;
    }

  mhash_init_vec_string (&om->if_index_by_host_if_name, sizeof (uword));

  vpm->virtual.start = params.pool_start;
  vpm->virtual.end = params.pool_end;
  vpm->virtual.size = params.pool_size;

  return 0;
}

VLIB_INIT_FUNCTION (odp_packet_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "ODP",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
