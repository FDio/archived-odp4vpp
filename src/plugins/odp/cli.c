/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <fcntl.h>		/* for open */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>		/* for iovec */
#include <netinet/in.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <odp/odp_packet.h>

static clib_error_t *
odp_packet_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *host_if_name = NULL;
  u8 hwaddr[6];
  u8 *hw_addr_ptr = 0;
  u32 sw_if_index;
  u32 mode = APPL_MODE_PKT_BURST;
  u32 rx_queues = 0;
  int r;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &host_if_name))
	;
      else
	if (unformat
	    (line_input, "hw-addr %U", unformat_ethernet_address, hwaddr))
	hw_addr_ptr = hwaddr;
      else if (unformat (line_input, "mode %d", &mode))
	;
      else if (unformat (line_input, "rx-queues %d", &rx_queues))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (host_if_name == NULL)
    return clib_error_return (0, "missing host interface name");

  r = odp_packet_create_if (vm, host_if_name, hw_addr_ptr, &sw_if_index,
			    mode, rx_queues);
  vec_free (host_if_name);

  if (r == VNET_API_ERROR_SYSCALL_ERROR_1)
    return clib_error_return (0, "%s (errno %d)", strerror (errno), errno);

  if (r == VNET_API_ERROR_INVALID_INTERFACE)
    return clib_error_return (0, "Invalid interface name");

  if (r == VNET_API_ERROR_SUBIF_ALREADY_EXISTS)
    return clib_error_return (0, "Interface elready exists");

  vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name, vnet_get_main (),
		   sw_if_index);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (odp_packet_create_command, static) = {
  .path = "create pktio-interface",
  .short_help = "create pktio-interface name <interface name> [hw-addr <mac>]",
  .function = odp_packet_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
odp_packet_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *host_if_name = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &host_if_name))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);


  if (host_if_name == NULL)
    return clib_error_return (0, "missing host interface name");


  odp_packet_delete_if (vm, host_if_name);
  vec_free (host_if_name);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (odp_packet_delete_command, static) = {
  .path = "delete pktio-interface",
  .short_help = "delete pktio-interface name <interface name>",
  .function = odp_packet_delete_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
odp_packet_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (odp_packet_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
