#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

#include <odp/ipsec/ipsec.h>
#include <odp/ipsec/esp.h>
#include <odp/odp_packet.h>

#include <assert.h>

#define foreach_odp_crypto_input_next \
	_(DROP, "error-drop") \
	_(ENCRYPT_POST, "odp-crypto-esp-encrypt-post") \
	_(DECRYPT_POST, "odp-crypto-esp-decrypt-post")

typedef enum
{
#define _(f, s) ODP_CRYPTO_INPUT_NEXT_##f,
  foreach_odp_crypto_input_next
#undef _
    ODP_CRYPTO_INPUT_N_NEXT,
} odp_crypto_input_next_t;

#define foreach_crypto_input_error \
_(DEQUE_COP, "Dequed crypto operations")

typedef enum
{
#define _(sym,str) CRYPTO_INPUT_ERROR_##sym,
  foreach_crypto_input_error
#undef _
} crypto_input_error_t;

static char *crypto_input_error_strings[] = {
#define _(sym,string) string,
  foreach_crypto_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  odp_packet_t pkt;
} odp_packet_crypto_trace_t;

static u8 *
format_odp_crypto_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, " odp-crypto-input ");

  return s;
}

static uword
odp_dequeue_cops (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * frame, odp_queue_t queue,
		  u32 next_node_index)
{
  u32 next_index = next_node_index, n_deq, n_cops, *to_next = 0;
  const int MAX_EVENTS = (1 << 8);
  odp_event_t events[MAX_EVENTS];

  n_deq = odp_queue_deq_multi (queue, events, MAX_EVENTS);

  n_cops = n_deq;

  int index = 0;
  while (n_cops > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_cops > 0 && n_left_to_next > 0)
	{
	  odp_event_t event = events[index++];

	  ASSERT (ODP_EVENT_CRYPTO_COMPL == odp_event_type (event));

	  odp_crypto_compl_t compl;
	  odp_crypto_op_result_t result;
	  odp_packet_t pkt;
	  vlib_buffer_t *b0;
	  u32 bi0;

	  compl = odp_crypto_compl_from_event (event);
	  odp_crypto_compl_result (compl, &result);
	  pkt = result.pkt;

	  b0 = vlib_buffer_from_odp_packet (pkt);
	  bi0 = vlib_get_buffer_index (vm, b0);

	  to_next[0] = bi0;
	  to_next += 1;

	  n_cops -= 1;
	  n_left_to_next -= 1;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      odp_packet_crypto_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next_node_index);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, odp_crypto_input_node.index,
			       CRYPTO_INPUT_ERROR_DEQUE_COP, n_deq);

  return n_deq;
}

static uword
odp_crypto_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  odp_crypto_main_t *ocm = &odp_crypto_main;
  u32 thread_index = vlib_get_thread_index ();
  odp_crypto_worker_main_t *cwm =
    vec_elt_at_index (ocm->workers, thread_index);
  u32 n_cops_dequeued = 0;
  n_cops_dequeued +=
    odp_dequeue_cops (vm, node, frame, cwm->post_encrypt,
		      ODP_CRYPTO_INPUT_NEXT_ENCRYPT_POST);
  n_cops_dequeued +=
    odp_dequeue_cops (vm, node, frame, cwm->post_decrypt,
		      ODP_CRYPTO_INPUT_NEXT_DECRYPT_POST);
  return n_cops_dequeued;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (odp_crypto_input_node) =
{
  .function = odp_crypto_input_node_fn,
  .name = "odp-crypto-input",
  .format_trace = format_odp_crypto_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .n_errors = ARRAY_LEN(crypto_input_error_strings),
  .error_strings = crypto_input_error_strings,

  .n_next_nodes = ODP_CRYPTO_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s, n) [ODP_CRYPTO_INPUT_NEXT_##s] = n,
	foreach_odp_crypto_input_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (odp_crypto_input_node,
			      odp_crypto_input_node_fn);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
