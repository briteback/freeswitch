#include <switch.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_lynes_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_lynes_load);

SWITCH_MODULE_DEFINITION(mod_lynes, mod_lynes_load, mod_lynes_shutdown, NULL);

static struct {
  switch_memory_pool_t *pool;
  switch_hash_t *lynes_pickup_hash;
  switch_mutex_t *lynes_pickup_mutex;
} globals;

typedef struct lynes_pickup_node_s {
  char *key;
  char *uuid;
  struct lynes_pickup_node_s *next;
} lynes_pickup_node_t;

static void lynes_pickup_add_session(switch_core_session_t *session, const char *key)
{
  lynes_pickup_node_t *head, *node, *np;
  char *dup_key = NULL;

  if (!strchr(key, '@')) {
    dup_key = switch_mprintf("%s@%s", key, switch_core_get_domain(SWITCH_FALSE));
    key = dup_key;
  }

  switch_zmalloc(node, sizeof(*node));
  switch_assert(node);
  node->key = strdup(key);
  node->uuid = strdup(switch_core_session_get_uuid(session));
  node->next = NULL;

  switch_mutex_lock(globals.lynes_pickup_mutex);
  head = switch_core_hash_find(globals.lynes_pickup_hash, key);

  if (head) {
    for (np = head; np && np->next; np = np->next);
    np->next = node;
  } else {
    head = node;
    switch_core_hash_insert(globals.lynes_pickup_hash, key, head);
  }

  switch_mutex_unlock(globals.lynes_pickup_mutex);

  switch_safe_free(dup_key);
}

static char *lynes_pickup_pop_uuid(const char *key, const char *uuid)
{
  lynes_pickup_node_t *node = NULL, *head;
  char *r = NULL;
  char *dup_key = NULL;

  if (!strchr(key, '@')) {
    dup_key = switch_mprintf("%s@%s", key, switch_core_get_domain(SWITCH_FALSE));
    key = dup_key;
  }

  switch_mutex_lock(globals.lynes_pickup_mutex);

  if ((head = switch_core_hash_find(globals.lynes_pickup_hash, key))) {

    switch_core_hash_delete(globals.lynes_pickup_hash, key);

    if (uuid) {
      lynes_pickup_node_t *np, *lp = NULL;

      for(np = head; np; np = np->next) {
        if (!strcmp(np->uuid, uuid)) {
          if (lp) {
            lp->next = np->next;
          } else {
            head = np->next;
          }

          node = np;
          break;
        }

        lp = np;
      }

    } else {
      node = head;
      head = head->next;
    }


    if (head) {
      switch_core_hash_insert(globals.lynes_pickup_hash, key, head);
    }
  }

  if (node) {
    r = node->uuid;
    free(node->key);
    free(node);
  }

  switch_mutex_unlock(globals.lynes_pickup_mutex);

  switch_safe_free(dup_key);

  return r;
}


typedef struct lynes_pickup_pvt_s {
  char *key;
  switch_event_t *vars;
} lynes_pickup_pvt_t;

static switch_status_t lynes_pickup_event_handler(switch_core_session_t *session)
{
  switch_channel_t *channel = switch_core_session_get_channel(session);
  switch_channel_state_t state = switch_channel_get_running_state(channel);
  lynes_pickup_pvt_t *tech_pvt = switch_core_session_get_private(session);
  char *uuid = NULL;

  switch(state) {
  case CS_DESTROY:
    if (tech_pvt->vars) {
      switch_event_destroy(&tech_pvt->vars);
    }
    break;
  case CS_REPORTING:
    if (switch_channel_get_cause(channel) == SWITCH_CAUSE_PICKED_OFF) {
      return SWITCH_STATUS_FALSE;
    }
    break;
  case CS_HANGUP:
    {
      if (switch_channel_test_flag(channel, CF_CHANNEL_SWAP)) {
        const char *key = switch_channel_get_variable(channel, "channel_swap_uuid");
        switch_core_session_t *swap_session;

        if ((swap_session = switch_core_session_locate(key))) {
          switch_channel_t *swap_channel = switch_core_session_get_channel(swap_session);
          switch_channel_hangup(swap_channel, SWITCH_CAUSE_PICKED_OFF);
          switch_core_session_rwunlock(swap_session);
        }
        switch_channel_clear_flag(channel, CF_CHANNEL_SWAP);
      }

      uuid = lynes_pickup_pop_uuid(tech_pvt->key, switch_core_session_get_uuid(session));
      switch_safe_free(uuid);
    }
    break;
  default:
    break;
  }


  return SWITCH_STATUS_SUCCESS;
}

switch_state_handler_table_t lynes_pickup_event_handlers = {
  /*.on_init */ lynes_pickup_event_handler,
  /*.on_routing */ lynes_pickup_event_handler,
  /*.on_execute */ lynes_pickup_event_handler,
  /*.on_hangup */ lynes_pickup_event_handler,
  /*.on_exchange_media */ lynes_pickup_event_handler,
  /*.on_soft_execute */ lynes_pickup_event_handler,
  /*.on_consume_media */ lynes_pickup_event_handler,
  /*.on_hibernate */ lynes_pickup_event_handler,
  /*.on_reset */ lynes_pickup_event_handler,
  /*.on_park */ lynes_pickup_event_handler,
  /*.on_reporting */ lynes_pickup_event_handler,
  /*.on_destroy */ lynes_pickup_event_handler
};

switch_endpoint_interface_t *lynes_pickup_endpoint_interface;

static switch_call_cause_t lynes_pickup_outgoing_channel(switch_core_session_t *session,
                           switch_event_t *var_event,
                           switch_caller_profile_t *outbound_profile,
                           switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags,
                           switch_call_cause_t *cancel_cause)
{
  char *lynes_pickup;
  switch_call_cause_t cause = SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
  switch_core_session_t *nsession;
  switch_channel_t *nchannel;
  char *name;
  lynes_pickup_pvt_t *tech_pvt;
  switch_caller_profile_t *caller_profile;

  if (zstr(outbound_profile->destination_number)) {
    goto done;
  }

  lynes_pickup = outbound_profile->destination_number;

  flags |= SOF_NO_LIMITS;

  if (!(nsession = switch_core_session_request_uuid(lynes_pickup_endpoint_interface, SWITCH_CALL_DIRECTION_OUTBOUND,
                                                      flags, pool, switch_event_get_header(var_event, "origination_uuid")))) {

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error Creating Session\n");
    goto error;
  }

  tech_pvt = switch_core_session_alloc(nsession, sizeof(*tech_pvt));
  tech_pvt->key = switch_core_session_strdup(nsession, lynes_pickup);


  switch_core_session_set_private(nsession, tech_pvt);

  nchannel = switch_core_session_get_channel(nsession);
  switch_channel_set_cap(nchannel, CC_PROXY_MEDIA);
  switch_channel_set_cap(nchannel, CC_BYPASS_MEDIA);

  caller_profile = switch_caller_profile_clone(nsession, outbound_profile);
  switch_channel_set_caller_profile(nchannel, caller_profile);

  switch_channel_set_state(nchannel, CS_ROUTING);



  *new_session = nsession;
  cause = SWITCH_CAUSE_SUCCESS;
  name = switch_core_session_sprintf(nsession, "lynes_pickup/%s", lynes_pickup);
  switch_channel_set_name(nchannel, name);
  switch_channel_set_variable(nchannel, "presence_id", NULL);

  switch_event_del_header(var_event, "presence_id");

  lynes_pickup_add_session(nsession, lynes_pickup);
  switch_channel_set_flag(nchannel, CF_PICKUP);
  switch_channel_set_flag(nchannel, CF_NO_PRESENCE);

  switch_event_dup(&tech_pvt->vars, var_event);

  goto done;

  error:

  if (pool) {
    *pool = NULL;
  }

  done:


  return cause;
}

#define LYNES_PICKUP_SYNTAX "[<key>]"
SWITCH_STANDARD_APP(lynes_pickup_function)
{
  char *uuid = NULL;
  switch_core_session_t *lynes_pickup_session;
  switch_channel_t *channel = switch_core_session_get_channel(session);

  if (zstr(data)) {
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Missing data.  Usage: lynes_pickup %s\n", LYNES_PICKUP_SYNTAX);
    return;
  }

  if ((uuid = lynes_pickup_pop_uuid((char *)data, NULL))) {
    if ((lynes_pickup_session = switch_core_session_locate(uuid))) {
      switch_channel_t *lynes_pickup_channel = switch_core_session_get_channel(lynes_pickup_session);
      switch_caller_profile_t *lynes_pickup_caller_profile = switch_channel_get_caller_profile(lynes_pickup_channel),
        *caller_profile = switch_channel_get_caller_profile(channel);
      const char *name, *num;
      switch_event_t *event;
      switch_event_header_t *hp;
      lynes_pickup_pvt_t *tech_pvt = switch_core_session_get_private(lynes_pickup_session);

      for(hp = tech_pvt->vars->headers; hp; hp = hp->next) {
        switch_channel_set_variable(channel, hp->name, hp->value);
      }


      switch_channel_set_flag(lynes_pickup_channel, CF_CHANNEL_SWAP);
      switch_channel_set_variable(lynes_pickup_channel, "channel_swap_uuid", switch_core_session_get_uuid(session));

      name = caller_profile->caller_id_name;
      num = caller_profile->caller_id_number;

      caller_profile->caller_id_name = switch_core_strdup(caller_profile->pool, lynes_pickup_caller_profile->caller_id_name);
      caller_profile->caller_id_number = switch_core_strdup(caller_profile->pool, lynes_pickup_caller_profile->caller_id_number);

      caller_profile->callee_id_name = name;
      caller_profile->callee_id_number = num;

      if (switch_event_create(&event, SWITCH_EVENT_CALL_UPDATE) == SWITCH_STATUS_SUCCESS) {
        const char *partner_uuid = switch_channel_get_partner_uuid(channel);
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Direction", "RECV");

        if (partner_uuid) {
          switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Bridged-To", partner_uuid);
        }
        switch_channel_event_set_data(channel, event);
        switch_event_fire(&event);
      }


      switch_channel_set_state(channel, CS_HIBERNATE);

      switch_channel_mark_answered(lynes_pickup_channel);
      switch_core_session_rwunlock(lynes_pickup_session);
    }
    free(uuid);
  }
}

switch_io_routines_t lynes_pickup_io_routines = {
  /*.outgoing_channel */ lynes_pickup_outgoing_channel
};

#define LYNES_PICKUP_LONG_DESC "Swap places with a waiting lynes_pickup channel"

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_lynes_shutdown)
{
  switch_mutex_destroy(globals.lynes_pickup_mutex);
  switch_core_hash_destroy(&globals.lynes_pickup_hash);

  return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_lynes_load)
{
  switch_application_interface_t *app_interface;

  globals.pool = pool;
  switch_core_hash_init(&globals.lynes_pickup_hash);
  switch_mutex_init(&globals.lynes_pickup_mutex, SWITCH_MUTEX_NESTED, globals.pool);

  *module_interface = switch_loadable_module_create_module_interface(pool, modname);

  lynes_pickup_endpoint_interface = (switch_endpoint_interface_t *) switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
  lynes_pickup_endpoint_interface->interface_name = "lynes_pickup";
  lynes_pickup_endpoint_interface->io_routines = &lynes_pickup_io_routines;
  lynes_pickup_endpoint_interface->state_handler = &lynes_pickup_event_handlers;

  SWITCH_ADD_APP(app_interface, "lynes_pickup", "Answer a lynes_pickup", LYNES_PICKUP_LONG_DESC, lynes_pickup_function, LYNES_PICKUP_SYNTAX, SAF_SUPPORT_NOMEDIA);

  return SWITCH_STATUS_SUCCESS;
}
