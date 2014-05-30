
#include <ruby.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include "otr.h"

static OtrlMessageAppOps g_ops;

static OtrlPolicy op_policy(void *opdata, ConnContext *context) {
  VALUE self = *(VALUE*)opdata;
  VALUE contact;
  VALUE policy;
  ID policy_id;

  contact = rb_funcall(self,
    rb_intern("find_contact"),
    2,
    rb_str_new2(context->accountname),
    rb_str_new2(context->username));

  if (!RTEST(contact)) {
    rb_raise(rb_eRuntimeError, "couldn't find contact \"%s\"", context->username);
  }

  policy = rb_funcall(contact, rb_intern("policy"), 0);
  policy_id = SYM2ID(policy);

  if (policy_id == rb_intern("never"))
    return OTRL_POLICY_NEVER;
  if (policy_id == rb_intern("opportunistic"))
    return OTRL_POLICY_OPPORTUNISTIC;
  if (policy_id == rb_intern("manual"))
    return OTRL_POLICY_MANUAL;
  if (policy_id == rb_intern("always"))
    return OTRL_POLICY_ALWAYS;

  return OTRL_POLICY_DEFAULT; // TODO: deal with it
}

static void op_create_privkey(void *opdata, const char *accountname,
  const char *protocol) {
  VALUE self = *(VALUE*)opdata;
  VALUE user_state = rb_iv_get(self, "@user_state");

  rb_funcall(user_state,
    rb_intern("generate_privkey"),
    2,
    rb_str_new2(accountname),
    rb_str_new2(protocol));
}

static int op_is_logged_in(void *opdata, const char *accountname,
  const char *protocol, const char *recipient) {
  VALUE self = *(VALUE*)opdata;
  VALUE contact;

  contact = rb_funcall(self,
    rb_intern("find_contact"),
    2,
    rb_str_new2(accountname),
    rb_str_new2(recipient));

  return RTEST(rb_funcall(contact, rb_intern("logged_in?"), 0));
}

static void op_inject_message(void *opdata, const char *accountname,
  const char *protocol, const char *recipient, const char *message) {
  VALUE self = *(VALUE*)opdata;

  rb_funcall(self,
    rb_intern("do_inject"),
    3,
    rb_str_new2(accountname),
    rb_str_new2(recipient),
    rb_str_new2(message));
}

static void op_update_context_list(void *opdata) {
  // VALUE self = *(VALUE*)opdata;
  // TODO: manage context list
}

static void op_new_fingerprint(void *opdata, OtrlUserState us,
  const char *accountname, const char *protocol,
  const char *username, unsigned char fingerprint[20]) {
  // VALUE self = *(VALUE*)opdata;
  // TODO: manage fingerprint list
}

static void op_write_fingerprints(void *opdata) {
  // VALUE self = *(VALUE*)opdata;
  // TODO: write to disk by calling otrl_privkey_write_fingerprints with gvl unlock
}

static void op_still_secure(void *opdata, ConnContext *context, int is_reply) {
  // VALUE self = *(VALUE*)opdata;
  // TODO: dunno
}

static int op_max_message_size(void *opdata, ConnContext *context) {
  VALUE self = *(VALUE*)opdata;
  int ret = FIX2INT(rb_funcall(self, rb_intern("max_message_size"), 0));
  return ret;
}

// static void op_received_symkey(void *opdata, ConnContext *context,
//   unsigned int use, const unsigned char *usedata,
//   size_t usedatalen, const unsigned char *symkey) {}

static const char *op_otr_error_message(void *opdata, ConnContext *context,
  OtrlErrorCode err_code) {
  char* err_msg = malloc(64);
  switch (err_code) {
    case OTRL_ERRCODE_NONE:
    sprintf(err_msg, "%s", "OTRL_ERRCODE_NONE");
    break;
    case OTRL_ERRCODE_ENCRYPTION_ERROR:
    sprintf(err_msg, "%s", "OTRL_ERRCODE_ENCRYPTION_ERROR");
    break;
    case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
    sprintf(err_msg, "%s", "OTRL_ERRCODE_MSG_NOT_IN_PRIVATE");
    break;
    case OTRL_ERRCODE_MSG_UNREADABLE:
    sprintf(err_msg, "%s", "OTRL_ERRCODE_MSG_UNREADABLE");
    break;
    case OTRL_ERRCODE_MSG_MALFORMED:
    sprintf(err_msg, "%s", "OTRL_ERRCODE_MSG_MALFORMED");
    break;
  }
  return err_msg;
}

static void op_otr_error_message_free(void *opdata, const char *err_msg) {
  free((void*)err_msg);
}

static const char *op_resent_msg_prefix(void *opdata, ConnContext *context) {
  VALUE self = *(VALUE*)opdata;
  char *str = NULL;
  VALUE prefix = rb_funcall(self, rb_intern("resent_msg_prefix"), 0);
  if (RTEST(prefix)) {
    Check_Type(prefix, T_STRING);
    str = strdup(RSTRING_PTR(prefix));
  }
  return str;
}

static void op_resent_msg_prefix_free(void *opdata, const char *prefix) {
  free((void*)prefix);
}

// static void op_handle_smp_event(void *opdata, OtrlSMPEvent smp_event,
//   ConnContext *context, unsigned short progress_percent,
//   char *question) {}

// static void op_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
//   ConnContext *context, const char *message,
//   gcry_error_t err) {}

static void op_create_instag(void *opdata, const char *accountname,
  const char *protocol) {

  VALUE user_state, self = *(VALUE*)opdata;
  OtrlUserState us;

  user_state = rb_iv_get(self, "@user_state");
  Data_Get_Struct(user_state, struct s_OtrlUserState, us);
  otrl_instag_generate(us,
    RSTRING_PTR(rb_funcall(user_state, rb_intern("instagfile"),0)),
    accountname,
    protocol);
}

// static void op_convert_msg(void *opdata, ConnContext *context,
//   OtrlConvertType convert_type, char ** dest, const char *src) {}

// static void op_convert_free(void *opdata, ConnContext *context, char *dest) {}

// static void op_timer_control(void *opdata, unsigned int interval) {}

static VALUE make_context(VALUE client, ConnContext *pcontext) {
  VALUE mOTR, cContext;
  VALUE account, contact;
  VALUE argv[4];

  if (pcontext) {
    mOTR = rb_const_get(rb_cObject, rb_intern("OTR"));
    cContext = rb_const_get_at(mOTR, rb_intern("Context"));

    account = rb_funcall(client, rb_intern("find_account"), 1, rb_str_new2(pcontext->accountname));
    contact = rb_funcall(account, rb_intern("find_contact"), 1, rb_str_new2(pcontext->username));

    argv[0] = account;
    argv[1] = contact;
    argv[2] = INT2NUM(pcontext->our_instance);
    argv[3] = INT2NUM(pcontext->their_instance);

    return rb_class_new_instance(4, argv, cContext);
  } else {
    return Qnil;
  }
}

static VALUE internal_send_message(VALUE self, VALUE account_name, VALUE recipient_name,
  VALUE message, VALUE instance, VALUE frag_policy) {

  VALUE user_state, protocol;
  OtrlUserState us;
  char *cmessage, *cmessage_new = NULL;
  ConnContext *pcontext;
  gcry_error_t err;
  VALUE context;
  VALUE ret = Qnil;

  user_state = rb_iv_get(self, "@user_state");
  Data_Get_Struct(user_state, struct s_OtrlUserState, us);

  protocol = rb_iv_get(self, "@protocol");

  cmessage = RSTRING_PTR(message);

  err = otrl_message_sending(us,
    &g_ops,
    &self,
    RSTRING_PTR(account_name),
    RSTRING_PTR(protocol),
    RSTRING_PTR(recipient_name),
    FIX2INT(instance),
    cmessage,
    0, // TODO: tlvs??
    &cmessage_new,
    FIX2INT(frag_policy),
    &pcontext,
    0,
    0);

  if (err) {
    RAISE_GPG_ERROR(err);
  }

  if (cmessage_new) {
    cmessage = cmessage_new;
  }

  context = make_context(self, pcontext);
  message = rb_str_new2(cmessage);
  ret = rb_ary_new3(2, message, context);

  if (cmessage_new) {
    otrl_message_free(cmessage_new);
  }

  return ret;
}

static VALUE internal_receive_message(VALUE self, VALUE account_name, VALUE
  sender_name, VALUE message) {

  VALUE user_state, protocol;
  OtrlUserState us;
  char *cmessage, *cmessage_new = NULL;
  OtrlTLV* tlvs = NULL;
  ConnContext* pcontext;
  int result;
  VALUE context;
  VALUE ret = Qnil;
  
  user_state = rb_iv_get(self, "@user_state");
  Data_Get_Struct(user_state, struct s_OtrlUserState, us);

  protocol = rb_iv_get(self, "@protocol");

  cmessage = RSTRING_PTR(message);

  result = otrl_message_receiving(us,
    &g_ops,
    &self,
    RSTRING_PTR(account_name),
    RSTRING_PTR(protocol),
    RSTRING_PTR(sender_name),
    cmessage,
    &cmessage_new,
    0, //&tlvs,
    &pcontext,
    NULL,
    NULL);

  if (result == 0) {
    if (cmessage_new) {
      cmessage = cmessage_new;
    }
    context = make_context(self, pcontext);
    message = rb_str_new2(cmessage);
    ret = rb_ary_new3(2, message, context);
  }

  if (tlvs) {
    otrl_tlv_free(tlvs);
  }

  if (cmessage_new) {
    otrl_message_free(cmessage_new);
  }

  return ret;
}

void init_client() {
  VALUE mOTR, cClient;
  VALUE meta_instances, frag_policies_table;

  mOTR = rb_const_get(rb_cObject, rb_intern("OTR"));

  cClient = rb_const_get(mOTR, rb_intern("Client"));

  meta_instances = rb_hash_new();
  rb_hash_aset(meta_instances, ID2SYM(rb_intern("master")), INT2FIX(OTRL_INSTAG_MASTER));
  rb_hash_aset(meta_instances, ID2SYM(rb_intern("best")), INT2FIX(OTRL_INSTAG_BEST));
  rb_hash_aset(meta_instances, ID2SYM(rb_intern("recent")), INT2FIX(OTRL_INSTAG_RECENT));
  rb_hash_aset(meta_instances, ID2SYM(rb_intern("recent_received")), INT2FIX(OTRL_INSTAG_RECENT_RECEIVED));
  rb_hash_aset(meta_instances, ID2SYM(rb_intern("recent_sent")), INT2FIX(OTRL_INSTAG_RECENT_SENT));
  rb_define_class_variable(cClient, "@@meta_instances", meta_instances);

  frag_policies_table = rb_hash_new();
  rb_hash_aset(frag_policies_table, ID2SYM(rb_intern("send_skip")), INT2FIX(OTRL_FRAGMENT_SEND_SKIP));
  rb_hash_aset(frag_policies_table, ID2SYM(rb_intern("send_all")), INT2FIX(OTRL_FRAGMENT_SEND_ALL));
  rb_hash_aset(frag_policies_table, ID2SYM(rb_intern("send_all_but_first")), INT2FIX(OTRL_FRAGMENT_SEND_ALL_BUT_FIRST));
  rb_hash_aset(frag_policies_table, ID2SYM(rb_intern("send_all_but_last")), INT2FIX(OTRL_FRAGMENT_SEND_ALL_BUT_LAST));
  rb_define_class_variable(cClient, "@@frag_policies_table", frag_policies_table);

  rb_define_private_method(cClient, "internal_send_message", internal_send_message, 5);
  rb_define_private_method(cClient, "internal_receive_message", internal_receive_message, 3);

  memset(&g_ops, 0, sizeof(OtrlMessageAppOps));
  g_ops.policy = op_policy;
  g_ops.create_privkey = op_create_privkey;
  g_ops.is_logged_in = op_is_logged_in;
  g_ops.inject_message = op_inject_message;
  g_ops.update_context_list = op_update_context_list;
  g_ops.new_fingerprint = op_new_fingerprint;
  g_ops.write_fingerprints = op_write_fingerprints;
  g_ops.still_secure = op_still_secure;
  g_ops.max_message_size = op_max_message_size;
  g_ops.otr_error_message = op_otr_error_message;
  g_ops.otr_error_message_free = op_otr_error_message_free;
  // g_ops.resent_msg_prefix = op_resent_msg_prefix;
  // g_ops.resent_msg_prefix_free = op_resent_msg_prefix_free;
  g_ops.create_instag = op_create_instag;
}
