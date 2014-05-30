
#include <ruby.h>
#include <libotr/privkey.h>

#include "otr.h"

static VALUE priv_key_allocate(VALUE klass);
static void priv_key_deallocate(void * data);

static VALUE priv_key_allocate(VALUE klass) {
  PrivKey *p_priv_key;

  p_priv_key = malloc(sizeof(PrivKey));
  return Data_Wrap_Struct(klass, NULL, priv_key_deallocate, p_priv_key);
}

static void priv_key_deallocate(void * data) {
  free(data);
}

static VALUE initialize(VALUE self, VALUE user_state, VALUE accountname, VALUE protocol) {
  PrivKey *p_priv_key;
  OtrlUserState* us;

  Check_Type(accountname, T_STRING);
  Check_Type(protocol, T_STRING);

  Data_Get_Struct(self, PrivKey, p_priv_key);
  Data_Get_Struct(user_state, OtrlUserState, us);

  p_priv_key->us = us;
  p_priv_key->pkey = otrl_privkey_find(us,
    RSTRING_PTR(accountname),
    RSTRING_PTR(protocol));
  if (!p_priv_key->pkey) {
    rb_raise(rb_eRuntimeError, "private key not found");
  }

  return self;
}

static VALUE fingerprint(VALUE self) {
  PrivKey *p_priv_key;
  char fingerprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

  Data_Get_Struct(self, PrivKey, p_priv_key);
  otrl_privkey_fingerprint(p_priv_key->us,
    fingerprint,
    p_priv_key->pkey->accountname,
    p_priv_key->pkey->protocol);

  return rb_str_new(fingerprint, OTRL_PRIVKEY_FPRINT_HUMAN_LEN);
}

static VALUE forget(VALUE self) {
  PrivKey *p_priv_key;

  Data_Get_Struct(self, PrivKey, p_priv_key);
  otrl_privkey_forget(p_priv_key->pkey);
  return Qnil;
}

void init_priv_key() {
  VALUE mOTR, cPrivKey;

  mOTR = rb_const_get(rb_cObject, rb_intern("OTR"));

  cPrivKey = rb_const_get(mOTR, rb_intern("PrivKey"));
  rb_define_alloc_func(cPrivKey, priv_key_allocate);
  rb_define_method(cPrivKey, "initialize", initialize, 3);
  rb_define_method(cPrivKey, "fingerprint", fingerprint, 0);
  rb_define_method(cPrivKey, "forget!", forget, 0);
}