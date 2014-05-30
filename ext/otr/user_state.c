
#include <ruby.h>
#include <ruby/thread.h>
#include <libotr/proto.h>
#include <libotr/privkey.h>

#include "otr.h"

static VALUE user_state_allocate(VALUE klass);
static void user_state_deallocate(void * data);

static VALUE generate_privkey(int argc, VALUE* argv, VALUE self);
static void* generate_privkey_background(void* data);
static void generate_privkey_cancel(void* data);

static VALUE read_keys(VALUE self, VALUE file);
static void* read_keys_background(void* data);

static VALUE user_state_allocate(VALUE klass) {
  OtrlUserState us;

  us = otrl_userstate_create();
  return Data_Wrap_Struct(klass, NULL, user_state_deallocate, us);
}

static void user_state_deallocate(void * data) {
  OtrlUserState us = data;

  otrl_userstate_free(us);
}

static VALUE generate_privkey(int argc, VALUE* argv, VALUE self) {
  VALUE accountname, protocol, file;
  OtrlUserState us;
  void *newkey;
  void *args_cancel[2];
  int fd;
  FILE* fp;
  gcry_error_t err;

  if (argc < 2 || argc > 3) {
    rb_raise(rb_eArgError, "wrong number of arguments");
  }

  accountname = argv[0];
  protocol = argv[1];

  Check_Type(accountname, T_STRING);
  Check_Type(protocol, T_STRING);

  if (argc == 3) {
    file = argv[2];
  } else {
    file = rb_funcall(self, rb_intern("keyfile"), 0);
  }

  if (!rb_obj_is_instance_of(file, rb_cFile) && !rb_obj_is_instance_of(file, rb_cString)) {
    rb_raise(rb_eTypeError, "file argument must be File or String");
  }

  Data_Get_Struct(self, struct s_OtrlUserState, us);

  err = otrl_privkey_generate_start(us,
    RSTRING_PTR(accountname),
    RSTRING_PTR(protocol),
    &newkey);
  if (err) {
    RAISE_GPG_ERROR(err);
  }

  args_cancel[0] = us;
  args_cancel[1] = newkey;

  err = rb_thread_call_without_gvl(generate_privkey_background,
    newkey,
    generate_privkey_cancel,
    args_cancel);
  if (err) {
    RAISE_GPG_ERROR(err);
  }

  if (rb_obj_is_instance_of(file, rb_cFile)) {
    fd = FIX2INT(rb_funcall(file, rb_intern("fileno"), 0));
    fp = fdopen(dup(fd), "wb+");
    err = otrl_privkey_generate_finish_FILEp(us,
      newkey,
      fp);
    fclose(fp);
  } else if (rb_obj_is_instance_of(file, rb_cString)) {
    err = otrl_privkey_generate_finish(us,
      newkey,
      RSTRING_PTR(file));
  }
  if (err) {
    RAISE_GPG_ERROR(err);
  }

  return Qnil;
}

static void* generate_privkey_background(void* data) {
  void *newkey = data;

  return otrl_privkey_generate_calculate(newkey);
}

static void generate_privkey_cancel(void* data) {
  void **args_cancel = data;
  OtrlUserState us = args_cancel[0];
  void* newkey = args_cancel[1];

  otrl_privkey_generate_cancelled(us, newkey);
}

static VALUE read_keys(VALUE self, VALUE file) {
  gcry_error_t err;
  VALUE args_bg[2];

  if (!rb_obj_is_instance_of(file, rb_cFile) && !rb_obj_is_instance_of(file, rb_cString)) {
    rb_raise(rb_eTypeError, "file argument must be File or String");
  }

  args_bg[0] = self;
  args_bg[1] = file;

  err = rb_thread_call_without_gvl(read_keys_background,
    &args_bg,
    RUBY_UBF_IO,
    0);

  if (err) {
    RAISE_GPG_ERROR(err);
  }

  return Qnil;
}

static void* read_keys_background(void* data) {
  VALUE* argv = data;
  VALUE self = argv[0], file = argv[1];
  gcry_error_t err;
  OtrlUserState us;
  int fd;
  FILE* fp;

  Data_Get_Struct(self, struct s_OtrlUserState, us);

  if (rb_obj_is_instance_of(file, rb_cFile)) {
    fd = FIX2INT(rb_funcall(file, rb_intern("fileno"), 0));
    fp = fdopen(dup(fd), "rb");
    err = otrl_privkey_read_FILEp(us, fp);
    fclose(fp);
  } else if (rb_obj_is_instance_of(file, rb_cString)) {
    err = otrl_privkey_read(us, RSTRING_PTR(file));
  }

  return err;
}

static VALUE forget_all(VALUE self) {
  OtrlUserState us;

  Data_Get_Struct(self, struct s_OtrlUserState, us);
  otrl_privkey_forget_all(us);
  return Qnil;
}

void init_user_state() {
  VALUE mOTR, cUserState;

  mOTR = rb_const_get(rb_cObject, rb_intern("OTR"));

  cUserState = rb_const_get(mOTR, rb_intern("UserState"));
  rb_define_alloc_func(cUserState, user_state_allocate);
  rb_define_method(cUserState, "generate_privkey", generate_privkey, -1);
  rb_define_method(cUserState, "read_keys", read_keys, 1);
  rb_define_method(cUserState, "forget_all!", forget_all, 0);
}