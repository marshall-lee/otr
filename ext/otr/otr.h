
#ifndef OTR_H_
#define OTR_H_

void init_user_state();
void init_priv_key();
void init_client();

typedef struct s_priv_key {
  OtrlPrivKey* pkey;
  OtrlUserState us;
} PrivKey;

#define GPG_ERROR rb_const_get(rb_const_get(rb_cObject, rb_intern("OTR")), rb_intern("GPGError"))
#define RAISE_GPG_ERROR(err) rb_raise(GPG_ERROR, gcry_strerror(err))

#endif