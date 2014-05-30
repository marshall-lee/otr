
#include <ruby.h>
#include <gcrypt.h>
#include <libotr/proto.h>
#include <libotr/privkey.h>

#include "otr.h"

void Init_otr() {
  // gcry_check_version (GCRYPT_VERSION);
  // gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  OTRL_INIT;

  init_user_state();
  init_priv_key();
  init_client();
}