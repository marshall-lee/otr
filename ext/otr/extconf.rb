require 'mkmf'
have_header 'libotr/proto.h'
have_library 'otr'
create_makefile 'otr/otr'