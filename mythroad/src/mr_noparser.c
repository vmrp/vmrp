
#include "./h/mr_lex.h"
#include "./h/mr_parser.h"
#include "./h/mr_zio.h"

void mr_X_init (mrp_State *L) {
  UNUSED(L);
}

Proto *mr_Y_parser (mrp_State *L, ZIO *z, Mbuffer *buff) {
  UNUSED(z);
  UNUSED(buff);
  mrp_pushstring(L,"parser not loaded");
  mrp_error(L);
  return NULL;
}
