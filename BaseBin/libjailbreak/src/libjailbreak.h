#include "primitives.h"
#include "backend_contract.h"
#include "info.h"
#include "kernel.h"
#include "util.h"
#include "translation.h"
#include "trustcache.h"
#include "jbclient_xpc.h"
#include "stock_fixes.h"

int jbclient_initialize_primitives_internal(bool physrwPTE);
int jbclient_initialize_primitives(void);
