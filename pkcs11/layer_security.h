#ifndef _LAYER_SECURITY_H_
#define _LAYER_SECURITY_H_
#include "pkcs/pkcs.h"
#include "layer_trans.h"

#define CKR_EVENT_INFO      0x00
#define CKR_EVENT_WARN      0x01
#define CKR_EVENT_ERROR     0x02

uint32_t layer_security_init(CK_NOTIFY* arg_notify);
uint32_t layer_security_final();
//Security Layer
CK_RV DC_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
#endif // !_LAYER_SECURITY_H_

