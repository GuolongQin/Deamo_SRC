#ifndef P11_STORE_H
#define P11_STORE_H
#include "pkcs.h"
#include "pkcs_define.h"


#define CKR_EVENT_INFO      0x00
#define CKR_EVENT_WARN      0x01
#define CKR_EVENT_ERROR     0x02

CK_FUNCTION_LIST function_list;
#ifdef Vendor_MODE
CK_NOTIFY notify;
#endif // Vendor_MODE

#endif
