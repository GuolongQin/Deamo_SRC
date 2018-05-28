#ifndef P11_GENERALPURPOSE_H
#define P11_GENERALPURPOSE_H
#include "pkcs.h"
#include "pkcs_define.h"

//General Purpose Functions
CK_RV DC_Initialize(CK_VOID_PTR pInitArgs);
CK_RV DC_Finalize(CK_VOID_PTR pReserved);
CK_RV DC_GetInfo(CK_INFO_PTR pInfo);

#endif // P11_GENERALPURPOSE_H
