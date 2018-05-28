#ifndef P11_SLOT_TOKEN_MANAGEMENT_H
#define P11_SLOT_TOKEN_MANAGEMENT_H
#include "pkcs.h"
#include "pkcs_define.h"

//Slot and token Management functions
CK_RV DC_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_INFO_PTR pSlotList, CK_ULONG_PTR pulCount);
CK_RV DC_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV DC_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV DC_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
CK_RV DC_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV DC_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
CK_RV DC_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
CK_RV DC_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV DC_SetPIN(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen);

#endif
