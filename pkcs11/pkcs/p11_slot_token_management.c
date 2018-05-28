#include "p11_slot_token_management.h"

//Slot and token Management functions
CK_RV DC_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_INFO_PTR pSlotList, CK_ULONG_PTR pulCount) {
    return CKR_OK;
}
CK_RV DC_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    return CKR_OK;
}
CK_RV DC_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    return CKR_OK;
}
CK_RV DC_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
    return CKR_OK;
}
CK_RV DC_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    return CKR_OK;
}
CK_RV DC_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    return CKR_OK;
}
CK_RV DC_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
    return CKR_OK;
}
CK_RV DC_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    return CKR_OK;
}

CK_RV DC_SetPIN(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen){
    return CKR_OK;
}
