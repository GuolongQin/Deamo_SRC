#include "p11_session_management.h"
//Session Management functions
CK_RV DC_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
    return CKR_OK;
}
CK_RV DC_CloseSession(CK_SESSION_HANDLE hSession) {
    return CKR_OK;
}
CK_RV DC_CloseAllSessions(CK_SLOT_ID slotID) {
    return CKR_OK;
}
CK_RV DC_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
    return CKR_OK;
}
CK_RV DC_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
    return CKR_OK;
}
CK_RV DC_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
    return CKR_OK;
}
CK_RV DC_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    return CKR_OK;
}
CK_RV DC_Logout(CK_SESSION_HANDLE hSession) {
    return CKR_OK;
}
