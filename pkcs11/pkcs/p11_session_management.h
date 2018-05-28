#ifndef P11_SESSION_MANAGEMENT_H
#define P11_SESSION_MANAGEMENT_H
#include "pkcs.h"
#include "pkcs_define.h"
//Session Management functions
CK_RV DC_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV DC_CloseSession(CK_SESSION_HANDLE hSession);
CK_RV DC_CloseAllSessions(CK_SLOT_ID slotID);
CK_RV DC_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
CK_RV DC_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
CK_RV DC_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
CK_RV DC_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV DC_Logout(CK_SESSION_HANDLE hSession);

#endif
