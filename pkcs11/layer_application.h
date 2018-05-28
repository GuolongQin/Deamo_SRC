/*
CopyRight	:	Westone. Chengdu Sichuan of China
Auther		:	Guolong Qin
Email		:	384726637@qq.com
Description	:	PKCS Test Application
*/

#ifndef _LAYER_APPLICATION_H_
#define _LAYER_APPLICATION_H_
#include <stdio.h>
#include "pkcs/pkcs.h"
#include "layer_security.h"
/*
typedef struct General_Purpose {
	//General Purpose Functions
	C_Initialize initialize;
	C_Finalize finalize;
	C_GetInfo getinfo;
	C_GetFunctionList getfunctionlist;
}General_Purpose;

typedef struct Token_Management {
	//Slot and token Management functions
	C_GetSlotList getslotlist;
	C_GetSlotInfo getslotinfo;
	C_GetTokenInfo gettokeninfo;
	C_WaitForSlotEvent waitforslotevent;
	C_GetMechanismList getmechanismlist;
	C_GetMechanismInfo getmechanisminfo;
	C_InitToken inittoken;
	C_InitPIN initpin;
}Token_Management;

typedef struct Session_Management{
	//Session Management functions
	C_OpenSession opensession;
	C_CloseSession closesession;
	C_CloseAllSessions closeallsessions;
	C_GetSessionInfo getsessionino;
	C_GetOperationState getoperationstate;
	C_SetOperationState setoperationstate;
	C_Login login;
	C_Logout logout;
}Session_Management;

typedef struct Object_Management {
	//Object management functions
	C_CreateObject createobject;
	C_CopyObject copyobject;
	C_DestroyObject destroyobject;
	C_GetObjectSize getobjectsize;
	C_GetAttributeValue getattributevalue;
	C_SetAttributeValue setattributevalue;
	C_FindObjectsInit findobjectinit;
	C_FindObjectFinal findobjectfinal;
}Object_Management;

typedef struct Encrypt {
	//Encryption functions
	C_EncryptInit encryptinit;
	C_Encrypt encrypt;
	C_EncryptUpdate encryptupdate;
	C_EncryptFinal encryptfinal;
}Encrypt;

typedef struct Decrypt {
	//Decryption functions
	C_DecryptInit decryptinit;
	C_Decrypt decrypt;
	C_DecryptUpdate decryptupdate;
	C_DecryptFinal decryptfinal;
}Decrypt;

typedef struct Digest {
	//Digestion functions
	C_DigestInit digestinit;
	C_Digest digest;
	C_DigestUpdate digestupdate;
	C_DigestKey digestkey;
	C_DigestFinal digestfinal;
}Digest;
typedef struct Signing_MACing {
	//Signing and MACing functions
	C_SignInit signinit;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
	C_Sign sign;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	C_SignUpdate signupdate;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	C_SignFinal signfinal;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	C_SignRecoverInit signrecoverinit;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	C_SignRecover signrecover;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
	C_VerifyInit verifyinit;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	C_Verify verify;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	C_VerifyUpdate verifyupdate;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
	C_VerifyFinal verifyfinal;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
	C_VerifyRecoverInit verifyrecoverinit;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
	C_VerifyRecover verifyrecover;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

}Signing_MACing;
typedef struct Dual_Function {
	//Dual-function cryptographic functions
	C_DigestEncryptUpdate digestencryptupdate;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
	C_DecryptDigestUpdate decryptdigestupdate;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
	C_SignEncryptUpdate signencryptupdate;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
	C_DecryptVerifyUpdate decryptverifyupdate;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
}Dual_Function;

typedef struct Key_Management {
	//Key management functions
	C_GenerateKey generatekey;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
	C_GenerateKeyPair generatekeypair;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
	C_WrapKey wrapkey;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
	C_Unwrapkey unwrapkey;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
	C_DeriveKey derivekey;//CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE phKey);
}Key_Management;

typedef struct Random {
	//Random number generate functions
	C_SeedRandom seedrandom;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
	C_GenerateRandom generaterandom;//CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
}Random;

typedef struct Parallel {
	//Parallel function management functions
	C_GetFunctionStatus getfunctionstatus;//CK_SESSION_HANDLE hSession);
	C_CancelFunction cancelfunction;//CK_SESSION_HANDLE hSession);
}Parallel;




typedef struct pkcs_function_call{
	General_Purpose* general_purpose;
	Token_Management* token_management;
	Session_Management* session_management;
	Object_Management* object_management;
	Encrypt* encrypt;
	Decrypt* decrypt;
	Digest* digest;
	Signing_MACing* signing_MACing;
	Dual_Function* dual_function;
	Key_Management* key_management;
	Random* random;
	Parallel* parallel;
}pkcs_function_call;
typedef pkcs_function_call* pkcs_function_call_ptr;
*/
typedef struct application_handle{
	CK_INFO_PTR	PKCS_INFO;
	CK_FUNCTION_LIST_PTR PKCS_FUNCTION;
}application_handle;

typedef application_handle* application_handle_p;

int application_init(application_handle_p hdl);
void application_final(application_handle_p hdl);
void get_application_info(application_handle_p hdl);




#endif // !_LAYER_APPLICATION_H_

