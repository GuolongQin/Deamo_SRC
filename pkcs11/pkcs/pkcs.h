#ifndef _PKCS_H_
#define _PKCS_H_
#include "pkcs_define.h"
#include "stddef.h"

#define Vendor_MODE

#pragma pack(1)

typedef void*				CK_VOID_PTR;
typedef CK_BYTE*			CK_BYTE_PTR;
typedef CK_ULONG			CK_OBJECT_HANDLE;
typedef CK_ULONG*			CK_ULONG_PTR;
typedef CK_UTF8CHAR*		CK_UTF8CHAR_PTR;
typedef CK_OBJECT_HANDLE*	CK_OBJECT_HANDLE_PTR;

typedef struct CK_VERSION {
	CK_BYTE major;
	CK_BYTE minor;
}CK_VERSION;

typedef struct CK_INFO {
	CK_VERSION cryptokiVersion;			//Cryptoki interface version number
	CK_UTF8CHAR manufacturerID[32];		//ID of the Crypto library manufacturer
	CK_FLAGS flags;						//Must be Zero
	CK_UTF8CHAR libraryDescription[32];	//libraryDescription
	CK_VERSION libraryVersion;			//Crypto library version Number
}CK_INFO;
typedef CK_INFO*			CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
	CK_UTF8CHAR slotDescription[64];	//Slot Description		Not be NULL
	CK_UTF8CHAR manufacturerID[32];		//ID of Slot Manufacture Not be NULL
	CK_FLAGS flags;						//Bit flags
	CK_VERSION hardwareVersion;			//Version Number of Slot hardware
	CK_VERSION firmwareVersion;			//Version Number of Slot firmware

}CK_SLOT_INFO;
typedef CK_SLOT_INFO*		CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
	CK_UTF8CHAR label[32];				//Application Define Label Not be NULL
	CK_UTF8CHAR manufacturerID[32];		//ID of the device manufacture Not be NULL
	CK_UTF8CHAR model[16];				//Model of Device Not be NULL
	CK_UTF8CHAR serialNumber[16];		//Serial(Character) of the Device
	CK_FLAGS	flags;					//Bit flags of the Capabilities of the Device
	CK_ULONG	ulMaxSessionCount;		//Maxinum of sessions can be opened with the token
	CK_ULONG	ulSessionCount;			//Number of sessions that the application has opened
	CK_ULONG	ulMaxRwSessionCount;	//Maxinum of R/W session that can be opened with this token
	CK_ULONG	ulRwSessionCount;		//Number of R/W seession that this application currently has open with the token
	CK_ULONG	ulMaxPinLen;			//Maxinum length in bytes of the PIN
	CK_ULONG	ulMinPinLen;			//Minnum length in bytes of the PIN
	CK_ULONG	ulTotalPublicMemory;	//Total amount of memory on the token
	CK_ULONG	ulFreePublicMemory;		//The amount of memory on the token in bytes(Public objects maybe stored)
	CK_ULONG	ulTotalPrivateMemory;	//The amount of free memory ont the token in bytes for public objects
	CK_ULONG	ulFreePrivateMemory;	//The amount of free memory ont the token in bytes for private objects
	CK_VERSION	hardwareVersion;		//Version number of Hardware
	CK_VERSION	firmwareVersion;		//Version number of firmware
	CK_CHAR		utcTime[16];			//Current time as a Character-string of length16(YYYYMMDDhhmmssxx)
}CK_TOKEN_INFO;
typedef CK_TOKEN_INFO*		CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO {
	CK_SLOT_ID slotID;
	CK_STATE state;
	CK_FLAGS flags;
	CK_ULONG ulDeviceError;
}CK_SESSION_INFO;
typedef CK_SESSION_INFO*	CK_SESSION_INFO_PTR;

typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
}CK_ATTRIBUTE;
typedef CK_ATTRIBUTE*		CK_ATTRIBUTE_PTR;

typedef struct CK_DATA {
	CK_CHAR year[4];	//Year		("1900"-"9999")
	CK_CHAR month[2];	//Month		("01"-"12")
	CK_CHAR day[2];		//The day	("01"-"31")
}CK_DATA;

typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_ULONG ulParameterLen;
}CK_MECHANISM;
typedef CK_MECHANISM*		CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
	CK_ULONG ulMinKeySize;
	CK_ULONG ulMaxKeySize;
	CK_FLAGS flags;
}CK_MECHANISM_INFO;




typedef CK_MECHANISM_INFO*  CK_MECHANISM_INFO_PTR;

typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

/*
Ret Value:
	CKR_OK
	CKR_GENERAL_ERROR
	CKR_HOST_MEMORY
*/
typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR ppMutex);

/*
Ret Value:
	CKR_OK
	CKR_GENERAL_ERROR
	CKR_HOST_MEMORY
	CKR_MUTEX_BAD
*/
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);

/*
Ret Value:
	CKR_OK
	CKR_GENERAL_ERROR
	CKR_HOST_MEMORY
	CKR_MUTEX_BAD
*/
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);

/*
Ret Value:
	CKR_OK
	CKR_GENERAL_ERROR
	CKR_HOST_MEMORY
	CKR_MUTEX_BAD
	CKR_MUTEX_NOT_LOCKED
*/
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

typedef struct CK_C_INITIALIZE_ARGS {
	CK_CREATEMUTEX CreateMutex;
	CK_DESTROYMUTEX DestroyMutex;
	CK_LOCKMUTEX LockMutex;
	CK_UNLOCKMUTEX UnlockMutex;
	CK_FLAGS flags;
	CK_VOID_PTR pReserved;
}CK_C_INITIALIZE_ARGS;



//General Purpose Functions
typedef CK_RV (*C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*C_GetInfo)(CK_INFO_PTR pInfo);
//Slot and token Management functions
typedef CK_RV (*C_GetSlotList)(CK_BBOOL tokenPresent,CK_SLOT_INFO_PTR pSlotList,CK_ULONG_PTR pulCount);
typedef CK_RV (*C_GetSlotInfo)(CK_SLOT_ID slotID,CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*C_GetTokenInfo)(CK_SLOT_ID slotID,CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*C_WaitForSlotEvent)(CK_FLAGS flags,CK_SLOT_ID_PTR pSlot,CK_VOID_PTR pReserved);
typedef CK_RV (*C_GetMechanismList)(CK_SLOT_ID slotID,CK_MECHANISM_TYPE_PTR pMechanismList,CK_ULONG_PTR pulCount);
typedef CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID slotID,CK_MECHANISM_TYPE type,CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*C_InitToken)(CK_SLOT_ID slotID,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen,CK_UTF8CHAR_PTR pLabel);
typedef CK_RV (*C_InitPIN)(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen);
typedef CK_RV (*C_SetPIN)(CK_SESSION_HANDLE hSession,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen);
//Session Management functions
typedef CK_RV (*C_OpenSession)(CK_SLOT_ID slotID,CK_FLAGS flags,CK_VOID_PTR pApplication,CK_NOTIFY Notify,CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (*C_GetSessionInfo)(CK_SESSION_HANDLE hSession,CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*C_GetOperationState)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pOperationState,CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*C_SetOperationState)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pOperationState,CK_ULONG ulOperationStateLen,CK_OBJECT_HANDLE hEncryptionKey,CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*C_Login)(CK_SESSION_HANDLE hSession,CK_USER_TYPE userType,CK_UTF8CHAR_PTR pPin,CK_ULONG ulPinLen);
typedef CK_RV (*C_Logout)(CK_SESSION_HANDLE hSession);
//Object management functions
typedef CK_RV (*C_CreateObject)(CK_SESSION_HANDLE hSession,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*C_CopyObject)(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject);
typedef CK_RV (*C_GetObjectSize)(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ULONG_PTR pulSize);
typedef CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
typedef CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE hSession,CK_OBJECT_HANDLE hObject,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
typedef CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE hSession,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount);
typedef CK_RV (*C_FindObjectFinal)(CK_SESSION_HANDLE hSession);
//Encryption functions
typedef CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_Encrypt)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pEncryptedData,CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*C_EncryptUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen,CK_BYTE_PTR pEncryptedPart,CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*C_EncryptFinal)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pLastEncryptedPart,CK_ULONG_PTR pulLastEncryptedPartLen);
//Decryption functions
typedef CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
//Message digesting functions
typedef CK_RV (*C_DigestInit)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*C_Digest)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*C_DigestUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen);
typedef CK_RV (*C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_DigestFinal)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pDigest,CK_ULONG_PTR pulDigestLen);
//Signing and MACing functions
typedef CK_RV (*C_SignInit)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*C_Sign)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*C_SignUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen);
typedef CK_RV (*C_SignFinal)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_Verify)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_ULONG ulDataLen,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen);
typedef CK_RV (*C_VerifyUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen);
typedef CK_RV (*C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hKey);
typedef CK_RV (*C_VerifyRecover)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSignature,CK_ULONG ulSignatureLen,CK_BYTE_PTR pData,CK_ULONG_PTR pulDataLen);
//Dual-function cryptographic functions
typedef CK_RV (*C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen,CK_BYTE_PTR pEncryptedPart,CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedPart,CK_ULONG ulEncryptedPartLen,CK_BYTE_PTR pPart,CK_ULONG_PTR pulPartLen);
typedef CK_RV (*C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pPart,CK_ULONG ulPartLen,CK_BYTE_PTR pEncryptedPart,CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pEncryptedPart,CK_ULONG ulEncryptedPartLen,CK_BYTE_PTR pPart,CK_ULONG_PTR pulPartLen);
//Key management functions
typedef CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_ATTRIBUTE_PTR pPublicKeyTemplate,CK_ULONG ulPrivateKeyAttributeCount,CK_OBJECT_HANDLE_PTR phPublicKey,CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*C_WrapKey)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hWrappingKey,CK_OBJECT_HANDLE hKey,CK_BYTE_PTR pWrappedKey,CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*C_Unwrapkey)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hUnwrappingKey,CK_BYTE_PTR pWrappedKey,CK_ULONG ulWrappedKeyLen,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulAttributeCount,CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE hSession,CK_MECHANISM_PTR pMechanism,CK_OBJECT_HANDLE hBaseKey,CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulAttributeCount,CK_OBJECT_HANDLE phKey);
//Random number generate functions
typedef CK_RV (*C_SeedRandom)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pSeed,CK_ULONG ulSeedLen);
typedef CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pRandomData,CK_ULONG ulRandomLen);
//Parallel function management functions
typedef CK_RV (*C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*C_CancelFunction)(CK_SESSION_HANDLE hSession);

#ifdef Vendor_MODE
    typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);
#endif // Vendor_MODE


typedef struct CK_FUNCTION_LIST {
	//General Purpose Functions
	CK_VERSION version;

    C_Initialize initialize;
    C_Finalize finalize;
    C_GetInfo getInfo;

	//Slot and token Management functions
	C_GetSlotList getslotlist;
	C_GetSlotInfo getslotinfo;
	C_GetTokenInfo gettokeninfo;
	C_WaitForSlotEvent waitforslotevent;
	C_GetMechanismList getmechanismlist;
	C_GetMechanismInfo getmechanisminfo;
	C_InitToken inittoken;
	C_InitPIN initpin;
    C_SetPIN setpin;

	//Session Management functions
	C_OpenSession opensession;
	C_CloseSession closesession;
	C_CloseAllSessions closeallsessions;
	C_GetSessionInfo getsessioninfo;
	C_GetOperationState getoperationstate;
	C_SetOperationState setoperationstate;
	C_Login login;
	C_Logout logout;

	//Object management functions
	C_CreateObject createobject;
	C_CopyObject copyobject;
	C_DestroyObject destroyobject;
	C_GetObjectSize getobjectsize;
	C_GetAttributeValue getattributevalue;
	C_SetAttributeValue setattributevalue;
	C_FindObjectsInit findobjectinit;
	C_FindObjectFinal findobjectfinal;

	//Encryption functions
	C_EncryptInit encryptinit;
	C_Encrypt encrypt;
	C_EncryptUpdate encryptupdate;
	C_EncryptFinal encryptfinal;

	//Decryption functions
	C_DecryptInit decryptinit;
	C_Decrypt decrypt;
	C_DecryptUpdate decryptupdate;
	C_DecryptFinal decryptfinal;

	//Message digesting functions
	C_DigestInit digestinit;
	C_Digest digest;
	C_DigestUpdate digestupdate;
	C_DigestKey digestkey;
	C_DigestFinal digestfinal;

	//Signing and MACing functions
	C_SignInit signinit;
	C_Sign sign;
	C_SignUpdate signupdate;
	C_SignFinal signfinal;
	C_SignRecoverInit signrecoverinit;
	C_SignRecover signrecover;
	C_VerifyInit verifyinit;
	C_Verify verify;
	C_VerifyUpdate verifyupdate;
	C_VerifyFinal verifyfinal;
	C_VerifyRecoverInit verifyrecoverinit;
	C_VerifyRecover verifyrecover;

	//Dual-function cryptographic functions
	C_DigestEncryptUpdate digestencryptupdate;
	C_DecryptDigestUpdate decryptdigestupdate;
	C_SignEncryptUpdate signencryptupdate;
	C_DecryptVerifyUpdate decryptverifyupdate;

	//Key management functions
	C_GenerateKey generatekey;
	C_GenerateKeyPair generatekeypair;
	C_WrapKey wrapkey;
	C_Unwrapkey unwrapkey;
	C_DeriveKey derivekey;

	//Random number generate functions
	C_SeedRandom seedrandom;
	C_GenerateRandom generaterandom;

	//Parallel function management functions
	C_GetFunctionStatus getfunctionstatus;
	C_CancelFunction cancelfunction;

}CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST*	CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR*	CK_FUNCTION_LIST_PTR_PTR;
//typedef CK_RV(*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

#define MAX_SLOT_COUNT  0xff
#define MAX_SESSION_COUNT   0xff
typedef struct P11_Slot{

}P11_Slot_t;

typedef struct P11_Session{

}P11_Session_t;


typedef struct P11_Context{
    CK_BBOOL inited;
    CK_BBOOL permission;
    CK_ULONG slot_count;
    P11_Slot_t slots[MAX_SLOT_COUNT];
    CK_ULONG session_count;
    P11_Session_t sessions[MAX_SESSION_COUNT];

}P11_Context_Info;


#endif // !_PKCS_H_

