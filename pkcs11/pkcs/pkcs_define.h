#ifndef _PKCS_DEFINE_H_
#define _PKCS_DEFINE_H_
#include <stdint.h>
typedef uint32_t CK_ULONG;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID*	CK_SLOT_ID_PTR;

typedef uint8_t CK_BYTE;
typedef CK_BYTE CK_BBOOL;
typedef uint32_t CK_FLAGS;
typedef char CK_UTF8CHAR;
typedef CK_UTF8CHAR CK_CHAR;

#define PKCS_VERSION_MAJOR      0x02
#define PKCS_VERSION_MINOR      0x01

//SLOT Infomation Flags
#define CKF_TOKEN_PRESENT		0x00000001	//True->Token avaliable
#define CKF_REMOVABLE_DEVICE	0x00000002	//True->Removeable Device
#define CKF_HW_SLOT				0x00000004	//True->Hardware Flase->Software

//Token Information Flags
/*
While CKF_WRITE_PROTECTED Seted :
	Creating/Modifying/Deleting any object on the token is invalied
	Creating/Modifying/Deleting a token object ont the token is invalied
	Changing the SO's PIN is invalied
	Changing the normal user's PIN is invalied
Note:
	CKF_WRITE_PROTECTED can be false :
		Session is R/W SO or R/W user
		USER has successfully called C_Login

Functions depend on security policy:
		CKF_USER_PIN_COUNT_LOW
		CKF_USER_PIN_FINAL_TRY
		CKF_SO_PIN_FINAL_TRY

Functions depen on Functions:
		CKF_USER_PIN_TO_BE_CHANGED
		CKF_SO_PIN_TO_BE_CHANGED
*/
#define CKF_RNG								0x00000001	//True->Token has its own Random Number Generator
#define CKF_WRITE_PROTECTED					0x00000002	//True->Token Write Protected
#define CKF_LOGIN_REQUIRED					0x00000004	//True->Login Before Cryptographic Function
#define CKF_USER_PIN_INITIALIZED			0x00000008	//True->Normal USER's PIN has been initialized
#define CKF_RESTORE_KEY_NOT_NEEDED			0x00000020	//True->Cryptographic operations state always contains all keys
#define CKF_CLOCK_ON_TOKEN					0x00000040	//True->Token Has its own Clock
#define CKF_PROTECTED_AUTHENTICATION_PATH	0x00000100	//True->Token has a protected authentication path
#define CKF_DUAL_CRYPTO_OPERATIONS			0x00000200	//True->A session can perform dual cryptographic operations
#define CKF_TOKEN_INITIALIZED				0x00000400	//True->If Token is INITed Call InitToken will reinitialize the token
#define CKF_SECONDARY_AUTHENTICATION		0x00000800	//True->The token supports secondary authentication for private key objects(Deprecated)
#define CKF_USER_PIN_COUNT_LOW				0x00010000	//True->An incorrect user login PIN has been entered at least once since the last successful authentication
#define CKF_USER_PIN_FINAL_TRY				0x00020000	//True->User PIN has been locked.Impossible to login.
#define CKF_USER_PIN_TO_BE_CHANGED			0x00080000	//True->Pin value is the default set by token initiazation or manufacturing
#define CKF_SO_PIN_COUNT_LOW				0x00100000	//True->An incorrect SO user login PIN has been entered at least once since the last successful authentication
#define CKF_SO_PIN_FINAL_TRY				0x00200000	//True->Last Try if PIN not correct will lock the Device
#define CKF_SO_PIN_LOCKED					0x00400000	//True->The So PIN has been locked.Impossible to login.
#define CKF_SO_PIN_TO_BE_CHANGED			0x00800000	//True->So PIN is Not Default Value
#define CKF_ERROR_STATE						0x01000000	//True->Token failed a FIPS 140-2 self-test and entered an error state

//Session Types
typedef CK_ULONG CK_SESSION_HANDLE;	//No Zero Value if Zero is CK_INVALIED_HANDLE
typedef CK_SESSION_HANDLE*	CK_SESSION_HANDLE_PTR;
#define CK_INVALID_HANDLE					0x00000000
typedef CK_ULONG CK_USER_TYPE;
#define CKU_SO								0x00000000
#define CKU_USER							0x00000001
#define CKU_CONTEXT_SPECIFIC				0x00000002
typedef CK_ULONG CK_STATE;
#define CKS_RO_PUBLIC_SESSION				0x00000001
#define CKS_RO_USER_FUNCTIONS				0x00000002
#define CKS_RW_PUBLIC_SESSION				0x00000003
#define CKS_RW_USER_FUNCTIONS				0x00000004
#define CKS_RW_SO_FUNCTIONS					0x00000005

#define CKF_RW_SESSION						0x00000002
#define CKF_SERIAL_SESSION					0x00000004

typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_HW_FEATURE_TYPE;

typedef CK_ULONG CK_NOTIFICATION;
typedef CK_ULONG CK_HW_FEATURE_TYPE;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_CERTIFICATE_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG JAVA_MIDP_SECURITY_DOMAIN;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE*	CK_MECHANISM_TYPE_PTR;

typedef CK_ULONG CK_CERTIFICATE_CATEGORY;
#define CK_CERTIFICATE_CATEGORY_UNSPECIFIED		0x00000000	//No category specified
#define CK_CERTIFICATE_CATEGORY_TOKEN_USER		0x00000001	//Certificate belong to Owner of the Token
#define CK_CERTIFICATE_CATEGORY_AUTHORITY		0x00000002	//Certificate belong to Certificate Authority
#define CK_CERTIFICATE_CATEGORY_OTHER_ENTITY	0x00000003	//Certificate belong to an end entity
#define CK_SECURITY_DOMAIN_UNSPECIFIED			0x00000000;
#define CK_SECURITY_DOMAIN_MANUFACTURER			0x00000001;
#define CK_SECURITY_DOMAIN_OPERATOR				0x00000002;
#define CK_SECURITY_DOMAIN_THIRD_PARTY			0x00000003;

typedef CK_ULONG CKN_SURRENDER;
typedef CK_ULONG CKH_VENDOR_DEFINED;
typedef CK_ULONG CKK_VENDOR_DEFINED;
typedef CK_ULONG CKC_VENDOR_DEFINED;
typedef CK_ULONG CKA_VENDOR_DEFINED;
typedef CK_ULONG CKM_VENDOR_DEFINED;

#define CKF_HW					0x00000001
#define CKF_ENCRYPT				0x00000100
#define CKF_DECRYPT				0x00000200
#define CKF_DIGEST				0x00000400
#define CKF_SIGN				0x00000800
#define CKF_SIGN_RECOVER		0x00001000
#define CKF_VERIFY				0x00002000
#define CKF_VERIFY_RECOVER		0x00004000
#define CKF_GENERATE			0x00008000
#define CKF_GENERATE_KEY_PAIR	0x00010000
#define CKF_WRAP				0x00020000
#define CKF_UNWRAP				0x00040000
#define CKF_DERIVE				0x00080000
#define CKF_EXTENSION			0x80000000

typedef CK_ULONG CK_RV;
typedef CK_ULONG CKR_VENDOR_DEFINED;

#define CKF_LIBRARY_CANT_CREATE_OS_THREADS		0x00000001
#define CKF_OS_LOCKING_OK						0x00000002

//Cryptoki Function Return Values

//Universal Return Value
#define	CKR_GENERAL_ERROR						0x00000001
#define	CKR_HOST_MEMORY							0x00000002
#define CKR_FUNCTION_FAILED						0x00000003
#define CKR_GENERAL_ERROR						0x00000004
#define CKR_OK									0x00000000
//Session Handle Return Value
#define CKR_SESSION_HANDLE_INVALID				0x00000010
#define CKR_DEVICE_REMOVED						0x00000020
#define CKR_SESSION_CLOSED						0x00000030
//Token Handle Return Value
#define CKR_DEVICE_MEMORY						0x00000100
#define CKR_DEVICE_ERROR						0x00000200
#define CKR_TOKEN_NOT_PRESENT					0x00000300
#define CKR_DEVICE_REMOVED						0x00000400
//Special Return Value
#define CKR_CANCEL								0x00001000
//Mutex Handle Return 
#define CKR_MUTEX_BAD							0x00010000
#define CKR_MUTEX_NOT_LOCKED					0x00020000
//All Other Cryptoki Function return value
#define CKR_ACTION_PROHIBITED					0x00030000
#define CKR_ARGUMENTS_BAD						0x00040000
#define CKR_ATTRIBUTE_READ_ONLY					0x00050000
#define CKR_ATTRIBUTE_TYPE_INVALID				0x00060000
#define CKR_VALUE_INVALID						0x00070000
#define CKR_BUFFER_TOO_SMALL					0x00080000
#define CKR_CANT_LOCK							0x00090000
#define CKR_CRYPTOKI_ALREADY_INITIALIZED		0x000A0000
#define CKR_CRYPTOKI_NOT_INITIALIZED			0x000B0000
#define CKR_CURVE_NOT_SUPPORTED					0x000C0000
#define CKR_DATA_INVALID						0x000D0000
#define CKR_DATA_LEN_RANGE						0x000E0000
#define CKR_DOMAIN_PARAMS_INVALID				0x000F0000
#define CKR_ENCRYPTED_DATA_INVALID				0x00100000
#define CKR_ENCRYPTED_DATA_LEN_RANGE			0x00200000
#define CKR_EXCEEDED_MAX_ITERATIONS				0x00300000
#define CKR_FIPS_SELF_TEST_FAILED				0x00400000
#define CKR_FUNCTION_CANCELED					0x00500000
#define CKR_FUNCTION_NOT_PARALLEL				0x00600000
#define CKR_FUNCTION_NOT_SUPPORTED				0x00700000
#define CKR_FUNCTION_REJECTED					0x00800000
#define CKR_INFORMATION_SENSITIVE				0x00900000
#define CKR_KEY_CHANGED							0x00A00000
#define CKR_KEY_FUNCTION_NOT_PERMITTED			0x00B00000
#define CKR_KEY_HANDLE_INvALID					0x00C00000
#define CKR_KEY_INDIGESTIBLE					0x00D00000
#define CKR_KEY_NEEDED							0x00E00000
#define CKR_KEY_NOT_NEEDED						0x00F00000
#define CKR_KEY_NOT_WRAPPABLE					0x01000000
#define CKR_KEY_SIZE_RANGE						0x02000000
#define CKR_KEY_TYPE_INCONSISTENT				0x03000000
#define CKR_KEY_UNEXTERACTABLE					0x04000000
#define CKR_LIBRARY_LOAD_FAILED					0x05000000
#define CKR_MECHANISM_INVALID					0x06000000
#define CKR_MECHANISM_PARAM_INVALID				0x07000000
#define CKR_NEED_TO_CREATE_THEADS				0x08000000
#define CKR_NO_EVENT							0x09000000
#define CKR_OBJECT_HANLDE_INVALID				0x0A000000
#define CKR_OPERATION_ACTIVE					0x0B000000
#define CKR_OPERATION_NOT_INITALIZED			0x0C000000
#define CKR_PIN_EXPIRED							0x0D000000
#define CKR_PIN_INCORRECT						0x0E000000
#define CKR_PIN_INVALID							0x0F000000
#define CKR_PIN_LEN_RANGE						0x10000001
#define CKR_PIN_LOCKED							0x10000002
#define CKR_PIN_TOO_WEAK						0x10000003
#define CKR_PUBLIC_KEY_iNVALID					0x10000004
#define CKR_RANDOM_NO_RNG						0x10000005
#define CKR_RANDOM_SEED_NOT_SUPPORTED			0x10000006
#define CKR_SAVED_STATE_INVALID					0x10000007
#define CKR_SESSION_COUNT						0x10000008
#define CKR_SESSION_EXISTS						0x10000009
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED		0x1000000A
#define CKR_SESSION_READ_ONLY					0x1000000B
#define CKR_SESSION_READ_ONLY_EXISTS			0x1000000C
#define CKR_SESSION_READ_WRITE_SO_EXISTS		0x1000000D
#define CKR_SIGNATURE_LEN_RANGE					0x1000000E
#define CKR_SIGNATURE_INVALID					0x1000000F
#define CKR_SLOT_ID_INVALID						0x10000010
#define CKR_STATE_UNSAVEABLE					0x10000020
#define CKR_TEMPLATE_INCOMPLETE					0x10000030
#define CKR_TEMPLATE_INCONSISTENT				0x10000040
#define CKR_TOKEN_NOT_RECOGNIZED				0x10000050
#define CKR_TOKEN_WRITE_PROTYECTED				0x10000060
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID		0x10000070
#define CKR_UNWRAPPING_KEY_SIZE_RANGE			0x10000080
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT	0x10000090
#define CKR_USER_ALREADY_LOGGED_IN				0x100000A0
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN		0x100000B0
#define CKR_USER_NOT_LOGGED						0x100000C0
#define CKR_USER_PIN_NOT_INITIALIZED			0x100000D0
#define CKR_USER_TOO_MANY_TYPES					0x100000E0
#define CKR_USER_TYPE_INVALID					0x100000F0
#define CKR_WRAPPED_KEY_INVALID					0x10000100
#define CKR_WRAPPED_KEY_LEN_RANGE				0x10000200
#define CKR_WRAPPING_KEY_HANDLE_INVALID			0x10000300
#define CKR_WRAPPING_KEY_SIZE_RANGE				0x10000400
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT		0x10000500

#endif // !_PKCS_DEFINE_H_
