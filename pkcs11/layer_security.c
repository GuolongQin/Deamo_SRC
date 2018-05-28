#include "layer_security.h"
#include "pkcs/pkcs_define.h"

#include "pkcs/p11_crypto_function.h"
#include "pkcs/p11_generalpurpose.h"
#include "pkcs/p11_object_function.h"
#include "pkcs/p11_session_management.h"
#include "pkcs/p11_slot_token_management.h"
#include "pkcs/p11_store.h"

#define TRAN_USB_MSD;

//Connector
uint32_t Init_TransLayer();
uint32_t Final_TrandLayer();

/*
DC_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

*/
uint32_t layer_security_init(CK_NOTIFY *arg_notify) {
    uint32_t ret;
    if(arg_notify!=NULL){
        notify = arg_notify;
    }
    if (Init_TransLayer()) {//Error Occured
        if(notify!=NULL)
        notify(NULL,CKR_EVENT_ERROR,"Init_TransLayer Failed\n");
        return 1;
    }
    else {
        //Version Def
        function_list.version.major = PKCS_VERSION_MAJOR;
        function_list.version.minor = PKCS_VERSION_MINOR;

        //Gerneral Purpose
        function_list.initialize = DC_Initialize;
        function_list.finalize = DC_Finalize;
        function_list.getInfo = DC_GetInfo;

        //Slot and Token
        function_list.getslotlist = DC_GetSlotList;
        function_list.getslotinfo = DC_GetSlotInfo;
        function_list.gettokeninfo = DC_GetTokenInfo;
        function_list.waitforslotevent = DC_WaitForSlotEvent;
        function_list.getmechanismlist = DC_GetMechanismList;
        function_list.getmechanisminfo = DC_GetMechanismInfo;
        function_list.inittoken = DC_InitToken;
        function_list.initpin = DC_InitPIN;

        //Session Management
        function_list.opensession = DC_OpenSession;
        function_list.closesession = DC_CloseSession;
        function_list.closeallsessions = DC_CloseAllSessions;
        function_list.getsessioninfo = DC_GetSessionInfo;
        function_list.getoperationstate = DC_GetOperationState;
        function_list.setoperationstate = DC_SetOperationState;
        function_list.login = DC_Login;
        function_list.logout = DC_Logout;

        //Object Management
        function_list.createobject = DC_CreateObject;
        function_list.copyobject = DC_CopyObject;
        function_list.destroyobject = DC_DestroyObject;
        function_list.getobjectsize = DC_GetObjectSize;
        function_list.getattributevalue = DC_GetAttributeValue;
        function_list.setattributevalue = DC_SetAttributeValue;
        function_list.findobjectinit = DC_FindObjectsInit;
        function_list.findobjectfinal = DC_FindObjectFinal;

        //Encrypt Function
        function_list.encryptinit = DC_EncryptInit;
        function_list.encrypt = DC_Encrypt;
        function_list.encryptupdate = DC_EncryptUpdate;
        function_list.encryptfinal = DC_EncryptFinal;

        //Decrypt Function
        function_list.decryptinit = DC_DecryptInit;
        function_list.decrypt = DC_Decrypt;
        function_list.decryptupdate = DC_DecryptUpdate;
        function_list.decryptfinal = DC_DecryptFinal;

        //Digest Function
        function_list.digestinit = DC_DigestInit;
        function_list.digest = DC_Digest;
        function_list.digestupdate = DC_DigestUpdate;
        function_list.digestkey = DC_DigestKey;
        function_list.digestfinal = DC_DigestFinal;

        //Decrypt Function
        function_list.signinit = DC_SignInit;
        function_list.sign = DC_Sign;
        function_list.signupdate = DC_SignUpdate;
        function_list.signfinal = DC_SignFinal;
        function_list.signrecoverinit = DC_SignRecover;
        function_list.signrecover = DC_SignRecover;

        //Verify Function
        function_list.verifyinit = DC_VerifyInit;
        function_list.verify = DC_Verify;
        function_list.verifyupdate = DC_VerifyUpdate;
        function_list.verifyfinal = DC_VerifyFinal;
        function_list.verifyrecoverinit = DC_VerifyRecoverInit;
        function_list.verifyrecover = DC_VerifyRecover;

        //Dual-purpose Function
        function_list.digestencryptupdate = DC_DigestEncryptUpdate;
        function_list.decryptdigestupdate = DC_DecryptDigestUpdate;
        function_list.signencryptupdate = DC_SignEncryptUpdate;
        function_list.decryptverifyupdate = DC_DecryptVerifyUpdate;

        //Key Management Function
        function_list.generatekey = DC_GenerateKey;
        function_list.generatekeypair = DC_GenerateKeyPair;
        function_list.wrapkey = DC_WrapKey;
        function_list.unwrapkey = DC_Unwrapkey;
        function_list.derivekey = DC_DeriveKey;

        //Random Number Functions
        function_list.seedrandom = DC_SeedRandom;
        function_list.generaterandom = DC_GenerateRandom;

        //Parallel Functions
        function_list.getfunctionstatus = DC_GetFunctionStatus;
        function_list.cancelfunction = DC_CancelFunction;

        if(arg_notify!=NULL){
            notify(NULL,CKR_EVENT_INFO,"Cryptoki Inited\n");
        }
        return 0;
    }

}
uint32_t layer_security_final() {
    Final_TrandLayer();
}

uint32_t Init_TransLayer() {
    uint32_t ret;
#ifdef under_linux
    #ifdef TRAN_USB_MSD
        ret = set_trans_init(TRANS_USB_MSD);
    #endif // TRAN_USB_MSD
#endif // under_linux
        return ret;
}
uint32_t Final_TrandLayer() {
    uint32_t ret;
#ifdef under_linux
    #ifdef TRAN_USB_MSD
        ret = set_trans_final();
    #endif // TRAN_USB_MSD
#endif
        return ret;
}



