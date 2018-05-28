#include "p11_generalpurpose.h"
//General Purpose Functions
#include "p11_store.h"
#define MULTI_THREAD_DISABLE

CK_RV DC_Initialize(CK_VOID_PTR pInitArgs) {
    notify(NULL,CKR_EVENT_INFO,"Initilizing PKCS11 System\n");
    if(pInitArgs!=NULL){
#ifdef        MULTI_THREAD_DISABLE
        notify(NULL,CKR_EVENT_ERROR,"This p11 Version not support pInitArgs\n");
        return CKR_ARGUMENTS_BAD;
#endif
        CK_C_INITIALIZE_ARGS init_arg = (CK_C_INITIALIZE_ARGS*)pInitArgs;
        init_arg.flags



    }




    return CKR_OK;
}
CK_RV DC_Finalize(CK_VOID_PTR pReserved) {
    return CKR_OK;
}
CK_RV DC_GetInfo(CK_INFO_PTR pInfo) {
    return CKR_OK;
}
CK_RV DC_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList){
    *ppFunctionList = &function_list;
    return CKR_OK;
}
