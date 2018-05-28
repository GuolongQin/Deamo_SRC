#include "p11_generalpurpose.h"
//General Purpose Functions
#include "p11_store.h"
#include "pkcs_apdu.h"
#include "layer_trans.h"
//#define MULTI_SESSION_DISABLE

extern

CK_RV DC_Initialize(CK_VOID_PTR pInitArgs) {
    uint8_t* Cache_S;
    uint8_t* Cache_R;
    uint32_t buflen;
    uint32_t flag;
    p11_t.permission = CKF_FALSE;
    Cache_S = (uint8_t*)malloc(50);

    notify(NULL,CKR_EVENT_INFO,"Initilizing PKCS11 System\n");
    if(pInitArgs!=NULL){

        CK_C_INITIALIZE_ARGS *init_arg = (CK_C_INITIALIZE_ARGS*)pInitArgs;
        p11_t.CreateMutex = init_arg->CreateMutex;
        p11_t.DestroyMutex = init_arg->DestroyMutex;
        p11_t.LockMutex = init_arg->LockMutex;
        p11_t.UnlockMutex = init_arg->UnlockMutex;
        p11_t.reserve = init_arg->pReserved;
        flag = init_arg->flags;

/*
LibraryCantCreate       OS_Locking_OK       PointerCallback     Result
yes                     ?                   NULL                Bad_arg
yes                     ?                   Not NULL            Re_lock
no                      yes                 ?                   Lo_lock
no                      no                  ?                   Bad_arg
*/

        if(flag|CKF_LIBRARY_CANT_CREATE_OS_THREADS){
            if(p11_t.CreateMutex==NULL||p11_t.DestroyMutex==NULL||p11_t.LockMutex==NULL&&p11_t.UnlockMutex==NULL){
                p11_t.permission = CKF_FALSE;
                notify(NULL,CKR_EVENT_ERROR,"Init Bad Arguement\nLibrary Cant Create mutex&The Arg dont give a Pointer\n");
                return CKR_ARGUMENTS_BAD;
            }else{
                p11_t.CreateMutex(p11_t.mutex);
                goto c_init_1;
            }
        }else{
            if(flag|CKF_OS_LOCKING_OK){
                p11_t.CreateMutex = Create_Mutex_local;
                p11_t.DestroyMutex = pthread_mutex_destroy;
                p11_t.LockMutex = pthread_mutex_lock;
                p11_t.UnlockMutex = pthread_mutex_unlock;
                p11_t.CreateMutex(p11_t.mutex);
                goto c_init_1;
            }else{
                p11_t.permission = CKF_FALSE;
                notify(NULL,CKR_EVENT_ERROR,"Init Bad Arguement\nLibrary Cant Create mutex\nOS Cant Create");
                return CKR_ARGUMENTS_BAD;
            }
        }



    }else{
        p11_t.permission = CKF_FALSE;
        return CKR_ARGUMENTS_BAD;
    }

c_init_1:

    //Layer_Trans Init
    /*
    PKCS_APDU_Build(PKCS_APDU_INITIALIZE_S,Cache_S,NULL,0,&buflen);
    if(Trans_Date_W(Cache_S,buflen) == 0){
        PKCS_APDU_Build(PKCS_APDU_INITIALIZE_R,Cache_S,NULL,0,&buflen);
        if(Trans_Date_R(Cache_S,&buflen) == 0){
            Cache_R = (uint8_t*)malloc(buflen);

        }

    }
    */

    p11_t.permission = CKF_TRUE;
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
