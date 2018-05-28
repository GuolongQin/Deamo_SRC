#include "layer_application.h"

CK_RV CK_NOTIFY_VENDOR(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

int application_init(application_handle_p hdl) {
	uint32_t ret;

	if (hdl == NULL) {
		printf("Error : Handle Null PTR\n");
		return -1;
    }else {
//        if (hdl->PKCS_FUNCTION != NULL) {
//            printf("Error : Handle_Function not Null PTR maybe has inited\n");
//            return -2;
//        }
      //  hdl->PKCS_FUNCTION = (CK_FUNCTION_LIST_PTR)malloc(sizeof(CK_FUNCTION_LIST));

        ret = layer_security_init(CK_NOTIFY_VENDOR);
        if(ret!=0){
            printf("layer_security init failed\n");
        }
        ret = DC_GetFunctionList(&(hdl->PKCS_FUNCTION));
        hdl->PKCS_FUNCTION->initialize(NULL);
	}
	return 0;
}

void application_final(application_handle_p hdl) {


}


void get_application_info(application_handle_p hdl) {

}
CK_RV CK_NOTIFY_VENDOR(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication){
    if(hSession!=NULL){
        printf("Session NULL :\n");
    }else{
        printf("Session %d   :\n");
    }
    switch(event){
    case CKR_EVENT_INFO:
        printf(" Info   :");
        break;
    case CKR_EVENT_WARN:
        printf(" Warn   :");
        break;
    case CKR_EVENT_ERROR:
        printf(" Error  :");
        break;
    }
    printf("%s",pApplication);

}
