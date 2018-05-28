#include "pkcs.h"

CK_RV Create_Mutex_local(void* arg){
    pthread_mutex_init(arg,NULL);


}
