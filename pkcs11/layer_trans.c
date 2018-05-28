#include "layer_trans.h"
#include "dirent.h"
#include "unistd.h"
#include "string.h"
#include <stdlib.h>

static char* SCSI_Dev_ID_PATH = "/dev/disk/by-id";
static uint32_t Set_Trans_Way;

static const char* DEVICE_LIST[] = {"HESC","IOT","Hello"};
Device_Detected_t *devices;

#define HSE_KEY         0x01;
#define HSE

static uint32_t Get_USB_MSG_Device(){
    DIR *dir;
    struct dirent *ptr;
    char* ret_strchr;
    Device_Detected_t* temp_dev;
    devices = (Device_Detected_t*)malloc(sizeof(Device_Detected_t));
    temp_dev = devices;

    if((dir = opendir("/dev/disk/by-id"))==NULL){
        printf("Error : Open dir Error.\n");
        return -1;
    }
    while((ptr=readdir(dir))!=NULL){
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)
            continue;
        if(ptr->d_type == 10){ //10 Link File //8 File //4 Dir
            //SCSI Store is Link File
            printf("%s\n",ptr->d_name);
            for(int i =0;i<sizeof(DEVICE_LIST)/sizeof(const char*);i++){
                ret_strchr = strchr(DEVICE_LIST[i],ptr->d_name);
                if(ret_strchr!=NULL){
                    if(temp_dev->Device_Name!=NULL){
                        temp_dev->Next = (Device_Detected_t*)malloc(sizeof(Device_Detected_t));
                        temp_dev = temp_dev->Next;
                    }

                    if(temp_dev->Device_Name==NULL){
                        devices->Device_Name = (char*)malloc(strlen(ptr->d_name));
                        strcpy(devices->Device_Name,ptr->d_name);
                    }

                }
            }

       }
    }

    return 0;
}



uint32_t set_trans_init(TR_FLAGS Trans_Way) {
    uint32_t ret;
    switch(Set_Trans_Way){
        case TRANS_USB_MSD:
           ret = Get_USB_MSG_Device();
           if(ret != 0){
               return ;
           }
            break;
        default:
            return TRANS_ERROR_NO_DEVICE;

    }


    return 0;
}
uint32_t set_trans_config(TR_BYTE_PTR pData, TR_ULONG pDataLen) {
    switch(Set_Trans_Way){
        case TRANS_USB_MSD:
           //Do Nothing
            break;
        default:
            return TRANS_ERROR_NO_DEVICE;

    }



    return TRANS_OK;
}
uint32_t set_trans_final() {
}
void print_trans_info() {
}

/*Send a Data
 * pData_Send   len_S   pData_Recv  len_R
 * N-NULL       N-NULL  N-NULL      N-NULL
 *
 * len_R
*/

TR_RV Trans_Date_W(TR_BYTE_PTR pData, TR_ULONG pDataLen){

}
TR_RV Trans_Date_R(TR_BYTE_PTR pData, TR_ULONG pDataLen){

}
