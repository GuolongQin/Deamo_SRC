#ifndef PKCS_APDU_H
#define PKCS_APDU_H
#include "stdint.h"

#define PKCS_APDU_INITIALIZE_S  0x00000001
#define PKCS_APDU_INITIALIZE_R  0x00000002
/*
FLAG--> Conver APDU Cache
Buf --> Send Cache not be NULL

*/
uint32_t PKCS_APDU_Build(uint32_t FLAG,uint8_t* buf,uint8_t* arg,uint32_t arg_len,uint32_t buflen);

#endif
