#ifndef _LAYER_TRANS_H_
#define _LAYER_TRANS_H_
#include <stdint.h>

#define under_linux
#define under_windows

#ifdef under_linux
#define under_os
#endif // under_linux
#define under_os

#ifdef under_windows
#define under_os
#endif

#define TRANS_OK						0x00000000
#define TRANS_ERROR_NO_DEVICE			0x00000001

#define TRANS_USB_MSD					0x00000000
#define TRANS_USB_CCID					0x00000001
#define TRANS_USB_CUSTOM				0x00000002
#define TRANS_IIC						0x00000003
#define TRANS_TCP						0x00000004
#define TRANS_UDP						0x00000005
#define TRANS_SPI						0x00000006
#define TRANS_UART						0x00000007

typedef uint32_t TR_RV;
typedef uint8_t	TR_BYTE;
typedef TR_BYTE* TR_BYTE_PTR;
typedef uint32_t TR_ULONG;
typedef uint32_t TR_FLAGS;

uint32_t set_trans_init(TR_FLAGS Trans_Way);
uint32_t set_trans_config(TR_BYTE_PTR pData,TR_ULONG pDataLen);
uint32_t set_trans_final();
#ifdef  under_os
void print_trans_info();
#endif //  under_os

TR_RV Trans_Date_W(TR_BYTE_PTR pData, TR_ULONG pDataLen);
TR_RV Trans_Date_R(TR_BYTE_PTR pData, TR_ULONG pDataLen);








#endif // !_CONNECTOR_H_

