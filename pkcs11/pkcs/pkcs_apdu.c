#include "pkcs_apdu.h"

/*Four Modes APDU Trans.
 * MODE 1:
 *  CLA INS P1  P2  00
 *  SW1 SW2
 *
 * MODE 2:
 *  CLA INS P1  P2  Le
 *  Le-bytes-Data   SW1 SW2
 *
 * MODE 3:
 *  CLA INS P1  P2  Lc  Lc-bytes-Data
 *  SW1 SW2
 *
 * MODE 4:
 *  CLA INS P1  P2  Lc  Lc-bytes-Data   Le
 *  Le-bytes-Data   SW1 SW2
 *
 * Attention :
 *  Send Message Use Mode 2or4
 *      Mode 2 use to Send without arg data
 *      Mode 4 use to Send with lc-bytes-length data
 *  Recv Message Use Mode 2
 *      Mode 2 use to Recv with Speciry length of data
*/

uint32_t PKCS_APDU_Build(uint32_t FLAG,uint8_t* buf,uint8_t* arg,uint32_t arg_len,uint32_t buflen){

    return 0;
}
