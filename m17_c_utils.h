#ifndef M17_C_UTILS_H
#define M17_C_UTILS_H

#include <string.h>

#include "m17_utils.h"

/** character map for the C version */
const char * c_charMap = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/.";

/** encode an address (call sign) into base 40 */
static unsigned long m17_addr_cencode(const char *address, unsigned int len)
{
    long value = 0;
    long encoded = 0;
    if(len < 10) {
        if(0 == strcmp(address, "ALL")) {
            encoded = 0xFFFFFFFFFFFF;
        }
        else {
            for (int i = (len - 1); i > -1; --i) {
                //qDebug()<<"Address[i]:"<<address[i]<<&ccharMap;
                value = strchr(c_charMap, address[i]) - c_charMap;
                //qDebug()<<"Value index:"<<value<<c_charMap[value];
                if(value < 0) {
                    value = 0;
                }
                encoded = (encoded * 40) + value;
                //qDebug()<<"encoded["<<i<<"]:"<<encoded;
            }
        }
        //qDebug()<<"Encoded Out:"<<encoded;
    }

    return (unsigned long) encoded;
}

/** decode a base 40 address (call sign) into plain text */
static void m17_addr_cdecode(char *out, unsigned long encoded) {
    //"0000038fe411"
    //qDebug()<<"decode:"<<encoded.toHex();
    //ulong enc = std::stoul(encoded, 0, 16);
    //qDebug()<<"encoded:"<<encoded;//<<encoded.toHex().toLong(0, 16);
    if(encoded == 0xFFFFFFFFFFFF) {
        strncpy(out, "ALL", 3);
    }
    else if ((encoded == 0) || (encoded >= 0xEE6B28000000)){
        strncpy(out, "RESERVED", 8);
    }
    else {
        while (encoded > 0) {
            //qDebug()<<"char:"<<c_charMap[encoded % 40];
            strncat(out, &c_charMap[encoded % 40], 1);
            encoded = encoded / 40;
            //qDebug()<<"next enc:"<<encoded;
        }
    }
    //qDebug()<<"c decode out:"<<out;
}

// width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
// residue=0x0000 name="CRC-16/M17"
/** C version of building a CRC value based on CRC-16/M17 */
static unsigned short crc_ccitt_cbuild(unsigned char *data, unsigned long len) {

    unsigned long i, j, c, bit;
    unsigned long crc = crcinit;

    unsigned char * p = data;

    // fast bit by bit algorithm without augmented zero bytes.
    // does not use lookup table, suited for polynom orders between 1...32.

    for (i=0; i<len; i++) {

        c = (unsigned long)*p++;
        //if (refin) c = reflect(c, 8);

        for (j=0x80; j; j>>=1) {

            bit = crc & crchighbit;
            crc<<= 1;
            if (c & j) bit^= crchighbit;
            if (bit) crc^= polynom;
        }
    }

    //if (refout) crc=reflect(crc, order);
    crc^= crcxor;
    crc&= crcmask;

    return(crc);
}

// STILL NEED TO CREATE build LSF and build LICH functions here

#endif // M17_C_UTILS_H
