#ifndef M17_CPP_UTILS_H
#define M17_CPP_UTILS_H

#include "m17_utils.h"

#include <stdlib.h>
#include <string>
#include <vector>


/** character map for the C++ stdlib version */
const std::string std_string_charMap = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/.";

/** stdlib : encode an address (call sign) in base 40 */
static std::vector<unsigned char> m17_addr_stdlib_encode(const std::string address) {
    long value = 0, encoded = 0;
    if(address.length() < 10) {
        if(address == "ALL") {
            encoded = 0xFFFFFFFFFFFF;
        }
        for (int i = (address.length() - 1); i > -1; --i) {
            value = std_string_charMap.find(address[i]);
            qDebug()<<"String Value:"<<value<<address[i];
            if(value < 0) {
                value = 0;
            }
            encoded = (encoded * 40) + value;
            //qDebug()<<"Encoded:"<<encoded;
        }
        //qDebug()<<"Encoded:"<<encoded;
    }
    std::vector<uint8_t> v;
    v.reserve(sizeof(encoded));
    // only the last 6 bytes of the long are important here
    for (size_t i = 2; i < sizeof(encoded); ++i) {
        v.insert(v.begin(), encoded & 0xFF);
        encoded >>= 8;
    }
//    v.erase(v.begin());
//    v.erase(v.begin());
    //qDebug()<<"V:"<<v<<v.size();
    //return encoded; // zero is an error
    return v;
}

/** decode a base 40 address (call sign) into plain text */
static std::string m17_addr_stdlib_decode(uint64_t encoded) {
    //"0000038fe411"
    //qDebug()<<"decode:"<<encoded.toHex();
    std::string out = "";
    //ulong enc = std::stoul(encoded, 0, 16);
    //qDebug()<<"encoded:"<<encoded;//<<encoded.toHex().toLong(0, 16);
    if(encoded == 0xFFFFFFFFFFFF) {
        out = "ALL";
    }
    else if (encoded == 0) {
        out = "RESERVED";
    }
    else if(encoded >= 0xEE6B28000000) {
        out = "RESERVED";
    }
    else {
        while (encoded > 0) {
            //qDebug()<<"char:"<<charMap[enc % 40];
            out = out + std_string_charMap[encoded % 40];
            encoded = encoded / 40;
            //qDebug()<<"next enc:"<<enc;
        }
    }
    //qDebug()<<"stdlib out:"<<out.c_str();
    return out;
}

// width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
// residue=0x0000 name="CRC-16/M17"
/** C++ stdlib version of building a CRC value based on CRC-16/M17 */
static uint16_t crc_ccitt_cppbuild(std::string data) {
    unsigned long len = data.length();
    unsigned long i, j, c, bit;
    unsigned long crc = crcinit;
    unsigned char * p = (unsigned char*)data.c_str();

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

/** build LSF from components */
static std::vector<unsigned char> build_cpp_LSF(std::vector<unsigned char> dest, std::vector<unsigned char> source, std::string meta, \
                                                                                                                                      bool isStream = true, uint datatype = 1, uint encryptionType = 0, uint encryptionSubtype = 0, \
                                                                            uint can_type = 0, uint reserved = 0)
{
    std::vector<unsigned char> out;
    return out;
}

// STILL NEED TO CREATE build LICH function here
/*
Link Information Channel (LICH) The LICH allows for late listening and independent de-
coding to check destination address if the LSF for the current transmission was missed.
Each Stream Frame contains a 48-bit Link Information Channel (LICH). Each LICH within a
Stream Frame includes a 40-bit chunk of the 240-bit LSF frame that was used to establish the
stream. A 3-bit modulo 6 counter (LICH_CNT) is used to indicate which chunk of the LSF is
present in the current Stream Frame. LICH_CNT starts at 0, increments to 5, then wraps back
to 0.
Bits Content
0..39 40-bit chunk of full LSF Contents (Type 1 bits)
40..42 LICH_CNT
43..47 Reserved
Table 2.11: Link Information Channel Contents
Total: 48 bits
The 40-bit chunks start with the most significant byte of the LSF.
LICH_CNT LSF bits
0 239:200
1 199:160
2 159:120
3 119:80
4 79:40
5 39:0
Table 2.12: LICH_CNT and LSF bits
*/
static std::vector<uint8_t> build_qLICH(const std::string lsf, const int lich_cnt)
{
    //  const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
    int32_t index = 0;
    uint8_t zero = 0, one = 32, two = 64, three = 96, four = 128, five = 160;
    std::vector<uint8_t> out;
    //QDataStream ds(&out, QIODeviceBase::WriteOnly);
//    ds.setByteOrder(QDataStream::LittleEndian);

//    switch(lich_cnt) {
//    case 0:ds<< lsf.mid(25)<<zero;break;
//    case 1:ds<< lsf.mid(20, 5)<<one;break;
//    case 2:ds<< lsf.mid(15, 5)<<two;break;
//    case 3:ds<< lsf.mid(10, 5)<<three;break;
//    case 4:ds<< lsf.mid(5, 5)<<four;break;
//    case 5:ds<< lsf.mid(0, 5)<<five;break;
//    }
//    out = out.mid(4); // remove the length int on the front rom the first <<
    //qDebug()<<"LICH:"<<out;
    return out;
}
#endif // M17_CPP_UTILS_H
