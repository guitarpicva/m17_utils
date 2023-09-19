#ifndef M17_UTILS_H
#define M17_UTILS_H

#include <QByteArray>
#include <QString>
#include <QDebug>

/** CRC code adapted from http://www.zorc.breitbandkatze.de/crctester.c
 *  CRC tester v1.3 written on 4th of February 2003 by Sven Reifegerste (zorc/reflex)
 *  CRC configuration for M17:
 *  width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
 *  residue=0x0000 name="CRC-16/M17"
*/
const int order = 16;
const unsigned long polynom = 0x5935;
const int direct = 1;
const unsigned long crcinit = 0xffff;
const unsigned long crcxor = 0x0000;
const int refin = 0;
const int refout = 0;

/** internal global CRC values: */
// compute constant bit masks for whole CRC and CRC high bit
unsigned long crcmask = ((((unsigned long)1<<(order-1))-1)<<1)|1;;
unsigned long crchighbit = (unsigned long)1<<(order-1);
unsigned long crcinit_direct = crcinit;
// END CRC Defaults

/** character map used to encode textual addresses into base 40 */
const QString charMap = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -/. ";

/** encode an address (call sign) in base 40 */
static QByteArray m17_addr_qencode(const QByteArray address) {
    QString numout;

    long value = 0, encoded = 0;
    if(address.length() < 10) {
        if(address == "ALL") {
            encoded = 0xFFFFFFFFFFFF;
        }
        else {
            encoded = 0;
        }
        for (int i = (address.length() - 1); i > -1; --i) {
            value = charMap.indexOf(address[i]);
            //qDebug()<<"Value:"<<value<<address[i];
            if(value < 0) {
                value = 0;
            }
            encoded = (encoded * 40) + value;
            //qDebug()<<"Encoded:"<<encoded;
        }

        // now load into a QByteArray
        numout = QString::number(encoded, 16);
        const int MAX = 12 - numout.length();
        for(int i = 0; i < MAX; ++i) {
            numout.prepend('0');
        }
    }
    return numout.toLocal8Bit(); // empty is error!
}

/** decode a base 40 address (call sign) into plain text */
static QByteArray m17_addr_qdecode(const QByteArray encoded) {
    //"0000038fe411"
    //qDebug()<<"decode:"<<encoded.toHex();
    QString out = "";
    ulong enc = encoded.toHex().toLong(0, 16);
    //qDebug()<<"enc:"<<enc<<encoded.toHex().toLong(0, 16);
    if(enc == 0xFFFFFFFFFFFF) {
        out = "ALL";
    }
    else if (enc == 0) {
        out = "RESERVED";
    }
    else if(enc >= 0xEE6B28000000) {
        out = "RESERVED";
    }
    else {
        while (enc > 0) {
            //qDebug()<<"char:"<<charMap[enc % 40];
            out = out + charMap[enc % 40];
            enc = enc / 40;
            //qDebug()<<"next enc:"<<enc;
        }
    }
    //qDebug()<<"out:"<<out;
    return out.toLocal8Bit();
}

/** stdlib : encode an address (call sign) in base 40 */
static ulong m17_addr_stdlib_encode(const std::string address) {
    std::string numout;

    long value = 0, encoded = 0;
    if(address.length() < 10) {
        if(address == "ALL") {
            encoded = 0xFFFFFFFFFFFF;
        }
        else {
            encoded = 0;
        }
        for (int i = (address.length() - 1); i > -1; --i) {
            value = charMap.toStdString().find(address[i]);
            qDebug()<<"Value:"<<value<<address[i];
            if(value < 0) {
                value = 0;
            }
            encoded = (encoded * 40) + value;
            //qDebug()<<"Encoded:"<<encoded;
        }
        qDebug()<<"Encoded:"<<encoded;
    }
    return encoded;

    //        // now load into a std::string
    //numout = std::to_string(encoded);
    //        qDebug()<<"numout std::string:"<<numout.c_str();
    //        const int MAX = 12 - numout.length();
    //        for(int i = 0; i < MAX; ++i) {
    //            numout.insert(0, "0");
    //        }
    //    }
    //    return numout; // empty is error!
}

/** Qt version of building a CRC value based on CRC-16/M17 */
static quint16 crc_ccitt_qbuild(const QByteArray data) {

    unsigned long i, j, c, bit, len;
    unsigned long crc = crcinit;
    len = data.length();
    unsigned char * p = (unsigned char*) data.data();

    // fast bit by bit algorithm without augmented zero bytes.

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

// width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
// residue=0x0000 name="CRC-16/M17"
/** C version of building a CRC value based on CRC-16/M17 */
static quint16 crc_ccitt_build(unsigned char *data, ulong len) {

    unsigned long crcinit_direct = crcinit;

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

// width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
// residue=0x0000 name="CRC-16/M17"
/** C++ stdlib version of building a CRC value based on CRC-16/M17 */
static quint16 crc_ccitt_cppbuild(std::string data) {
    unsigned long len = data.length();
    unsigned long crcinit_direct = crcinit;

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


#endif // M17_UTILS_H
