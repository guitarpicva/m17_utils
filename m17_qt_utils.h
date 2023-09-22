#ifndef M17_QT_UTILS_H
#define M17_QT_UTILS_H

#include "m17_utils.h"

#include <QByteArray>
#include <QDataStream>
#include <QString>
#include <QDebug>

/** character map used to encode textual addresses into base 40 */
const QString q_charMap = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/.";

/** encode an address (call sign) in base 40 */
static QByteArray m17_addr_qencode(const QByteArray address) {
    QString numout;

    long value = 0, encoded = 0;
    if(address.length() < 10) {
        if(address == "ALL") {
            encoded = 0xFFFFFFFFFFFF;
        }
        for (int i = (address.length() - 1); i > -1; --i) {
            value = q_charMap.indexOf(address[i]);
            if(value < 0) {
                value = 0;
            }
            encoded = (encoded * 40) + value;
        }

        // now load into a QString to convert to bytes
        numout = QString::number(encoded, 16);
        const int MAX = 12 - numout.length();
        for(int i = 0; i < MAX; ++i) {
            numout.prepend('0');
        }
    }
    return QByteArray::fromHex(numout.toLocal8Bit()); // empty is error!
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
            out = out + q_charMap[enc % 40];
            enc = enc / 40;
            //qDebug()<<"next enc:"<<enc;
        }
    }
    //qDebug()<<"out:"<<out;
    return out.toLocal8Bit();
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

/** Build the LSF from components, adding the CRC on the end */
static QByteArray build_qLSF(QByteArray dest, QByteArray source, QByteArray meta, \
                           bool isStream = true, uint datatype = 1, uint encryptionType = 0, uint encryptionSubtype = 0, \
                           uint can_type = 0, uint reserved = 0)
{
    QByteArray out;
    out.append(dest).append(source);
    quint16 mask = 0; // mask takes in stream type, data type, enc type, enc subtype, can, and reserved bits
    if(isStream) {
        mask =32768; // one in the left most bit 0x1000000000000000
    }
    //
//qDebug()<<"Stream Mask:"<<mask;
    // data type 00 res, 01 data, 10 voice, 11 voice  + data
    switch(datatype) {
    case 0:break; // equiv to mask += 0;
    case 1: mask += DATATYPE; break;
    case 2: mask += VOICETYPE; break;
    case 3: mask += VOICEDATA; break;
    }
    //qDebug()<<"Data Mask:"<<mask;
    QByteArray temp;
    temp.setNum(mask, 16);
    //qDebug()<<"Temp:"<<temp;
    out.append(QByteArray::fromHex(temp));
    out.append(meta);
    // now add the CRC to the end
    temp.clear();
    temp.setNum(crc_ccitt_qbuild(out), 16);
    //qDebug()<<"CRC:"<<QByteArray::fromHex(temp.toHex());
    out.append(QByteArray::fromHex(temp));
    return out;
/*
The LSF is the initial frame for both Stream and Packet Modes and contains information needed
to establish a link.
Field Length Description
6 - DST 48 bits Destination address - Encoded callsign or a special number (eg. a group)
6 - SRC 48 bits Source address - Encoded callsign of the originator or a special number (eg. a group)
2 - TYPE 16 bits Information about the incoming data stream
14 -META 112 bits Metadata field, suitable for cryptographic metadata like IVs or single-use
numbers, or non-crypto metadata like the sender’s GNSS position.
2 - CRC 16 bits CRC for the link setup data

Table 2.4: Link Setup Frame TYPE Contents 16 bits
        Bits Contents
        0    Packet/Stream indicator
        1..2 Data type indicator
        3..4 Encryption type
        5..6 Encryption subtype
        7..10 Channel Access Number (CAN)
        11..15 Reserved (don’t care)*/
}

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
static QByteArray build_qLICH(const QByteArray lsf, const int lich_cnt)
{
//  const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
    int index = 0;
    quint8 zero = 0, one = 32, two = 64, three = 96, four = 128, five = 160;
    QByteArray out = "";
    QDataStream ds(&out, QIODeviceBase::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);

    switch(lich_cnt) {
    case 0:ds<< lsf.mid(25)<<zero;break;
    case 1:ds<< lsf.mid(20, 5)<<one;break;
    case 2:ds<< lsf.mid(15, 5)<<two;break;
    case 3:ds<< lsf.mid(10, 5)<<three;break;
    case 4:ds<< lsf.mid(5, 5)<<four;break;
    case 5:ds<< lsf.mid(0, 5)<<five;break;
    }
    out = out.mid(4); // remove the length int on the front rom the first <<
    //qDebug()<<"LICH:"<<out;
    return out;
}
#endif // M17_QT_UTILS_H
