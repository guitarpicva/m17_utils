//#include <QCoreApplication>
#include "m17_utils.h"
#include <stdlib.h>
#include <QDebug>

int main(int argc, char *argv[])
{
    const QByteArray addr("AB4MW");
    qDebug()<<"Encode AB4MW Qt:"<<m17_addr_qencode(addr);
    qDebug()<<"Encode AB4MW stdlib:"<<m17_addr_stdlib_encode(addr.toStdString());

    //qDebug()<<"Encode AB4MW stdlib:"<<QString::number(m17_addr_stdlib_encode(addr.toStdString()), 16);
    qDebug()<<"Decode EE:"<<m17_addr_qdecode(QByteArray::fromHex("EE6B28000000"));
    qDebug()<<"Decode 0:"<<m17_addr_qdecode(QByteArray::fromHex("000000000000"));
    qDebug()<<"Decode FF:"<<m17_addr_qdecode(QByteArray::fromHex("FFFFFFFFFFFF"));
    qDebug()<<"Decode Qt Encoded AB4MW:"<<m17_addr_qdecode(QByteArray::fromHex("0000038fe411"));
    qDebug()<<"Decode stdlib Encoded AB4MW:"<<m17_addr_stdlib_decode(59761681u).c_str();

    qDebug()<<"qCRC for test frame (54412):"<<crc_ccitt_qbuild(QByteArray::fromHex("0000038fe411000003b5819fa0003132333435363738393031323334"));
    qDebug()<<"qCRC for 123456789:"<<crc_ccitt_qbuild(QString("123456789").toLatin1());
    qDebug()<<"qCRC for A:"<<crc_ccitt_qbuild(QString("A").toLatin1());
    qDebug()<<"qCRC for <empty>:"<<crc_ccitt_qbuild(QString("").toLatin1());

    qDebug()<<"cCRC for 123456789:"<<crc_ccitt_cbuild((unsigned char*)"123456789", 9);
    qDebug()<<"cCRC for A:"<<crc_ccitt_cbuild((unsigned char*)"A", 1);
    qDebug()<<"cCRC for <empty>:"<<crc_ccitt_cbuild((unsigned char*)"", 0);

    qDebug()<<"cppCRC for 123456789:"<<crc_ccitt_cppbuild(std::string("123456789"));
    qDebug()<<"cppCRC for A:"<<crc_ccitt_cppbuild(std::string("A"));
    qDebug()<<"cppCRC for <empty>:"<<crc_ccitt_cppbuild(std::string(""));
    const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";

    qDebug()<<"LSF Qt test:"<<build_qLSF(m17_addr_qencode("AB4MW"), m17_addr_qencode("G4KLX"), "12345678901234").toHex();
    qDebug()<<"LSF stdlib test:"<<build_cppLSF(m17_addr_stdlib_encode("AB4MW"), m17_addr_stdlib_encode("G4KLX"), "12345678901234");

    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 0"<<build_qLICH(LSF, 0).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 1"<<build_qLICH(LSF, 1).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 2"<<build_qLICH(LSF, 2).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 3"<<build_qLICH(LSF, 3).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 4"<<build_qLICH(LSF, 4).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 5"<<build_qLICH(LSF, 5).toHex();

    qDebug()<<"Encode AB4MW c:"<<m17_addr_cencode(addr.toStdString().c_str(), addr.length());
    char cdecoded[9];
    qDebug()<<"cdecoded array:"<<QString(cdecoded).toLatin1();
    m17_addr_cdecode(cdecoded, 59761681u);
    qDebug()<<"Decode AB4MW c:"<<cdecoded;
    return 0;
}
