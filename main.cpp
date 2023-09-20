#include <QCoreApplication>
#include "m17_utils.h"
#include <stdlib.h>
#include <QDebug>

int main(int argc, char *argv[])
{
    const QByteArray addr("AB4MW");
    qDebug()<<"Encode AB4MW Qt:"<<m17_addr_qencode(addr);
    qDebug()<<"Encode AB4MW stdlib:"<<QString::number(m17_addr_stdlib_encode(addr.toStdString()), 16);
    qDebug()<<"Decode EE:"<<m17_addr_qdecode(QByteArray::fromHex("EE6B28000000"));
    qDebug()<<"Decode 0:"<<m17_addr_qdecode(QByteArray::fromHex("000000000000"));
    qDebug()<<"Decode FF:"<<m17_addr_qdecode(QByteArray::fromHex("FFFFFFFFFFFF"));
    qDebug()<<"Decode Qt Encoded AB4MW:"<<m17_addr_qdecode(QByteArray::fromHex("0000038fe411"));
    qDebug()<<"Decode stdlib Encoded AB4MW:"<<m17_addr_stdlib_decode(59761681u).c_str();

    qDebug()<<"qCRC for 123456789:"<<crc_ccitt_qbuild(QString("123456789").toLatin1());
    qDebug()<<"qCRC for A:"<<crc_ccitt_qbuild(QString("A").toLatin1());
    qDebug()<<"qCRC for <empty>:"<<crc_ccitt_qbuild(QString("").toLatin1());

    qDebug()<<"cCRC for 123456789:"<<crc_ccitt_build((unsigned char*)"123456789", 9);
    qDebug()<<"cCRC for A:"<<crc_ccitt_build((unsigned char*)"A", 1);
    qDebug()<<"cCRC for <empty>:"<<crc_ccitt_build((unsigned char*)"", 0);

    qDebug()<<"cppCRC for 123456789:"<<crc_ccitt_cppbuild(std::string("123456789"));
    qDebug()<<"cppCRC for A:"<<crc_ccitt_cppbuild(std::string("A"));
    qDebug()<<"cppCRC for <empty>:"<<crc_ccitt_cppbuild(std::string(""));
    return 0;
}
