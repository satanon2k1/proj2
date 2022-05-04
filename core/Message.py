from typing import Tuple
from config.config import BUFFER_SIZE, SIGNATURE_SIZE, ERROR_CODE
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad

def serial(buf: bytes) -> bytes:
    return long_to_bytes(buf, 2) + buf

def unserial(buf: bytes) -> Tuple(int, bytes):
    size = bytes_to_long(buf[:2])
    if len(buf) < 2 + size:
        raise Exception(ERROR_CODE.WRONG_SERIAL_SIZE)
    _buf = buf[2:size+2]
    return (size, _buf)

'''
Message:
    propNumber: 1 byte

    properties: 
        propertyName:
            size: 2 bytes
            name: {size} bytes
        propertyValue:
            size: 2 bytes
            value: {size} bytes
    ...
    [padding]
'''

class Message:
    def __init__(self, _buffer):
        if len(_buffer) != BUFFER_SIZE + SIGNATURE_SIZE:
            raise Exception(ERROR_CODE.WRONG_BUFFER_SIZE)

        self.signature = _buffer[BUFFER_SIZE:]
        self.buffer = self.msgPad(_buffer[:BUFFER_SIZE])
        self.propNumber = 0
        self.properties = {}
        self.parseBuffer()

    def msgPad(self, _buffer):
        return pad(_buffer, BUFFER_SIZE)

    def msgUnpad(self, _buffer):
        try:
            self.buffer = unpad(_buffer, BUFFER_SIZE)
        except:
            raise Exception(ERROR_CODE.WRONG_PADDING_SIZE)

    def parseBuffer(self):
        self.propNumber = bytes_to_long(self.buffer[0])
        self.buffer = self.buffer[1:]
        for _ in range(self.propNumber):
            nameLen, name = unserial(self.buffer)
            self.buffer = self.buffer[nameLen + 2:]
            valueLen, value = unserial(self.buffer)
            self.buffer = self.buffer[valueLen + 2:]
            self.properties[name] = value

        if self.propNumber != len(self.properties):
            raise Exception(ERROR_CODE.WRONG_PROPERTIES_NUMBER)

    def writeBuffer(self):
        buf = long_to_bytes(self.propNumber, 1)
        for key in self.properties:
            buf += serial(key)
            buf += serial(self.properties[key])

        self.buffer = buf

    def encode(self):
        self.writeBuffer()
        return self.msgPad(self.buffer)

    def msgVerify(self):
        signature = self.signature
        data = self.encode()
