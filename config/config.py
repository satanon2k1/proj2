BUFFER_SIZE = 2048
SIGNATURE_SIZE = 2048

from enum import Enum

class ERROR_CODE(Enum):
    WRONG_BUFFER_SIZE = 500
    WRONG_SERIAL_SIZE = 501
    WRONG_PADDING_SIZE = 502
    WRONG_PROPERTIES_NUMBER = 503

ERROR_DESC = {
    ERROR_CODE.WRONG_BUFFER_SIZE: "Wrong buffer size",
    ERROR_CODE.WRONG_SERIAL_SIZE: "Wrong serial size",
    ERROR_CODE.WRONG_PADDING_SIZE: "Wrong padding size",
    ERROR_CODE.WRONG_PROPERTIES_NUMBER: "Wrong properties number"
}
