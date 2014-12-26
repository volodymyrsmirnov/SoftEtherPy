import struct


class SoftEtherProtocol(object):
    payload = b''
    offset = 0

    data = {}

    def __init__(self, payload=b''): 
        self.payload = payload

    def get_raw(self, size):
        raw = self.payload[self.offset:self.offset+size]
        self.offset += size
        return raw

    def get_int_impl(self, size):
        raw = self.get_raw(size)
        return struct.unpack('!I' if size == 4 else '!Q', raw)[0]

    def get_int(self):
        return self.get_int_impl(4)

    def get_int64(self):
        return self.get_int_impl(8)

    def get_string(self, offset=0):
        return self.get_raw(self.get_int() - offset)

    def deserialize(self, with_type=False):
        self.data = {}
        output = {}

        count = self.get_int()

        for i in range(0, count):
            key = self.get_string(1).decode('ascii', 'ignore')

            key_type = self.get_int()

            key_value_count = self.get_int()
            key_value_getter = lambda: b''

            if key_type == 0:
                key_value_getter = self.get_int

            elif key_type in [1, 2, 3]:
                key_value_getter = self.get_string

            elif key_type == 4:
                key_value_getter = self.get_int64

            key_value = []

            for j in range(0, key_value_count):
                key_value.append(key_value_getter())

            if key_type == 2:
                key_value = list([value.decode('ascii', 'ignore') for value in key_value])

            elif key_type == 3:
                key_value = list([value.decode('utf-8', 'ignore') for value in key_value])

            self.data[key] = (key_type, key_value)
            output[key] = key_value

        return self.data if with_type else output

    def set_raw(self, raw):
        self.payload += raw if type(raw) is bytes else str.encode(raw)

    def set_int_impl(self, value, size):
        raw = struct.pack('!i' if size == 4 else '!q', value)
        self.set_raw(raw)
    
    def set_int(self, value):
        self.set_int_impl(value, 4)

    def set_int64(self, value):
        self.set_int_impl(value, 8)

    def set_boolean(self, value):
        self.set_int(1 if value else 0)

    def set_data(self, value):
        self.set_int(len(value))
        self.set_raw(value)

    def set_string(self, value, offset=0):
        value = value.encode('ascii', 'ignore')

        self.set_int(len(value) + offset)
        self.set_raw(value)

    def set_ustring(self, value, offset=0):
        value = value.encode('utf-8', 'ignore')

        self.set_int(len(value) + offset)
        self.set_raw(value)

    def serialize(self, data):
        self.data = {}
        self.payload = b""

        self.set_int(len(data))

        for key, value_tuple in data.items():
            value_type, value = value_tuple

            if type(value_type) is int:
                value_type_int = value_type

            else:
                if value_type == 'int':
                    value_type_int = 0

                elif value_type == 'raw':
                    value_type_int = 1

                elif value_type == 'string':
                    value_type_int = 2

                elif value_type == 'ustring':
                    value_type_int = 3

                elif value_type == 'int64':
                    value_type_int = 4

                else:
                    value_type_int = 1

            self.data[key] = (value_type_int, value)

            key_value_setter = lambda v: v

            if value_type_int == 0:
                key_value_setter = self.set_int

            elif value_type_int == 1:
                key_value_setter = self.set_data

            elif value_type_int == 2:
                key_value_setter = self.set_string

            elif value_type_int == 3:
                key_value_setter = self.set_ustring

            elif value_type_int == 4:
                key_value_setter = self.set_int64

            self.set_string(key, 1)
            self.set_int(value_type_int)
            self.set_int(len(value))

            for value_item in value:
                key_value_setter(value_item)

        return self.payload
