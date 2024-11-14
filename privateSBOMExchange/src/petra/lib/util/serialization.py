import base64

def stringify(self, buffer):
    return bytes(buffer).decode("utf-8")

def to_b64_str(data: bytes) -> str:
    """Returns a utf-8 encoded string for
       the base64 encoding of the input data.
    """
    return base64.b64encode(data).decode("utf-8")
