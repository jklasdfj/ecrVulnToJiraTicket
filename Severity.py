from enum import Enum

# https://docs.python.org/3/howto/enum.html#orderedenum
class OrderedEnum(Enum):
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented
    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

class Severity(OrderedEnum): # number represents ticket priority level we use in jira, lower is higher
    LOW = 4
    MEDIUM = 3
    HIGH = 2
    CRITICAL = 1

    @staticmethod
    def from_raw(raw):
        if isinstance(raw, Severity):
            return raw
        if isinstance(raw, str):
            mapping = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.HIGH,
                'MEDIUM': Severity.MEDIUM,
                'LOW': Severity.LOW,
            }
            return mapping.get(raw.upper(), Severity.LOW)
        raise TypeError(f'Unsupported severity value: {raw!r}')
