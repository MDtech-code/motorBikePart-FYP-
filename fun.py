from typing import TypeVar,List

DataType=TypeVar('DataType')

def get_item(item:List[DataType]):
    return item[0]
print(get_item([1,2,3,4,5]))
print(get_item(['a','b','c']))

def get_first_item(item):
    return item[0]
print(get_item([1,2,3,4,5]))
print(get_item(['a','b','c']))