from collections import OrderedDict

from typing import TypeVar, Generic, Optional

TValue = TypeVar('TValue')
TKey = TypeVar('TKey')

# todo unused?

class LRUCache(Generic[TKey, TValue]):
    # refactored from
    # https://www.geeksforgeeks.org/lru-cache-in-python-using-ordereddict/

    def __init__(self, capacity: int):
        self.cache: OrderedDict = OrderedDict()
        self.capacity = capacity

    def get(self, key: TKey, default: TValue = None) -> Optional[TValue]:
        # todo is it the fastest way?
        if key not in self.cache:
            return default
        else:
            self.cache.move_to_end(key)
            return self.cache[key]

    def put(self, key: TKey, value: TValue) -> None:
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
