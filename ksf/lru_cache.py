from collections import OrderedDict


# todo add generic types

class LRUCache:
    # based on
    # https://www.geeksforgeeks.org/lru-cache-in-python-using-ordereddict/

    def __init__(self, capacity: int):
        self.cache = OrderedDict()
        self.capacity = capacity

    def get(self, key, default=None):
        # todo is it the fastest way?
        if key not in self.cache:
            return default
        else:
            self.cache.move_to_end(key)
            return self.cache[key]

    # first, we add / update the key by conventional methods.
    # And also move the key to the end to show that it was recently used.
    # But here we will also check whether the length of our
    # ordered dictionary has exceeded our capacity,
    # If so we remove the first key (least recently used)
    def put(self, key, value) -> None:
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
