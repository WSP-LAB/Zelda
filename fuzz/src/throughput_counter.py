
import time

from multiprocessing import Value


class ThroughputCounter:
    def __init__(self):
        self._counter = Value('i', 0)
        self._start_time = 0

    def StartTimer(self):
        self._start_time = time.perf_counter()
        return self._start_time

    def AddCounter(self, num):
        with self._counter.get_lock():
            self._counter.value += num

    def GetElapsedTime(self):
        return time.perf_counter() - self._start_time

    def GetThroughput(self):
        return self._counter.value / (time.perf_counter() - self._start_time)

    def GetTotalCount(self):
        return self._counter.value