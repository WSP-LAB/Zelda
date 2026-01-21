
import time

from multiprocessing import shared_memory


class CoverageCheckerPCOV:

    def __init__(self):
        self._shared_mem_name = 'fuzzer_coverage_mem'
        self._shared_mem_size = 2048
        self._shared_mem = None

    def OpenNewMemory(self):
        self._shared_mem = shared_memory.SharedMemory(
            name=self._shared_mem_name, create=True, size=self._shared_mem_size)
        for i in range(self._shared_mem_size):
            self._shared_mem.buf[i:(i+1)] = bytes.fromhex('00')
        return self._shared_mem

    def OpenExistingMemory(self):
        self._shared_mem = shared_memory.SharedMemory(self._shared_mem_name)
        return self._shared_mem

    def CheckUpdate(self, given_bitmap):
        # 1) Get the current coverage
        current_bitmap = self._shared_mem.buf
        int_current_bitmap = int.from_bytes(current_bitmap, 'little')
        # 2) Check whether given coverage | current coverage change the current coverage
        or_bitmap = self.orbytes(given_bitmap, bytes(current_bitmap))
        int_or_bitmap = int.from_bytes(or_bitmap, 'little')
        # if there is no change, return False indicating "no update necessary."
        if int_or_bitmap == int_current_bitmap:
            #print("CCoverage: ", int_current_bitmap, ", GCoverage: ", coverage_bitmap, ", Given Coverage|Current Coverage: ", int_or_bitmap)
            return False
        else:
            return True

    def GetCurrentCoverage(self):
        return bytes(self._shared_mem.buf)

    def orbytes(self, abytes, bbytes):
        #print ("A Bytes, ", abytes, ", Type:" , type(abytes))
        #print ("B Bytes, ", bbytes, ", Type:" , type(bbytes))
        return bytes([a | b for a, b in zip(abytes, bbytes)])

    def UpdateCoverage(self, coverage_bitmap):
        or_bytes = self.orbytes(coverage_bitmap, bytes(self._shared_mem.buf))
        #print('[Given Coverage]:', coverage_bitmap)
        #print('[Computed OR Coverage]:', bytes)
        for i in range(len(or_bytes)):
            #byte = int(bytes[i:(i+1)], 16)
            #print("Bytes[", i, "]: ", or_byte)
            #print("Bytes[", i, "]: ", or_bytes[i:(i+1)])
            self._shared_mem.buf[i:(i+1)] = or_bytes[i:(i+1)]
        #self._shared_mem.buf[:] = bytes
