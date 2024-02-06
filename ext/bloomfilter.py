'Bloom filter class'

from bitarray import bitarray
import hashlib as ha
from pox.lib import addresses as addr


class bloomfilter(object):

    def __init__(self, size=128, k=5):
        self.size = size
        self.k = k
        self.bitarray = bitarray(size)
        self.bitarray.setall(0)
        # counts the elements in bloom filter, could be usefull later
        self.elements = 1

    def double_hash(self, mac_addr):
        md5hex = ha.md5(mac_addr).hexdigest()
        sha1hex = ha.sha1(mac_addr).hexdigest()
        for i in range(1, self.k + 1):
            h_k = (int(md5hex, base=16) + i * (int(sha1hex, base=16))) % self.size
            self.bitarray[h_k] = 1

    # Merge two bloomfilters/links together
    def merge(self, bloomfilter):
        new_bitarray = self.bitarray | bloomfilter.bitarray
        new_bloomfilter = self.set_bloomfilter_by_array(new_bitarray)
        new_bloomfilter.elements = self.elements + bloomfilter.elements
        return new_bloomfilter

    def contains(self, bloomfilter):
        if self.bitarray & bloomfilter.bitarray == self.bitarray:
            return True
        else:
            return False

    def empty(self):
        return self.bitarray.any()

    def to_IPv6(self):
        raw_bloom_filter = self.bitarray.tobytes()
        return addr.IPAddr6(raw=raw_bloom_filter)

    def to_IPv6_str(self):
        IPv6 = self.to_IPv6()
        return str(IPv6)

    # Bloom filter construction Factory methods
    @classmethod
    def set_bloomfilter_by_mac(bloomfilter, mac_addr):
        bloomfilter_obj = bloomfilter()
        bloomfilter_obj.double_hash(mac_addr)
        return bloomfilter_obj

    @classmethod
    def set_bloomfilter_by_array(bloomfilter, array):
        bloomfilter_obj = bloomfilter(array.length())
        bloomfilter_obj.bitarray = array
        return bloomfilter_obj

    #####

    def __str__(self):
        return self.bitarray.to01()
