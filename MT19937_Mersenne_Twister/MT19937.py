from Lab1 import *
import sys

# Mersenne Twister MT 19937

# Mzg3NDg3OTI5NDozMzgyNjQ2MjYzOjc4MzU0MzQ0MToyNDMxMTk1OTM0Ojg2NDM4NzA2NDozODg4NTA4OTE6MTY4MzA2NDQ5MDoxNjE2NTE5MDk=


class MT19937:
    def __init__(self, seed):
        # TODO: Initialize MT state here
        self.seed = seed_mt(int.from_bytes(seed, byteorder=sys.byteorder))

    def extract_number(self):
        # TODO: Temper and Extract Here
        return extract_number1()

    def generate_number(self):
        # TODO: Mix state here
        twist()



