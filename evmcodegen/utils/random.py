#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Author : <github.com/tintinweb>
import random
import binascii


class WeightedRandomizer(object):
    # https://stackoverflow.com/a/14993631/1729555
    def __init__(self, weights):
        self.__max = .0
        self.__weights = []
        for value, weight in weights.items():
            self.__max += weight
            self.__weights.append((self.__max, value))

    def random(self):
        r = random.random() * self.__max
        for ceil, value in self.__weights:
            if ceil > r:
                return value


def random_gauss(mu, sigma, bottom=None, top=None):
    while True:
        rndval = int(random.gauss(mu, sigma))
        if (bottom is not None and top is not None) and bottom <= rndval <= top:
            break
    return rndval


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def bytes_to_hexstr(b, prefix=""):
    return "%s%s" % (prefix, binascii.hexlify(b).decode("utf-8"))