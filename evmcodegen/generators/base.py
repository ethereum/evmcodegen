#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Author : <github.com/tintinweb>


class _BaseCodeGen(object):

    def generate(self, length=None):
        raise NotImplementedError("--not implemented--")

    def __iter__(self):
        return self

    def __next__(self):
        return self.generate()
