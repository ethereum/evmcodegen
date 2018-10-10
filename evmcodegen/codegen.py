#! /usr/bin/env python
# -*- coding: utf-8 -*-
# Author : <github.com/tintinweb>
"""
Synthetic EVM Bytecode generator
"""
import binascii
import random
import evmdasm
from .utils.random import random_gauss, WeightedRandomizer, bytes_to_hexstr, int2bytes
from .distributions import EVM_BYTE, EVM_INSTRUCTION, EVM_OPCODE_PREVALANCE, EVM_CATEGORY

from .generators.base import _BaseCodeGen
from .generators.distribution import GaussDistrCodeGen
try:
    from .generators.rnn import RnnCodeGen
except ImportError as ie:
    print("RnnCodeGen not available: %r"%ie)


class Rnd:

    @staticmethod
    def randomize_operand(instr):
        instr.operand_bytes = bytes(bytearray(random.getrandbits(8) for _ in range(instr.length_of_operand)))
        return instr

    @staticmethod
    def uni_integer(min=None, max=None):
        min = min or 0
        max = max or 2**64-1
        assert(min <= max)
        # numpy.random.randint
        return min + random.randint(min, max) % (max-min)  # uniIntDist 0..0x7fffffff

    @staticmethod
    def byte_sequence(length):
        return bytearray(random.getrandbits(8) for _ in range(length))

    @staticmethod
    def percent():
        return Rnd.uni_integer(0,100)  ## percentDist 0..100 percent

    @staticmethod
    def small_uni_integer():
        return Rnd.uni_integer(1, 1024*1024*10) ## opMemrDist(gen)  <1..10MB byte string

    @staticmethod
    def length_32():
        return Rnd.uni_integer(1, 32)

    @staticmethod
    def small_memory_length_1024():
        return Rnd.uni_integer(0, 1024)

    @staticmethod
    def memory_length():
        return Rnd.uni_integer(0, 1024*1024*10)

    @staticmethod
    def opcode():
        return Rnd.uni_integer(0x00, 0xff)

valuemap ={
    evmdasm.argtypes.Address: lambda: Rnd.byte_sequence(20),
    evmdasm.argtypes.Word: lambda: Rnd.byte_sequence(32),
    evmdasm.argtypes.Timestamp: lambda: Rnd.byte_sequence(4),
    evmdasm.argtypes.Data: lambda: Rnd.byte_sequence(Rnd.uni_integer(0, Rnd.opcode())),
    evmdasm.argtypes.CallValue: lambda: Rnd.uni_integer(0,1024),
    evmdasm.argtypes.Gas: lambda: Rnd.uni_integer(0,1024),
    evmdasm.argtypes.Length: lambda: Rnd.small_memory_length_1024(),
    evmdasm.argtypes.MemOffset: lambda: Rnd.small_memory_length_1024(),
    evmdasm.argtypes.Index256: lambda: Rnd.uni_integer(1,256),
    evmdasm.argtypes.Index64: lambda: Rnd.uni_integer(1,64),
    evmdasm.argtypes.Index32: lambda: Rnd.length_32(),
    evmdasm.argtypes.Byte: lambda: Rnd.byte_sequence(1),
    evmdasm.argtypes.Bool: lambda: Rnd.byte_sequence(1),
    evmdasm.argtypes.Value: lambda: Rnd.uni_integer(),
    #evmdasm.argtypes.Label: lambda: 0xc0fefefe,  # this is handled by fix_code_layout (fix jumps)
}


class CodeGen(_BaseCodeGen):

    def __init__(self, generator, mutator=None):
        super().__init__()
        self._generator = generator
        self._mutator = mutator

    @staticmethod
    def build_stack_layout(instructions):
        for instr in instructions:
            if instr.name.startswith("PUSH"):
                Rnd.randomize_operand(instr)   # push random stuff
            elif instr.name.startswith("SWAP"):
                for _ in range(instr.pops):
                    yield Rnd.randomize_operand(evmdasm.registry.create_instruction("PUSH%s" % Rnd.uni_integer(1, 32)))
            elif instr.name.startswith("DUP"):
                for _ in range(instr.pops):
                    yield Rnd.randomize_operand(evmdasm.registry.create_instruction("PUSH%s" % Rnd.uni_integer(1, 32)))
            else:
                # prepare stack layout based on instr.args
                for arg in reversed(instr.args):
                    f = valuemap.get(arg.__class__)
                    if f:
                        yield CodeGen.create_push_for_data(f())
            yield instr

    @staticmethod
    def create_push_for_data(data):
        # expect bytes but silently convert int2bytes
        if isinstance(data, int):
            data = int2bytes(data)

        instr = evmdasm.registry.create_instruction("PUSH%d" % len(data))
        instr.operand_bytes = data
        return instr

    @staticmethod
    def fix_code_layout(bytecode):
        # fix JUMP/JUMPI landing on JUMPDEST
        # reuse existing jumpdestß

        # strategy: add random jumpdests and make jump/jumpis point to jumpdest
        disassembly = evmdasm.EvmBytecode(bytecode).disassemble()
        jumps = [j for j in disassembly if j.name in ("JUMP","JUMPI")]
        jumpdests = []
        # add n_jumps JUMPDESTS and fix the jumps to point to the correct address
        for jump in jumps:
            rnd_position = random.randrange(0, len(disassembly)-1)
            jmpdest = evmdasm.registry.create_instruction("JUMPDEST")
            disassembly.insert(rnd_position, jmpdest)  # insert fixes addresses
            jumpdests.append(jmpdest)

        # fix the stack to make the code jump to the jumpdest
        for jump in jumps:
            # find the index of the jump and insert a push right before it
            jmp_index = disassembly.index(jump)
            jumpdest = jumpdests.pop()  # pop one destination
            #
            # only need to insert the PUSH(jumpdest) as the condition/flag was already put onto the stack by fix_stack_layout
            disassembly.insert(jmp_index, CodeGen.create_push_for_data(jumpdest.address))

        return disassembly.assemble()

    def generate(self, length=50):
        instructions = [evmdasm.registry.create_instruction(opcode=opcode) for opcode in
                        self._generator.generate(length)]

        instructions = CodeGen.build_stack_layout(instructions)

        serialized = ''.join(e.serialize() for e in instructions)
        serialized = CodeGen.fix_code_layout(serialized)

        return serialized

    @staticmethod
    def stats(evmbytecode):
        print("========stats==========")
        print("instructions: %s" % len(evmbytecode.disassemble()))
        from collections import Counter

        stats_instructions = Counter([instr.opcode for instr in evmbytecode.disassemble()])
        total = sum(stats_instructions.values())
        for opcode_byte, cnt in sorted(stats_instructions.items(), key=lambda a: a[1], reverse=True):
            try:
                opcode = ord(opcode_byte)
            except:
                opcode = opcode_byte
            instr = evmdasm.registry.registry.by_opcode.get(opcode)
            if instr:
                name = instr.name
            else:
                name = "UNKNOWN_%x" % opcode

            print("%-20s | %-f%%" % (name, cnt / total * 100))


def main():

    from optparse import OptionParser

    parser = OptionParser()
    loglevels = ['CRITICAL', 'FATAL', 'ERROR', 'WARNING', 'WARN', 'INFO', 'DEBUG', 'NOTSET']
    parser.add_option("-v", "--verbosity", default="critical",
                      help="available loglevels: %s [default: %%default]" % ','.join(l.lower() for l in loglevels))

    parser.add_option("-g", "--generator", default="GaussDistrCategory", help="select generator (default: DistrCategory)")
    parser.add_option("-d", "--disassemble", action="store_true", help="show disassembly")
    parser.add_option("-c", "--count", default=1, type=int, help="number of codes to generate")
    parser.add_option("-s", "--stats", default=True, action="store_true", help="show statistics")
    # parse args
    (options, args) = parser.parse_args()


    if options.generator=="GaussDistrCategory":
        rnd_codegen = GaussDistrCodeGen(distribution=EVM_CATEGORY)
    elif options.generator=="Rnn":
        rnd_codegen = RnnCodeGen()
        # rnd_codegen.temperature = 0.2
    else:
        parser.error("--missing generator--")

    codegen = CodeGen(generator=rnd_codegen)
    for nr, evmcode in enumerate(codegen):
        print(evmcode)
        if options.disassemble:
            print(evmcode.disassemble().as_string)
        if options.stats:
            CodeGen.stats(evmcode)
        if nr >= options.count:
            break

if __name__=="__main__":
    main()
