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

VALUEMAP ={
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


class CodeGen(object):
    """
    CodeGen().generate(length,min_gas).add_stack_args(valuemap)
    """

    def __init__(self, instructions=None):
        self.instructions = instructions

    @property
    def instructions(self):
        return self._instructions

    @instructions.setter
    def instructions(self, instructions):
        if isinstance(instructions, evmdasm.EvmInstructions):
            self._instructions = instructions
        elif isinstance(instructions, list):
            self._instructions = evmdasm.EvmInstructions(instructions=instructions)
        elif instructions is None:
            self._instructions = evmdasm.EvmInstructions(instructions=[])
        else:
            raise TypeError("invalid type for instructions. evmdasm.EvmInstructions or [] expected")
        return self

    @staticmethod
    def build_stack_layout(instructions, valuemap):
        for instr in instructions:
            if instr.name.startswith("PUSH"):
                Rnd.randomize_operand(instr)  # push random stuff
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

    def generate(self, generator, length=None, min_gas=0):
        instructions = []
        # generate instruction
        while min_gas >= 0:
            instructions += [evmdasm.registry.create_instruction(opcode=opcode) for opcode in generator.generate(length)]
            min_gas -= evmdasm.EvmInstructions(instructions).get_gas_required()

        self.instructions = instructions  # add or replace?
        return self

    def fix_stack_arguments(self, valuemap):
        self.instructions = list(CodeGen.build_stack_layout(instructions=self.instructions, valuemap=valuemap))
        return self

    def reassemble(self):
        # serialize and disassemble to have addresses and stuff fixed
        self.instructions = self.instructions.assemble().disassemble()
        return self

    def assemble(self):
        assembled = self.instructions.assemble()
        return assembled

    def fix_jumps(self):
        # fix JUMP/JUMPI landing on JUMPDEST
        # reuse existing jumpdestß
        # serialize f

        self.reassemble()  # can only work on disassembled code

        # strategy: add random jumpdests and make jump/jumpis point to jumpdest
        disassembly = self.instructions
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

        self.instructions = disassembly
        return self

    def fix_stack_balance(self, balance=0):
        depth = self.instructions.get_stack_balance() + balance

        # append pushes or pops to balance the stack
        self.instructions += [evmdasm.registry.create_instruction("PUSH1" if depth <= 0 else "POP") for _ in range(depth)]
        return self

    def mutate(self, mutator):
        raise NotImplementedError("not yet implemented")
        return self

    def stats(self):
        self.reassemble()
        out = []
        out.append("========stats==========")
        out.append("instructions: %s" % len(self.instructions))
        out.append("gas (all instructions: %s" % self.instructions.get_gas_required())
        from collections import Counter

        stats_instructions = Counter([instr.opcode for instr in self.instructions])
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

            out.append("%-20s | %-f%%" % (name, cnt / total * 100))
        return '\n'.join(out)


def main():

    from optparse import OptionParser

    parser = OptionParser()
    loglevels = ['CRITICAL', 'FATAL', 'ERROR', 'WARNING', 'WARN', 'INFO', 'DEBUG', 'NOTSET']
    parser.add_option("-v", "--verbosity", default="critical",
                      help="available loglevels: %s [default: %%default]" % ','.join(l.lower() for l in loglevels))

    parser.add_option("-g", "--generator", default="GaussDistrCategory", help="select generator (default: DistrCategory)")
    parser.add_option("-d", "--disassemble", action="store_true", help="show disassembly")
    parser.add_option("-c", "--count", default=1, type=int, help="number of evmcodes to generate")
    parser.add_option("-m", "--min-gas", default=0, type=int, help="generate instructions consuming at least this amount of gas")
    parser.add_option("-l", "--length", default=-1, type=int,
                      help="instructions per generated code")
    parser.add_option("-s", "--stats", default=True, action="store_true", help="show statistics")
    parser.add_option("-b", "--balance", default=False, action="store_true", help="balance the stack")
    # parse args
    (options, args) = parser.parse_args()

    if options.generator == "GaussDistrCategory":
        rnd_codegen = GaussDistrCodeGen(distribution=EVM_CATEGORY)
    elif options.generator == "Rnn":
        rnd_codegen = RnnCodeGen()
        # rnd_codegen.temperature = 0.2
    else:
        parser.error("--missing generator--")

    options.length = options.length if options.length >= 0 else None

    while options.count >0:
        evmcode = CodeGen()\
            .generate(generator=rnd_codegen, length=options.length, min_gas=options.min_gas)\
            .fix_stack_arguments(valuemap=VALUEMAP)\
            .fix_jumps()
        if options.balance:
            evmcode.fix_stack_balance()
        print("0x%s" % evmcode.assemble().as_hexstring)
        if options.disassemble:
            print(evmcode.reassemble().instructions.as_string)
        if options.stats:
            print(CodeGen.stats(evmcode))
        options.count -= 1


if __name__=="__main__":
    main()
