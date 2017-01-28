"""
The guts for the i386 envi opcode disassembler.
"""

import re
import struct

import envi
import envi.bits as e_bits
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from . import opcode86

# Grab our register enums etc...
import envi.archs.i386.regs

# Our instruction prefix masks
# NOTE: table 3-4 (section 3.6) of intel 1 shows how REX/OP_SIZE
# interact...
INSTR_PREFIX=      0x0001
PREFIX_LOCK =      0x0002
PREFIX_REPNZ=      0x0004
PREFIX_REPZ =      0x0008
PREFIX_REP  =      0x0010
PREFIX_REP_SIMD=   0x0020
PREFIX_REP_MASK =  PREFIX_REPNZ | PREFIX_REPZ | PREFIX_REP | PREFIX_REP_SIMD
PREFIX_OP_SIZE=    0x0040
PREFIX_ADDR_SIZE=  0x0080
PREFIX_SIMD=       0x0100
PREFIX_CS  =       0x0200
PREFIX_SS  =       0x0400
PREFIX_DS  =       0x0800
PREFIX_ES  =       0x1000
PREFIX_FS  =       0x2000
PREFIX_GS  =       0x4000
PREFIX_REG_MASK=   0x8000

# envi.registers meta offsets
RMETA_LOW8  = 0x00080000
RMETA_HIGH8 = 0x08080000
RMETA_LOW16 = 0x00100000
RMETA_LOW128= 0x00800000

MODE_16 = 0
MODE_32 = 1
MODE_64 = 2

# A set of instructions that are considered privileged (mark with IF_PRIV)
# FIXME this should be part of the opcdode tables!
priv_lookup = {
    "int": True,
    "in": True,
    "out": True,
    "insb": True,
    "outsb": True,
    "insd": True,
    "outsd": True,
    "vmcall": True,
    "vmlaunch": True,
    "vmresume": True,
    "vmxoff": True,
    "vmread": True,
    "vmwrite": True,
    "rsm": True,
    "lar": True,
    "lsl": True,
    "clts": True,
    "invd": True,
    "wbinvd": True,
    "wrmsr": True,
    "rdmsr": True,
    "sysexit": True,
    "lgdt": True,
    "lidt": True,
    "lmsw": True,
    "monitor": True,
    "mwait": True,
    "vmclear": True,
    "vmptrld": True,
    "vmptrst": True,
    "vmxon": True,
}

# Map of codes to their respective envi flags
iflag_lookup = {
    opcode86.INS_RET: envi.IF_NOFALL | envi.IF_RET,
    opcode86.INS_CALL: envi.IF_CALL,
    opcode86.INS_HALT: envi.IF_NOFALL,
    opcode86.INS_DEBUG: envi.IF_NOFALL,
    opcode86.INS_CALLCC: envi.IF_CALL | envi.IF_COND,
    opcode86.INS_BRANCH: envi.IF_NOFALL | envi.IF_BRANCH,
    opcode86.INS_BRANCHCC: envi.IF_BRANCH | envi.IF_COND,
    opcode86.INS_MOVCC: envi.IF_COND,
    opcode86.INS_XCHGCC: envi.IF_COND,
}

sizenames = ["" for x in range(33)]
sizenames[1] = "byte"
sizenames[2] = "word"
sizenames[4] = "dword"
sizenames[8] = "qword"
sizenames[16] = "oword"
sizenames[32] = "dqword"  # yword?


def addrToName(mcanv, va):
    sym = mcanv.syms.getSymByAddr(va)
    if sym is not None:
        return repr(sym)
    return "0x%.8x" % va


###########################################################################
#
# Operand objects for the i386 architecture
#


class i386RegOper(envi.RegisterOper):
    def __init__(self, reg, tsize):
        self.reg = reg
        self.tsize = tsize

    def repr(self, op):
        return self._dis_regctx.getRegisterName(self.reg)

    def getOperValue(self, op, emu=None):
        if emu is None: return None  # This operand type requires an emulator
        return emu.getRegister(self.reg)

    def setOperValue(self, op, emu, value):
        emu.setRegister(self.reg, value)

    def render(self, mcanv, op, idx):
        hint = mcanv.syms.getSymHint(op.va, idx)
        name = self._dis_regctx.getRegisterName(self.reg)
        if hint is not None:
            #  FIXME: bug?  what should this be?
            mcanv.addNameText(name, typename="registers")
        else:
            rname = self._dis_regctx.getRegisterName(self.reg & RMETA_NMASK)
            mcanv.addNameText(name, name=rname, typename="registers")

    def __eq__(self, other):
        if not isinstance(other, i386RegOper):
            return False
        if other.reg != self.reg:
            return False
        if other.tsize != self.tsize:
            return False
        return True


class i386ImmOper(envi.ImmedOper):
    """
    An operand representing an immediate.
    """

    def __init__(self, imm, tsize):
        self.imm = imm
        self.tsize = tsize

    def repr(self, op):
        ival = self.imm
        if self.tsize == 6:
            return "0x%.4x:0x%.8x" % (ival >> 32, ival & 0xffffffff)
        if ival > 4096:
            return "0x%.8x" % ival
        return str(ival)

    def getOperValue(self, op, emu=None):
        return self.imm

    def render(self, mcanv, op, idx):
        value = self.imm
        hint = mcanv.syms.getSymHint(op.va, idx)
        if hint is not None:
            if mcanv.mem.isValidPointer(value):
                mcanv.addVaText(hint, value)
            else:
                mcanv.addNameText(hint)
        elif mcanv.mem.isValidPointer(value):
            name = addrToName(mcanv, value)
            mcanv.addVaText(name, value)
        else:

            if self.tsize == 6:
                mcanv.addNameText("0x%.4x:0x%.8x" % (value >> 32, value & 0xffffffff))
            elif self.imm >= 4096:
                mcanv.addNameText('0x%.8x' % value)
            else:
                mcanv.addNameText(str(value))

    def __eq__(self, other):
        if not isinstance(other, i386ImmOper):
            return False
        if other.imm != self.imm:
            return False
        if other.tsize != self.tsize:
            return False
        return True


class i386PcRelOper(envi.Operand):
    """
    This is the operand used for EIP relative offsets
    for operands on instructions like jmp/call
    """

    def __init__(self, imm, tsize):
        self.imm = imm
        self.tsize = tsize

    def repr(self, op):
        return "0x%.8x" % (op.va + op.size + self.imm)

    def isImmed(self):
        return True

    def isDiscrete(self):
        return True  # Based on op.va...

    def getOperValue(self, op, emu=None):
        return op.va + op.size + self.imm

    def render(self, mcanv, op, idx):
        hint = mcanv.syms.getSymHint(op.va, idx)
        value = op.va + op.size + self.imm
        if hint is not None:
            mcanv.addVaText(hint, value)
        else:
            name = addrToName(mcanv, value)
            mcanv.addVaText(name, value)

    def __eq__(self, other):
        if not isinstance(other, i386PcRelOper):
            return False
        if other.imm != self.imm:
            return False
        if other.tsize != self.tsize:
            return False
        return True


class Amd64RipRelOper(envi.DerefOper):
    def __init__(self, imm, tsize):
        self.imm = imm
        self.tsize = tsize
        self._is_deref = True

    def getOperValue(self, op, emu=None):
        if not self._is_deref:  # Special lea behavior
            return self.getOperAddr(op)
        if emu is None:
            return None
        return emu.readMemValue(self.getOperAddr(op, emu), self.tsize)

    def setOperValue(self, op, emu, val):
        emu.writeMemValue(self.getOperAddr(op, emu), val, self.tsize)

    def getOperAddr(self, op, emu=None):
        return op.va + op.size + self.imm

    def isDeref(self):
        # The disassembler may reach in and set this (if lea...)
        return self._is_deref

    def isDiscrete(self):
        return True

    def render(self, mcanv, op, idx):
        destva = op.va + op.size + self.imm
        sym = mcanv.syms.getSymByAddr(destva)

        mcanv.addNameText(e_i386.sizenames[self.tsize])
        mcanv.addText(" [")
        mcanv.addNameText("rip", typename="registers")

        if self.imm > 0:
            mcanv.addText(" + ")
            if sym is not None:
                mcanv.addVaText("$%s" % repr(sym), destva)
            else:
                mcanv.addNameText(str(self.imm))
        elif self.imm < 0:
            mcanv.addText(" - ")
            if sym is not None:
                mcanv.addVaText("$%s" % repr(sym), destva)
            else:
                mcanv.addNameText(str(abs(self.imm)))
        mcanv.addText("]")

    def repr(self, op):
        return "[rip + %d]" % self.imm


class i386RegMemOper(envi.DerefOper):
    """
    An operand which represents the result of reading/writting memory from the
    dereference (with possible displacement) from a given register.
    """

    def __init__(self, reg, tsize, disp=0):
        self.reg = reg
        self.tsize = tsize
        self.disp = disp
        self._is_deref = True

    def repr(self, op):
        r = self._dis_regctx.getRegisterName(self.reg)
        if self.disp > 0:
            return "%s [%s + %d]" % (sizenames[self.tsize], r, self.disp)
        elif self.disp < 0:
            return "%s [%s - %d]" % (sizenames[self.tsize], r, abs(self.disp))
        return "%s [%s]" % (sizenames[self.tsize], r)

    def getOperValue(self, op, emu=None):
        if emu is None:
            return None  # This operand type requires an emulator
        return emu.readMemValue(self.getOperAddr(op, emu), self.tsize)

    def setOperValue(self, op, emu, val):
        emu.writeMemValue(self.getOperAddr(op, emu), val, self.tsize)

    def getOperAddr(self, op, emu):
        if emu is None:
            return None  # This operand type requires an emulator
        base, size = emu.getSegmentInfo(op)
        rval = emu.getRegister(self.reg)
        return base + rval + self.disp

    def isDeref(self):
        # The disassembler may reach in and set this (if lea...)
        return self._is_deref

    def render(self, mcanv, op, idx):
        mcanv.addNameText(sizenames[self.tsize])
        mcanv.addText(" [")
        name = self._dis_regctx.getRegisterName(self.reg)
        rname = self._dis_regctx.getRegisterName(self.reg & RMETA_NMASK)
        mcanv.addNameText(name, name=rname, typename="registers")
        hint = mcanv.syms.getSymHint(op.va, idx)
        if hint is not None:
            mcanv.addText(" + ")
            mcanv.addNameText(hint)

        else:
            if mcanv.mem.isValidPointer(self.disp):
                mcanv.addText(" + ")
                name = addrToName(mcanv, self.disp)
                mcanv.addVaText(name, self.disp)
            elif self.disp > 0:
                mcanv.addText(" + ")
                mcanv.addNameText(str(self.disp))
            elif self.disp < 0:
                mcanv.addText(" - ")
                mcanv.addNameText(str(abs(self.disp)))
        mcanv.addText("]")

    def __eq__(self, other):
        if not isinstance(other, i386RegMemOper):
            return False
        if other.reg != self.reg:
            return False
        if other.disp != self.disp:
            return False
        if other.tsize != self.tsize:
            return False
        return True


class i386ImmMemOper(envi.DerefOper):
    """
    An operand which represents the dereference (memory read/write) of
    a memory location associated with an immediate.
    """

    def __init__(self, imm, tsize):
        self.imm = imm
        self.tsize = tsize
        self._is_deref = True

    def isDeref(self):
        # The disassembler may reach in and set this (if lea...)
        return self._is_deref

    def isDiscrete(self):
        return True

    def repr(self, op):
        return "%s [0x%.8x]" % (sizenames[self.tsize], self.imm)

    def getOperValue(self, op, emu=None):
        if emu is None:
            return None  # This operand type requires an emulator
        return emu.readMemValue(self.getOperAddr(op, emu), self.tsize)

    def setOperValue(self, op, emu, val):
        emu.writeMemValue(self.getOperAddr(op, emu), val, self.tsize)

    def getOperAddr(self, op, emu=None):
        ret = self.imm
        if emu is not None:
            base, size = emu.getSegmentInfo(op)
            ret += base
        return ret

    def render(self, mcanv, op, idx):
        mcanv.addNameText(sizenames[self.tsize])
        mcanv.addText(" [")
        value = self.imm

        hint = mcanv.syms.getSymHint(op.va, idx)
        if hint is not None:
            mcanv.addVaText(hint, value)
        else:
            name = addrToName(mcanv, value)
            mcanv.addVaText(name, value)

        mcanv.addText("]")

    def __eq__(self, other):
        if not isinstance(other, i386ImmMemOper):
            return False
        if other.imm != self.imm:
            return False
        if other.tsize != self.tsize:
            return False
        return True


class i386SibOper(envi.DerefOper):
    """
    An operand which represents the result of reading/writting memory from the
    dereference (with possible displacement) from a given register.
    """

    def __init__(self, tsize, reg=None, imm=None, index=None, scale=1, disp=0):
        self.reg = reg
        self.imm = imm
        self.index = index
        self.scale = scale
        self.tsize = tsize
        self.disp = disp
        self._is_deref = True

    def __eq__(self, other):
        if not isinstance(other, i386SibOper):
            return False
        if other.imm != self.imm:
            return False
        if other.reg != self.reg:
            return False
        if other.index != self.index:
            return False
        if other.scale != self.scale:
            return False
        if other.disp != self.disp:
            return False
        if other.tsize != self.tsize:
            return False
        return True

    def isDeref(self):
        return self._is_deref

    def repr(self, op):

        r = "%s [" % sizenames[self.tsize]

        if self.reg is not None:
            r += self._dis_regctx.getRegisterName(self.reg)

        if self.imm is not None:
            r += "0x%.8x" % self.imm

        if self.index is not None:
            r += " + %s" % self._dis_regctx.getRegisterName(self.index)
            if self.scale != 1:
                r += " * %d" % self.scale

        if self.disp > 0:
            r += " + %d" % self.disp
        elif self.disp < 0:
            r += " - %d" % abs(self.disp)

        r += "]"

        return r

    def getOperValue(self, op, emu=None):
        if emu is None:
            return None  # This operand type requires an emulator
        return emu.readMemValue(self.getOperAddr(op, emu), self.tsize)

    def setOperValue(self, op, emu, val):
        emu.writeMemValue(self.getOperAddr(op, emu), val, self.tsize)

    def getOperAddr(self, op, emu=None):
        if emu is None: return None  # This operand type requires an emulator

        ret = 0

        if self.imm is not None:
            ret += self.imm

        if self.reg is not None:
            ret += emu.getRegister(self.reg)

        if self.index is not None:
            ret += (emu.getRegister(self.index) * self.scale)

        if emu.imem_psize == 4:
            ret &= 0xFFFFFFFF
        elif emu.imem_psize == 8:
            ret &= 0xFFFFFFFFFFFFFFFF

        # Handle x86 segmentation
        base, size = emu.getSegmentInfo(op)
        ret += base

        return ret + self.disp

    def _getOperBase(self, emu=None):
        # Special SIB only method for getting the SIB base value
        if self.imm:
            return self.imm
        if emu:
            return emu.getRegister(self.reg)
        return None

    def render(self, mcanv, op, idx):

        mcanv.addNameText(sizenames[self.tsize])
        mcanv.addText(" [")
        if self.imm is not None:
            name = addrToName(mcanv, self.imm)
            mcanv.addVaText(name, self.imm)

        if self.reg is not None:
            name = self._dis_regctx.getRegisterName(self.reg)
            rname = self._dis_regctx.getRegisterName(self.reg & RMETA_NMASK)
            mcanv.addNameText(name, name=rname, typename="registers")

        # Does our SIB have a scale
        if self.index is not None:
            mcanv.addText(" + ")
            name = self._dis_regctx.getRegisterName(self.index)
            rname = self._dis_regctx.getRegisterName(self.index & RMETA_NMASK)
            mcanv.addNameText(name, name=rname, typename="registers")
            if self.scale != 1:
                mcanv.addText(" * ")
                mcanv.addNameText(str(self.scale))

        hint = mcanv.syms.getSymHint(op.va, idx)
        if hint is not None:
            mcanv.addText(" + ")
            mcanv.addNameText(hint)

        else:
            # If we have a displacement, add it.
            if self.disp != 0:
                mcanv.addText(" + ")
                mcanv.addNameText(str(self.disp))

        mcanv.addText("]")


class i386Opcode(envi.Opcode):
    # Printable prefix names
    prefix_names = [
        (PREFIX_LOCK, "lock"),
        (PREFIX_REPNZ, "repnz"),
        (PREFIX_REP, "rep"),
        (PREFIX_CS, "cs"),
        (PREFIX_SS, "ss"),
        (PREFIX_DS, "ds"),
        (PREFIX_ES, "es"),
        (PREFIX_FS, "fs"),
        (PREFIX_GS, "gs"),
    ]

    def getBranches(self, emu=None):
        ret = []

        # To start with we have no flags ( except our arch )
        flags = self.iflags & envi.ARCH_MASK
        addb = False

        # If we are a conditional branch, even our fallthrough
        # case is conditional...
        if self.opcode == opcode86.INS_BRANCHCC:
            flags |= envi.BR_COND
            addb = True

        # If we can fall through, reflect that...
        if not self.iflags & envi.IF_NOFALL:
            ret.append((self.va + self.size, flags | envi.BR_FALL))

        # In intel, if we have no operands, it has no
        # further branches...
        if len(self.opers) == 0:
            return ret

        # Check for a call...
        if self.opcode == opcode86.INS_CALL:
            flags |= envi.BR_PROC
            addb = True

        # A conditional call?  really?  what compiler did you use? ;)
        elif self.opcode == opcode86.INS_CALLCC:
            flags |= (envi.BR_PROC | envi.BR_COND)
            addb = True

        elif self.opcode == opcode86.INS_BRANCH:
            oper0 = self.opers[0]
            if isinstance(oper0, i386SibOper) and oper0.scale == 4:
                # In the case with no emulator, note that our deref is
                # from the base of a table. If we have one, parse out all the
                # valid pointers from our base
                base = oper0._getOperBase(emu)
                if emu is None:
                    ret.append((base, flags | envi.BR_DEREF | envi.BR_TABLE))

                else:
                    # Since we're parsing this out, lets just resolve the derefs
                    # for our caller...
                    dest = emu.readMemValue(base, oper0.tsize)
                    while emu.isValidPointer(dest):
                        ret.append((dest, envi.BR_COND))
                        base += oper0.tsize
                        dest = emu.readMemValue(base, oper0.tsize)
            else:
                addb = True

        if addb:
            oper0 = self.opers[0]
            if oper0.isDeref():
                flags |= envi.BR_DEREF
                tova = oper0.getOperAddr(self, emu=emu)
            else:
                tova = oper0.getOperValue(self, emu=emu)

            ret.append((tova, flags))

        return ret

    def render(self, mcanv):
        """
        Render this opcode to the specified memory canvas
        """
        if self.prefixes:
            pfx = self.getPrefixName()
            if pfx:
                mcanv.addNameText("%s: " % pfx, pfx)

        mcanv.addNameText(self.mnem, typename="mnemonic")
        mcanv.addText(" ")

        # Allow each of our operands to render
        imax = len(self.opers)
        lasti = imax - 1
        for i in range(imax):
            oper = self.opers[i]
            oper.render(mcanv, self, i)
            if i != lasti:
                mcanv.addText(",")


class i386Disasm:
    def __init__(self, mode=MODE_32):
        self._md = Cs(CS_ARCH_X86, CS_MODE_32)
        self._md.detail = True
        self._reg_lookup = envi.archs.i386.regs

        self._dis_mode = MODE_32
        self._dis_regctx = envi.archs.i386.regs.i386RegisterContext()
        self._dis_oparch = envi.ARCH_I386
        self.ptrsize = 4


    def disasm(self, bytez, offset, va):

        md_iter = self._md.disasm(bytez[offset:offset+16], va)
        md_insn = None
        for insn in md_iter:
            md_insn = insn
            break
        if md_insn is None:
            # if capstone fails to disassemble, probably invalid
            raise envi.InvalidInstruction(bytez=bytez[offset:offset + 16], va=va)

        cs_optype = opcode86.mnem_to_optype.get(md_insn.insn_name(), 0)
        if cs_optype == 0:
            print('failed to find cs_optype for insn {}'.format(md_insn.insn_name()))
        cs_iflags = iflag_lookup.get(cs_optype, 0) | self._dis_oparch

        cs_prefix_to_viv_prefix = {
            0: 0,
            capstone.x86.X86_PREFIX_ADDRSIZE: PREFIX_ADDR_SIZE,
            capstone.x86.X86_PREFIX_CS: PREFIX_CS,
            capstone.x86.X86_PREFIX_DS: PREFIX_DS,
            capstone.x86.X86_PREFIX_ES: PREFIX_ES,
            capstone.x86.X86_PREFIX_FS: PREFIX_FS,
            capstone.x86.X86_PREFIX_GS: PREFIX_GS,
            capstone.x86.X86_PREFIX_SS: PREFIX_SS,
            capstone.x86.X86_PREFIX_LOCK: PREFIX_LOCK,
            capstone.x86.X86_PREFIX_OPSIZE: PREFIX_OP_SIZE,
            capstone.x86.X86_PREFIX_REP: PREFIX_REP,
            capstone.x86.X86_PREFIX_REPNE: PREFIX_REPNZ,
        }

        vw_prefixes = 0
        for cs_prefix in md_insn.prefix:
            vw_prefixes |= cs_prefix_to_viv_prefix[cs_prefix]
        if vw_prefixes & PREFIX_REP_MASK:
            cs_iflags |= envi.IF_REPEAT

        if priv_lookup.get(md_insn.insn_name(), False):
            cs_iflags |= envi.IF_PRIV

        cs_opers = list()
        for md_oper in md_insn.operands:
            vw_oper = None
            tsize = md_oper.size

            if md_oper.type == capstone.x86.X86_OP_REG:
                reg_name = md_insn.reg_name(md_oper.reg).upper()
                # capstone names them r10b but vivisect names them r10l
                if re.match('R[0-9]+B', reg_name):
                    reg_name = reg_name[:-1] + 'L'
                reg = getattr(self._reg_lookup, 'REG_%s' % reg_name)
                vw_oper = i386RegOper(reg, tsize)

            elif md_oper.type == capstone.x86.X86_OP_IMM:
                vw_oper = i386ImmOper(md_oper.imm, tsize)

            elif md_oper.type == capstone.x86.X86_OP_MEM:
                disp = md_oper.mem.disp
                base = md_oper.mem.base
                if base != 0:
                    base_reg_name = md_insn.reg_name(base).upper()
                    base_reg = getattr(self._reg_lookup, 'REG_%s' % base_reg_name)
                else:
                    base_reg = None

                if md_insn.sib != 0:
                    # SIB addressing
                    index = md_oper.mem.index
                    if index == 0:
                        index_reg = None
                        imm = None
                    else:
                        index_reg_name = md_insn.reg_name(index).upper()
                        index_reg = getattr(self._reg_lookup, 'REG_%s' % index_reg_name)
                        imm = disp
                        disp = 0

                    scale = md_oper.mem.scale
                    # TODO when do we use imm?
                    vw_oper = i386SibOper(tsize, reg=base_reg, index=index_reg, scale=scale, disp=disp, imm=imm)

                elif base != 0:
                    if base_reg_name == 'RIP':
                        vw_oper = Amd64RipRelOper(disp, tsize)
                    else:
                        vw_oper = i386RegMemOper(base_reg, tsize, disp=disp)

                else:
                    vw_oper = i386ImmMemOper(disp, tsize)
                        
            elif md_oper.type == capstone.x86.X86_OP_FP:
                pass

            elif md_oper.type == capstone.x86.X86_OP_INVALID:
                print('invalid operand')
                import code
                code.interact(local=locals())

            else:
                print('unknown operand')
                import code
                code.interact(local=locals())

            # do the same hack as vivisect above
            vw_oper._dis_regctx = self._dis_regctx
            cs_opers.append(vw_oper)

        # Lea will have a reg-mem/sib operand with _is_deref True, but should be false
        if cs_optype == opcode86.INS_LEA:
            cs_opers[1]._is_deref = False

        ret = i386Opcode(va, cs_optype, md_insn.insn_name(), vw_prefixes, md_insn.size, cs_opers, cs_iflags)        

        return ret


if __name__ == '__main__':
    import envi.archs
    envi.archs.dismain(i386Disasm())
