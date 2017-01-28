import struct

import envi.archs.i386 as e_i386
import envi.archs.amd64.regs
from envi.archs.i386.disasm import i386Opcode
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class Amd64Opcode(i386Opcode):
    def __repr__(self):
        """
        Over-ride this if you want to make arch specific repr.
        """
        pfx = self.getPrefixName()
        if pfx:
            pfx = '%s: ' % pfx

        mnem = self.mnem
        if self.prefixes & PREFIX_VEX:
            mnem = 'v' + mnem

        return pfx + mnem + " " + ",".join([o.repr(self) for o in self.opers])

    def render(self, mcanv):
        """
        Render this opcode to the specified memory canvas
        """
        if self.prefixes:
            pfx = self.getPrefixName()
            if pfx:
                mcanv.addNameText("%s: " % pfx, pfx)

        mnem = self.mnem
        if self.prefixes & PREFIX_VEX:
            mnem = 'v' + mnem

        mcanv.addNameText(mnem, typename="mnemonic")
        mcanv.addText(" ")

        # Allow each of our operands to render
        imax = len(self.opers)
        lasti = imax - 1
        for i in range(imax):
            oper = self.opers[i]
            oper.render(mcanv, self, i)
            if i != lasti:
                mcanv.addText(",")


class Amd64Disasm(e_i386.i386Disasm):
    def __init__(self):
        e_i386.i386Disasm.__init__(self)
        self._md = Cs(CS_ARCH_X86, CS_MODE_64)
        self._md.detail = True
        self._reg_lookup = envi.archs.amd64.regs
        
        self._dis_oparch = envi.ARCH_AMD64
        self._dis_regctx = envi.archs.amd64.regs.Amd64RegisterContext()
        self.ptrsize = 8


if __name__ == '__main__':
    import envi.archs
    envi.archs.dismain(Amd64Disasm())
