import struct

import envi
import envi.memory as e_mem
import envi.registers as e_reg
import envi.memcanvas as e_memcanvas
import envi.memcanvas.renderers as e_rend
import envi.archs.arm as arm
import vivisect
import platform
import unittest
from envi import IF_RET, IF_NOFALL, IF_BRANCH, IF_CALL, IF_COND
from envi.archs.arm.regs import *
from envi.archs.arm.const import *
from envi.archs.arm.disasm import *

'''
  This dictionary will contain all instructions supported by ARM to test
  Fields will contain following information:
  archVersionBitmask, ophex, va, repr, flags, emutests
'''
#List of instructions not tested and reason:
#chka - thumbee
#cps - thumb
#cpy - pre ual for mov
#enterx - go from thumb to thumbee
#eret - exception return see B9.1980
#F* (FLDMX, FSTMX)commands per A8.8.50 - pre UAL floating point
#HB, HBL, HBLP, HBP - thumbee instructions see A9.1125-1127
#IT - thumb

instrs = [
        (REV_ALL_ARM, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, ()),
        (REV_ALL_ARM, '0830bbe5', 0xbfb00000, 'ldr r3, [r11, #0x8]!', 0, ()),
        (REV_ALL_ARM, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, (
            {'setup':(('r0',0xaa),('PSR_C',0),('r3',0x1a)),
                'tests':(('r3',0xfefefefe),('PSR_Q',0),('PSR_N',0),('PSR_Z',0),('PSR_V',0),('PSR_C',0)) },
            {'setup':(('r0',0xaa),('PSR_C',0),('r3',0x1a)),
                'tests':(('r3',0xfefefefe),('PSR_Q',0),('PSR_N',0),('PSR_Z',0),('PSR_V',0),('PSR_C',0)) }
        )),
        (REV_ALL_ARM, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, (
            {#'setup':(('r0',0xaa),('PSR_C',0),('r3',0x1a)),
                'tests':(('r3',0xfefefefe),('PSR_Q',0),('PSR_N',0),('PSR_Z',0),('PSR_V',0),('PSR_C',0)) },
        #    {'setup':(('r0',0xaa),('PSR_C',0),('r3',0x1a)),
        #        'tests':(('r3',0xfefefefe),('PSR_Q',0),('PSR_N',0),('PSR_Z',0),('PSR_V',0),('PSR_C',0)) }
        )),

        (REV_ALL_ARM, '08309be4', 0xbfb00000, 'ldr r3, [r11], #0x8', 0, ()),
        (REV_ALL_ARM, '08301be4', 0xbfb00000, 'ldr r3, [r11], #-0x8', 0, ()),
        (REV_ALL_ARM, '02209ae7', 0xbfb00000, 'ldr r2, [r10, r2]', 0, ()),
        (REV_ALL_ARM, '02209ae6', 0xbfb00000, 'ldr r2, [r10], r2', 0, ()),
        (REV_ALL_ARM, '02203ae7', 0xbfb00000, 'ldr r2, [r10, -r2]!', 0, ()),
        (REV_ALL_ARM, '0220bae7', 0xbfb00000, 'ldr r2, [r10, r2]!', 0, ()),
        (REV_ALL_ARM, '22209ae7', 0xbfb00000, 'ldr r2, [r10, r2, lsr #32]', 0, ()),
        (REV_ALL_ARM, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, ()),
        (REV_ALL_ARM, '08309fe5', 0xbfb00000, 'ldr r3, [#0xbfb00010]', 0, ()),
        (REV_ALL_ARM, '674503e0', 0x4560, 'and r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674513e0', 0x4560, 'ands r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674523e0', 0x4560, 'eor r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674533e0', 0x4560, 'eors r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674543e0', 0x4560, 'sub r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674553e0', 0x4560, 'subs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674563e0', 0x4560, 'rsb r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674573e0', 0x4560, 'rsbs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674583e0', 0x4560, 'add r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674593e0', 0x4560, 'adds r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745a3e0', 0x4560, 'adc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745b3e0', 0x4560, 'adcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745c3e0', 0x4560, 'sbc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745d3e0', 0x4560, 'sbcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745e3e0', 0x4560, 'rsc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745f3e0', 0x4560, 'rscs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674513e1', 0x4560, 'tst r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674533e1', 0x4560, 'teq r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674553e1', 0x4560, 'cmp r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674573e1', 0x4560, 'cmn r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674583e1', 0x4560, 'orr r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674593e1', 0x4560, 'orrs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745c3e1', 0x4560, 'bic r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745d3e1', 0x4560, 'bics r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745e3e1', 0x4560, 'mvn r4, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745f3e1', 0x4560, 'mvns r4, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '774503e0', 0x4560, 'and r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774513e0', 0x4560, 'ands r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774523e0', 0x4560, 'eor r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774533e0', 0x4560, 'eors r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774543e0', 0x4560, 'sub r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774553e0', 0x4560, 'subs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774563e0', 0x4560, 'rsb r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774573e0', 0x4560, 'rsbs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774583e0', 0x4560, 'add r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774593e0', 0x4560, 'adds r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745a3e0', 0x4560, 'adc r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745b3e0', 0x4560, 'adcs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745c3e0', 0x4560, 'sbc r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745d3e0', 0x4560, 'sbcs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745e3e0', 0x4560, 'rsc r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745f3e0', 0x4560, 'rscs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774513e1', 0x4560, 'tst r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774533e1', 0x4560, 'teq r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774553e1', 0x4560, 'cmp r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774573e1', 0x4560, 'cmn r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774583e1', 0x4560, 'orr r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '774593e1', 0x4560, 'orrs r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745c3e1', 0x4560, 'bic r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745d3e1', 0x4560, 'bics r4, r3, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745e3e1', 0x4560, 'mvn r4, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '7745f3e1', 0x4560, 'mvns r4, r7, ror r5', 0, ()),
        (REV_ALL_ARM, '874503e0', 0x4560, 'and r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874513e0', 0x4560, 'ands r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874523e0', 0x4560, 'eor r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874533e0', 0x4560, 'eors r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874543e0', 0x4560, 'sub r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874553e0', 0x4560, 'subs r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874563e0', 0x4560, 'rsb r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874573e0', 0x4560, 'rsbs r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874583e0', 0x4560, 'add r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874593e0', 0x4560, 'adds r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745a3e0', 0x4560, 'adc r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745b3e0', 0x4560, 'adcs r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745c3e0', 0x4560, 'sbc r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745d3e0', 0x4560, 'sbcs r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745e3e0', 0x4560, 'rsc r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745f3e0', 0x4560, 'rscs r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874513e1', 0x4560, 'tst r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874533e1', 0x4560, 'teq r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874553e1', 0x4560, 'cmp r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874573e1', 0x4560, 'cmn r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874583e1', 0x4560, 'orr r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '874593e1', 0x4560, 'orrs r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745c3e1', 0x4560, 'bic r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745d3e1', 0x4560, 'bics r4, r3, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745e3e1', 0x4560, 'mvn r4, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '8745f3e1', 0x4560, 'mvns r4, r7, lsl #11', 0, ()),
        (REV_ALL_ARM, '974583e0', 0x4560, 'umull r4, r3, r7, r5', 0, ()),
        (REV_ALL_ARM, '974593e0', 0x4560, 'umulls r4, r3, r7, r5', 0, ()),
        (REV_ALL_ARM, '9745a3e0', 0x4560, 'umlal r4, r3, r7, r5', 0, ()),
        (REV_ALL_ARM, '9745b3e0', 0x4560, 'umlals r4, r3, r7, r5', 0, ()),
        (REV_ALL_ARM, '9745c3e0', 0x4560, 'smull r4, r3, r7, r5', 0, ()),
        (REV_ALL_ARM, '9745d3e0', 0x4560, 'smulls r4, r3, r7, r5', 0, ()),
        (REV_ALL_ARM, 'a74503e0', 0x4560, 'and r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74513e0', 0x4560, 'ands r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74523e0', 0x4560, 'eor r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74533e0', 0x4560, 'eors r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74543e0', 0x4560, 'sub r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74553e0', 0x4560, 'subs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74563e0', 0x4560, 'rsb r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74573e0', 0x4560, 'rsbs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74583e0', 0x4560, 'add r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74593e0', 0x4560, 'adds r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745a3e0', 0x4560, 'adc r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745b3e0', 0x4560, 'adcs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745c3e0', 0x4560, 'sbc r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745d3e0', 0x4560, 'sbcs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745e3e0', 0x4560, 'rsc r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745f3e0', 0x4560, 'rscs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74513e1', 0x4560, 'tst r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74533e1', 0x4560, 'teq r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74553e1', 0x4560, 'cmp r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74573e1', 0x4560, 'cmn r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74583e1', 0x4560, 'orr r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a74593e1', 0x4560, 'orrs r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745c3e1', 0x4560, 'bic r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745d3e1', 0x4560, 'bics r4, r3, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745e3e1', 0x4560, 'mvn r4, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'a745f3e1', 0x4560, 'mvns r4, r7, lsr #11', 0, ()),
        (REV_ALL_ARM, 'b74503e0', 0x4560, 'strh r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'b74513e0', 0x4560, 'ldrh r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'b74523e0', 0x4560, 'strht r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'b74533e0', 0x4560, 'ldrht r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'b74543e0', 0x4560, 'strh r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'b74553e0', 0x4560, 'ldrh r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'b74563e0', 0x4560, 'strht r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'b74573e0', 0x4560, 'ldrht r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'b74583e0', 0x4560, 'strh r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'b74593e0', 0x4560, 'ldrh r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'b745a3e0', 0x4560, 'strht r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'b745b3e0', 0x4560, 'ldrht r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'b745c3e0', 0x4560, 'strh r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'b745d3e0', 0x4560, 'ldrh r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'b745e3e0', 0x4560, 'strht r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'b745f3e0', 0x4560, 'ldrht r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'b74503e1', 0x4560, 'strh r4, [r3, -r7] ', 0, ()),
        (REV_ALL_ARM, 'b74513e1', 0x4560, 'ldrh r4, [r3, -r7] ', 0, ()),
        (REV_ALL_ARM, 'b74523e1', 0x4560, 'strh r4, [r3, -r7]! ', 0, ()),
        (REV_ALL_ARM, 'b74533e1', 0x4560, 'ldrh r4, [r3, -r7]! ', 0, ()),
        (REV_ALL_ARM, 'b74543e1', 0x4560, 'strh r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL_ARM, 'b74553e1', 0x4560, 'ldrh r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL_ARM, 'b74563e1', 0x4560, 'strh r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL_ARM, 'b74573e1', 0x4560, 'ldrh r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL_ARM, 'b74583e1', 0x4560, 'strh r4, [r3, r7] ', 0, ()),
        (REV_ALL_ARM, 'b74593e1', 0x4560, 'ldrh r4, [r3, r7] ', 0, ()),
        (REV_ALL_ARM, 'b745a3e1', 0x4560, 'strh r4, [r3, r7]! ', 0, ()),
        (REV_ALL_ARM, 'b745b3e1', 0x4560, 'ldrh r4, [r3, r7]! ', 0, ()),
        (REV_ALL_ARM, 'b745c3e1', 0x4560, 'strh r4, [r3, #0x57] ', 0, ()),
        (REV_ALL_ARM, 'b745d3e1', 0x4560, 'ldrh r4, [r3, #0x57] ', 0, ()),
        (REV_ALL_ARM, 'b745e3e1', 0x4560, 'strh r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL_ARM, 'b745f3e1', 0x4560, 'ldrh r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL_ARM, 'c74503e0', 0x4560, 'and r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74513e0', 0x4560, 'ands r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74523e0', 0x4560, 'eor r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74533e0', 0x4560, 'eors r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74543e0', 0x4560, 'sub r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74553e0', 0x4560, 'subs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74563e0', 0x4560, 'rsb r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74573e0', 0x4560, 'rsbs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74583e0', 0x4560, 'add r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74593e0', 0x4560, 'adds r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745a3e0', 0x4560, 'adc r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745b3e0', 0x4560, 'adcs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745c3e0', 0x4560, 'sbc r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745d3e0', 0x4560, 'sbcs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745e3e0', 0x4560, 'rsc r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745f3e0', 0x4560, 'rscs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74513e1', 0x4560, 'tst r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74533e1', 0x4560, 'teq r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74553e1', 0x4560, 'cmp r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74573e1', 0x4560, 'cmn r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74583e1', 0x4560, 'orr r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c74593e1', 0x4560, 'orrs r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745c3e1', 0x4560, 'bic r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745d3e1', 0x4560, 'bics r4, r3, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745e3e1', 0x4560, 'mvn r4, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'c745f3e1', 0x4560, 'mvns r4, r7, asr #11', 0, ()),
        (REV_ALL_ARM, 'd74503e0', 0x4560, 'ldrd r4, r5, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'd74513e0', 0x4560, 'ldrsb r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'd74523e0', 0x4560, 'ldrd r4, r5, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'd74533e0', 0x4560, 'ldrsbt r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'd74543e0', 0x4560, 'ldrd r4, r5, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'd74553e0', 0x4560, 'ldrsb r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'd74573e0', 0x4560, 'ldrsbt r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'd74583e0', 0x4560, 'ldrd r4, r5, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'd74593e0', 0x4560, 'ldrsb r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'd745b3e0', 0x4560, 'ldrsbt r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'd745c3e0', 0x4560, 'ldrd r4, r5,[r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'd745d3e0', 0x4560, 'ldrsb r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'd745f3e0', 0x4560, 'ldrsbt r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'd74503e1', 0x4560, 'ldrd r4, r5, [r3, -r7] ', 0, ()),
        (REV_ALL_ARM, 'd74513e1', 0x4560, 'ldrsb r4, [r3, -r7] ', 0, ()),
        (REV_ALL_ARM, 'd74523e1', 0x4560, 'ldrd r4, r5, [r3, -r7]! ', 0, ()),
        (REV_ALL_ARM, 'd74533e1', 0x4560, 'ldrsb r4, [r3, -r7]! ', 0, ()),
        (REV_ALL_ARM, 'd74543e1', 0x4560, 'ldrd r4, r5, [r3, #-0x57] ', 0, ()),
        (REV_ALL_ARM, 'd74553e1', 0x4560, 'ldrsb r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL_ARM, 'd74563e1', 0x4560, 'ldrd r4, r5, [r3, #-0x57]! ', 0, ()),
        (REV_ALL_ARM, 'd74573e1', 0x4560, 'ldrsb r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL_ARM, 'd74583e1', 0x4560, 'ldrd r4, r5, [r3, r7] ', 0, ()),
        (REV_ALL_ARM, 'd74593e1', 0x4560, 'ldrsb r4, [r3, r7] ', 0, ()),
        (REV_ALL_ARM, 'd745a3e1', 0x4560, 'ldrd r4, r5, [r3, r7]! ', 0, ()),
        (REV_ALL_ARM, 'd745b3e1', 0x4560, 'ldrsb r4, [r3, r7]! ', 0, ()),
        (REV_ALL_ARM, 'd745c3e1', 0x4560, 'ldrd r4, r5, [r3, #0x57] ', 0, ()),
        (REV_ALL_ARM, 'd745d3e1', 0x4560, 'ldrsb r4, [r3, #0x57] ', 0, ()),
        (REV_ALL_ARM, 'd745e3e1', 0x4560, 'ldrd r4, r5,  [r3, #0x57]! ', 0, ()),
        (REV_ALL_ARM, 'd745f3e1', 0x4560, 'ldrsb r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL_ARM, 'e74503e0', 0x4560, 'and r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74513e0', 0x4560, 'ands r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74523e0', 0x4560, 'eor r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74533e0', 0x4560, 'eors r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74543e0', 0x4560, 'sub r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74553e0', 0x4560, 'subs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74563e0', 0x4560, 'rsb r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74573e0', 0x4560, 'rsbs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74583e0', 0x4560, 'add r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74593e0', 0x4560, 'adds r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745a3e0', 0x4560, 'adc r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745b3e0', 0x4560, 'adcs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745c3e0', 0x4560, 'sbc r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745d3e0', 0x4560, 'sbcs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745e3e0', 0x4560, 'rsc r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745f3e0', 0x4560, 'rscs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74513e1', 0x4560, 'tst r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74533e1', 0x4560, 'teq r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74553e1', 0x4560, 'cmp r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74573e1', 0x4560, 'cmn r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74583e1', 0x4560, 'orr r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e74593e1', 0x4560, 'orrs r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745c3e1', 0x4560, 'bic r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745d3e1', 0x4560, 'bics r4, r3, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745e3e1', 0x4560, 'mvn r4, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'e745f3e1', 0x4560, 'mvns r4, r7, ror #11', 0, ()),
        (REV_ALL_ARM, 'f74503e0', 0x4560, 'strd r4, r5, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'f74513e0', 0x4560, 'ldrsh r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'f74533e0', 0x4560, 'ldrsht r4, [r3], -r7 ', 0, ()),
        (REV_ALL_ARM, 'f74543e0', 0x4560, 'strd r4, r5, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'f74553e0', 0x4560, 'ldrsh r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'f74573e0', 0x4560, 'ldrsht r4, [r3], #-0x57 ', 0, ()),
        (REV_ALL_ARM, 'f74583e0', 0x4560, 'strd r4, r5, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'f74593e0', 0x4560, 'ldrsh r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'f745b3e0', 0x4560, 'ldrsht r4, [r3], r7 ', 0, ()),
        (REV_ALL_ARM, 'f745c3e0', 0x4560, 'strd r4, r5, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'f745d3e0', 0x4560, 'ldrsh r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'f745f3e0', 0x4560, 'ldrsht r4, [r3], #0x57 ', 0, ()),
        (REV_ALL_ARM, 'f74503e1', 0x4560, 'strd r4, r5, [r3, -r7] ', 0, ()),
        (REV_ALL_ARM, 'f74513e1', 0x4560, 'ldrsh r4, [r3, -r7] ', 0, ()),
        (REV_ALL_ARM, 'f74523e1', 0x4560, 'strd r4, r5, [r3, -r7]! ', 0, ()),
        (REV_ALL_ARM, 'f74533e1', 0x4560, 'ldrsh r4, [r3, -r7]! ', 0, ()),
        (REV_ALL_ARM, 'f74543e1', 0x4560, 'strd r4, r5, [r3, #-0x57] ', 0, ()),
        (REV_ALL_ARM, 'f74553e1', 0x4560, 'ldrsh r4, [r3, #-0x57] ', 0, ()),
        (REV_ALL_ARM, 'f74563e1', 0x4560, 'strd r4, r5, [r3, #-0x57]! ', 0, ()),
        (REV_ALL_ARM, 'f74573e1', 0x4560, 'ldrsh r4, [r3, #-0x57]! ', 0, ()),
        (REV_ALL_ARM, 'f74583e1', 0x4560, 'strd r4, r5, [r3, r7] ', 0, ()),
        (REV_ALL_ARM, 'f74593e1', 0x4560, 'ldrsh r4, [r3, r7] ', 0, ()),
        (REV_ALL_ARM, 'f745a3e1', 0x4560, 'strd r4, r5, [r3, r7]! ', 0, ()),
        (REV_ALL_ARM, 'f745b3e1', 0x4560, 'ldrsh r4, [r3, r7]! ', 0, ()),
        (REV_ALL_ARM, 'f745c3e1', 0x4560, 'strd r4, r5, [r3, #0x57] ', 0, ()),
        (REV_ALL_ARM, 'f745d3e1', 0x4560, 'ldrsh r4, [r3, #0x57] ', 0, ()),
        (REV_ALL_ARM, 'f745e3e1', 0x4560, 'strd r4, r5,[r3, #0x57]! ', 0, ()),
        (REV_ALL_ARM, 'f745f3e1', 0x4560, 'ldrsh r4, [r3, #0x57]! ', 0, ()),
        (REV_ALL_ARM, '074603e0', 0x4560, 'and r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074613e0', 0x4560, 'ands r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074623e0', 0x4560, 'eor r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074633e0', 0x4560, 'eors r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074643e0', 0x4560, 'sub r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074653e0', 0x4560, 'subs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074663e0', 0x4560, 'rsb r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074673e0', 0x4560, 'rsbs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074683e0', 0x4560, 'add r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074693e0', 0x4560, 'adds r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746a3e0', 0x4560, 'adc r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746b3e0', 0x4560, 'adcs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746c3e0', 0x4560, 'sbc r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746d3e0', 0x4560, 'sbcs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746e3e0', 0x4560, 'rsc r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746f3e0', 0x4560, 'rscs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074613e1', 0x4560, 'tst r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074633e1', 0x4560, 'teq r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074653e1', 0x4560, 'cmp r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074673e1', 0x4560, 'cmn r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074683e1', 0x4560, 'orr r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '074693e1', 0x4560, 'orrs r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746c3e1', 0x4560, 'bic r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746d3e1', 0x4560, 'bics r4, r3, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746e3e1', 0x4560, 'mvn r4, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0746f3e1', 0x4560, 'mvns r4, r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '174603e0', 0x4560, 'and r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174613e0', 0x4560, 'ands r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174623e0', 0x4560, 'eor r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174633e0', 0x4560, 'eors r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174643e0', 0x4560, 'sub r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174653e0', 0x4560, 'subs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174663e0', 0x4560, 'rsb r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174673e0', 0x4560, 'rsbs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174683e0', 0x4560, 'add r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174693e0', 0x4560, 'adds r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746a3e0', 0x4560, 'adc r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746b3e0', 0x4560, 'adcs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746c3e0', 0x4560, 'sbc r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746d3e0', 0x4560, 'sbcs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746e3e0', 0x4560, 'rsc r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746f3e0', 0x4560, 'rscs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174613e1', 0x4560, 'tst r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174623e1', 0x4560, 'bx r7', 0, ()),
        (REV_ALL_ARM, '174653e1', 0x4560, 'cmp r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174673e1', 0x4560, 'cmn r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174683e1', 0x4560, 'orr r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '174693e1', 0x4560, 'orrs r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746c3e1', 0x4560, 'bic r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746d3e1', 0x4560, 'bics r4, r3, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746e3e1', 0x4560, 'mvn r4, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '1746f3e1', 0x4560, 'mvns r4, r7, lsl r6', 0, ()),
        (REV_ALL_ARM, '274603e0', 0x4560, 'and r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274613e0', 0x4560, 'ands r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274623e0', 0x4560, 'eor r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274633e0', 0x4560, 'eors r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274643e0', 0x4560, 'sub r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274653e0', 0x4560, 'subs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274663e0', 0x4560, 'rsb r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274673e0', 0x4560, 'rsbs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274683e0', 0x4560, 'add r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274693e0', 0x4560, 'adds r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746a3e0', 0x4560, 'adc r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746b3e0', 0x4560, 'adcs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746c3e0', 0x4560, 'sbc r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746d3e0', 0x4560, 'sbcs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746e3e0', 0x4560, 'rsc r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746f3e0', 0x4560, 'rscs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274613e1', 0x4560, 'tst r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274653e1', 0x4560, 'cmp r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274673e1', 0x4560, 'cmn r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274683e1', 0x4560, 'orr r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '274693e1', 0x4560, 'orrs r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746c3e1', 0x4560, 'bic r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746d3e1', 0x4560, 'bics r4, r3, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746e3e1', 0x4560, 'mvn r4, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '2746f3e1', 0x4560, 'mvns r4, r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '374603e0', 0x4560, 'and r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374613e0', 0x4560, 'ands r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374623e0', 0x4560, 'eor r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374633e0', 0x4560, 'eors r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374643e0', 0x4560, 'sub r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374653e0', 0x4560, 'subs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374663e0', 0x4560, 'rsb r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374673e0', 0x4560, 'rsbs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374683e0', 0x4560, 'add r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374693e0', 0x4560, 'adds r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746a3e0', 0x4560, 'adc r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746b3e0', 0x4560, 'adcs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746c3e0', 0x4560, 'sbc r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746d3e0', 0x4560, 'sbcs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746e3e0', 0x4560, 'rsc r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746f3e0', 0x4560, 'rscs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374613e1', 0x4560, 'tst r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374623e1', 0x4560, 'blx r7', 0, ()),
        (REV_ALL_ARM, '374633e1', 0x4560, 'teq r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374653e1', 0x4560, 'cmp r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374673e1', 0x4560, 'cmn r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374683e1', 0x4560, 'orr r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '374693e1', 0x4560, 'orrs r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746c3e1', 0x4560, 'bic r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746d3e1', 0x4560, 'bics r4, r3, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746e3e1', 0x4560, 'mvn r4, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '3746f3e1', 0x4560, 'mvns r4, r7, lsr r6', 0, ()),
        (REV_ALL_ARM, '474603e0', 0x4560, 'and r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474613e0', 0x4560, 'ands r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474623e0', 0x4560, 'eor r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474633e0', 0x4560, 'eors r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474643e0', 0x4560, 'sub r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474653e0', 0x4560, 'subs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474663e0', 0x4560, 'rsb r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474673e0', 0x4560, 'rsbs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474683e0', 0x4560, 'add r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474693e0', 0x4560, 'adds r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746a3e0', 0x4560, 'adc r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746b3e0', 0x4560, 'adcs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746c3e0', 0x4560, 'sbc r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746d3e0', 0x4560, 'sbcs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746e3e0', 0x4560, 'rsc r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746f3e0', 0x4560, 'rscs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474613e1', 0x4560, 'tst r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474633e1', 0x4560, 'teq r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474653e1', 0x4560, 'cmp r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474673e1', 0x4560, 'cmn r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474683e1', 0x4560, 'orr r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '474693e1', 0x4560, 'orrs r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746c3e1', 0x4560, 'bic r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746d3e1', 0x4560, 'bics r4, r3, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746e3e1', 0x4560, 'mvn r4, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '4746f3e1', 0x4560, 'mvns r4, r7, asr #12', 0, ()),
        (REV_ALL_ARM, '574603e0', 0x4560, 'and r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574613e0', 0x4560, 'ands r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574623e0', 0x4560, 'eor r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574633e0', 0x4560, 'eors r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574643e0', 0x4560, 'sub r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574653e0', 0x4560, 'subs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574663e0', 0x4560, 'rsb r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574673e0', 0x4560, 'rsbs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574683e0', 0x4560, 'add r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574693e0', 0x4560, 'adds r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746a3e0', 0x4560, 'adc r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746b3e0', 0x4560, 'adcs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746c3e0', 0x4560, 'sbc r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746d3e0', 0x4560, 'sbcs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746e3e0', 0x4560, 'rsc r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746f3e0', 0x4560, 'rscs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574613e1', 0x4560, 'tst r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574633e1', 0x4560, 'teq r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574653e1', 0x4560, 'cmp r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574673e1', 0x4560, 'cmn r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574683e1', 0x4560, 'orr r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '574693e1', 0x4560, 'orrs r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746c3e1', 0x4560, 'bic r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746d3e1', 0x4560, 'bics r4, r3, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746e3e1', 0x4560, 'mvn r4, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '5746f3e1', 0x4560, 'mvns r4, r7, asr r6', 0, ()),
        (REV_ALL_ARM, '674503e6', 0x4560, 'str r4, [r3], -r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674523e6', 0x4560, 'strt r4, [r3], -r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674543e6', 0x4560, 'strb r4, [r3], -r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674563e6', 0x4560, 'strbt r4, [r3], -r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674583e6', 0x4560, 'str r4, [r3], r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745a3e6', 0x4560, 'strt r4, [r3], r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745c3e6', 0x4560, 'strb r4, [r3], r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745e3e6', 0x4560, 'strbt r4, [r3], r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674503e7', 0x4560, 'str r4, [r3, -r7, ror #10]', 0, ()),
        (REV_ALL_ARM, '674523e7', 0x4560, 'str r4, [r3, -r7, ror #10]!', 0, ()),
        (REV_ALL_ARM, '674543e7', 0x4560, 'strb r4, [r3, -r7, ror #10]', 0, ()),
        (REV_ALL_ARM, '674563e7', 0x4560, 'strb r4, [r3, -r7, ror #10]!', 0, ()),
        (REV_ALL_ARM, '674583e7', 0x4560, 'str r4, [r3, r7, ror #10]', 0, ()),
        (REV_ALL_ARM, '6745a3e7', 0x4560, 'str r4, [r3, r7, ror #10]!', 0, ()),
        (REV_ALL_ARM, '6745c3e7', 0x4560, 'strb r4, [r3, r7, ror #10]', 0, ()),
        (REV_ALL_ARM, '6745e3e7', 0x4560, 'strb r4, [r3, r7, ror #10]!', 0, ()),
        (REV_ALL_ARM, '674503e0', 0x4560, 'and r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674513e0', 0x4560, 'ands r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674523e0', 0x4560, 'eor r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674533e0', 0x4560, 'eors r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674543e0', 0x4560, 'sub r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674553e0', 0x4560, 'subs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674563e0', 0x4560, 'rsb r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674573e0', 0x4560, 'rsbs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674583e0', 0x4560, 'add r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '674593e0', 0x4560, 'adds r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745a3e0', 0x4560, 'adc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745b3e0', 0x4560, 'adcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745c3e0', 0x4560, 'sbc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745d3e0', 0x4560, 'sbcs r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745e3e0', 0x4560, 'rsc r4, r3, r7, ror #10', 0, ()),
        (REV_ALL_ARM, '6745f3e0', 0x4560, 'rscs r4, r3, r7, ror #10', 0, ()),
        #ADDED TESTS
        (REV_ALL_ARM, 'ff4ca3e2', 0x4560, 'adc  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff4cb3e2', 0x4560, 'adcs  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff4c83e2', 0x4560, 'add  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff4c93e2', 0x4560, 'adds  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, '013a8fe2', 0x4560, 'adr  r3, 0x00005568', 0, ()),
        (REV_ALL_ARM, '013a4fe2', 0x4560, 'adr  r3, 0x00003568', 0, ()),
        (REV_ALL_ARM, 'ff4c03e2', 0x4560, 'and  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff4c13e2', 0x4560, 'ands  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, '001000ea', 0x4560, 'b 0x00008568', 0, ()),
        (REV_ALL_ARM, 'ff4cc3e3', 0x4560, 'bic  r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, '001000eb', 0x4560, 'bl  0x00008568', 0, ()),
        (REV_ALL_ARM, '001000fa', 0x4560, 'blx  0x00005568', 0, ()),
        (REV_ALL_ARM, '273764ee', 0x4560, 'cdp  p7, 6, cr3, cr4, cr7, 1', 0, ()),
        (REV_ALL_ARM, '473b34ee', 0x4560, 'cdp  p11, 3, cr3, cr4, cr7, 2', 0, ()),
        (REV_ALL_ARM, 'ff0c74e3', 0x4560, 'cmn  r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff0c54e3', 0x4560, 'cmp  r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff4c23e2', 0x4560, 'eor r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff4c33e2', 0x4560, 'eors r4, r3, #0xff00', 0, ()),
        (REV_ALL_ARM, '073894ed', 0x4560, 'ldc p8, cr3, [r4, #0x1c]', 0, ()),
        (REV_ALL_ARM, '073814ed', 0x4560, 'ldc p8, cr3, [r4, #-0x1c]', 0, ()),
        (REV_ALL_ARM, '0738b4ed', 0x4560, 'ldc p8, cr3, [r4, #0x1c]!', 0, ()),
        (REV_ALL_ARM, '073834ed', 0x4560, 'ldc p8, cr3, [r4, #-0x1c]!', 0, ()),
        (REV_ALL_ARM, '0738b4ec', 0x4560, 'ldc p8, cr3, [r4], #0x1c', 0, ()),
        (REV_ALL_ARM, '073834ec', 0x4560, 'ldc p8, cr3, [r4], #-0x1c', 0, ()),
        (REV_ALL_ARM, '073894ec', 0x4560, 'ldc p8, cr3, [r4], {7}', 0, ()),
        (REV_ALL_ARM, '0738d4ed', 0x4560, 'ldcl p8, cr3, [r4, #0x1c]', 0, ()),
        (REV_ALL_ARM, '073854ed', 0x4560, 'ldcl p8, cr3, [r4, #-0x1c]', 0, ()),
        (REV_ALL_ARM, '0738f4ed', 0x4560, 'ldcl p8, cr3, [r4, #0x1c]!', 0, ()),
        (REV_ALL_ARM, '073874ed', 0x4560, 'ldcl p8, cr3, [r4, #-0x1c]!', 0, ()),
        (REV_ALL_ARM, '0738f4ec', 0x4560, 'ldcl p8, cr3, [r4], #0x1c', 0, ()),
        (REV_ALL_ARM, '073874ec', 0x4560, 'ldcl p8, cr3, [r4], #-0x1c', 0, ()),
        (REV_ALL_ARM, '0738d4ec', 0x4560, 'ldcl p8, cr3, [r4], {7}', 0, ()),
        (REV_ALL_ARM, '07389fed', 0x4560, 'ldc p8, cr3, [#0x4584]', 0, ()),
        (REV_ALL_ARM, '07381fed', 0x4560, 'ldc p8, cr3, [#0x454c]', 0, ()),
        (REV_ALL_ARM, '0738bfed', 0x4560, 'ldc p8, cr3, [#0x4584]', 0, ()),
        (REV_ALL_ARM, '07383fed', 0x4560, 'ldc p8, cr3, [#0x454c]', 0, ()),
        (REV_ALL_ARM, '0738bfed', 0x4560, 'ldc p8, cr3, [#0x4584]', 0, ()),
        (REV_ALL_ARM, '07383fed', 0x4560, 'ldc p8, cr3, [#0x454c]', 0, ()),
        (REV_ALL_ARM, '07389fec', 0x4560, 'ldc p8, cr3, [pc], {7}', 0, ()),
        (REV_ALL_ARM, '0738dfed', 0x4560, 'ldcl p8, cr3, [#0x4584]', 0, ()),
        (REV_ALL_ARM, '07385fed', 0x4560, 'ldcl p8, cr3, [#0x454c]', 0, ()),
        (REV_ALL_ARM, '0738ffed', 0x4560, 'ldcl p8, cr3, [#0x4584]', 0, ()),
        (REV_ALL_ARM, '07387fed', 0x4560, 'ldcl p8, cr3, [#0x454c]', 0, ()),
        (REV_ALL_ARM, '0738ffed', 0x4560, 'ldcl p8, cr3, [#0x4584]', 0, ()),
        (REV_ALL_ARM, '07387fed', 0x4560, 'ldcl p8, cr3, [#0x454c]', 0, ()),
        (REV_ALL_ARM, '0738dfec', 0x4560, 'ldcl p8, cr3, [pc], {7}', 0, ()),
        (REV_ALL_ARM, '980090e8', 0x4560, 'ldm  r0, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '9800b0e8', 0x4560, 'ldm  r0!, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '98009de9', 0x4560, 'ldmib  sp, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '9800bde9', 0x4560, 'ldmib  sp!, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '98001de8', 0x4560, 'ldmda  sp, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '98003de8', 0x4560, 'ldmda  sp!, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '98001de9', 0x4560, 'ldmdb  sp, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, '98003de9', 0x4560, 'ldmdb  sp!, {r3, r4, r7}', 0, ()),
        (REV_ALL_ARM, 'ff30d4e5', 0x4560, 'ldrb  r3, [r4, #0xff]', 0, ()),
        (REV_ALL_ARM, 'ff3054e5', 0x4560, 'ldrb  r3, [r4, #-0xff]', 0, ()),
        (REV_ALL_ARM, 'ff30f4e5', 0x4560, 'ldrb  r3, [r4, #0xff]!', 0, ()),
        (REV_ALL_ARM, 'ff3074e5', 0x4560, 'ldrb  r3, [r4, #-0xff]!', 0, ()),
        (REV_ALL_ARM, 'ff30d4e4', 0x4560, 'ldrb  r3, [r4], #0xff', 0, ()),
        (REV_ALL_ARM, 'ff3054e4', 0x4560, 'ldrb  r3, [r4], #-0xff', 0, ()),
        (REV_ALL_ARM, 'ff305fe5', 0x4560, 'ldrb  r3, [#0x4469]', 0, ()),
        (REV_ALL_ARM, 'ff30dfe5', 0x4560, 'ldrb  r3, [#0x4667]', 0, ()),
        (REV_ALL_ARM, '0730d4e7', 0x4560, 'ldrb  r3, [r4, r7]', 0, ()),
        (REV_ALL_ARM, '0736d4e7', 0x4560, 'ldrb  r3, [r4, r7, lsl #12]', 0, ()),
        (REV_ALL_ARM, '0736f4e7', 0x4560, 'ldrb  r3, [r4, r7, lsl #12]!', 0, ()),
        (REV_ALL_ARM, '073654e7', 0x4560, 'ldrb  r3, [r4, -r7, lsl #12]', 0, ()),
        (REV_ALL_ARM, '073674e7', 0x4560, 'ldrb  r3, [r4, -r7, lsl #12]!', 0, ()),
        (REV_ALL_ARM, '0730d4e6', 0x4560, 'ldrb  r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '073054e6', 0x4560, 'ldrb  r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, '0736d4e6', 0x4560, 'ldrb  r3, [r4], r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '073654e6', 0x4560, 'ldrb  r3, [r4], -r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '0730f4e6', 0x4560, 'ldrbt  r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '073074e6', 0x4560, 'ldrbt  r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, '2736f4e6', 0x4560, 'ldrbt  r3, [r4], r7, lsr #12', 0, ()),
        (REV_ALL_ARM, '273674e6', 0x4560, 'ldrbt  r3, [r4], -r7, lsr #12', 0, ()),
        (REV_ALL_ARM, 'dc4c4fe1', 0x4560, 'ldrd  r4, r5, [#0x449c]', 0, ()),
        (REV_ALL_ARM, 'dc4ccfe1', 0x4560, 'ldrd  r4, r5, [#0x4634]', 0, ()),
        (REV_ALL_ARM, 'dc3c5fe1', 0x4560, 'ldrsb  r3, [#0x449c]', 0, ()),
        (REV_ALL_ARM, 'dc3cdfe1', 0x4560, 'ldrsb  r3, [#0x4634]', 0, ()),
        (REV_ALL_ARM, 'fc3c5fe1', 0x4560, 'ldrsh  r3, [#0x449c]', 0, ()),
        (REV_ALL_ARM, 'fc3cdfe1', 0x4560, 'ldrsh  r3, [#0x4634]', 0, ()),
        (REV_ALL_ARM, 'ff3034e4', 0x4560, 'ldrt  r3, [r4], #-0xff', 0, ()),
        (REV_ALL_ARM, 'ff30b4e4', 0x4560, 'ldrt  r3, [r4], #0xff', 0, ()),
        (REV_ALL_ARM, '073034e6', 0x4560, 'ldrt  r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, '0730b4e6', 0x4560, 'ldrt  r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '0736b4e6', 0x4560, 'ldrt  r3, [r4], r7, lsl #12', 0, ()),
        (REV_ALL_ARM, '073634e6', 0x4560, 'ldrt  r3, [r4], -r7, lsl #12', 0, ()),
        (REV_ALL_ARM, 'ff3ca0e3', 0x4560, 'mov r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3cb0e3', 0x4560, 'movs r3, #0xff00', 0, ()),
        (REV_ALL_ARM, '0430a0e1', 0x4560, 'mov r3, r4', 0, ()),
        (REV_ALL_ARM, '0430b0e1', 0x4560, 'movs r3, r4', 0, ()),
        (REV_ALL_ARM, 'd73884ee', 0x4560, 'mcr p8, 4, r3, cr4, cr7, 6', 0, ()),
        (REV_ALL_ARM, '473844ec', 0x4560, 'mcrr p8, 4, r3, r4, cr7', 0, ()),
        (REV_ALL_ARM, 'd73894ee', 0x4560, 'mrc p8, 4, r3, cr4, cr7, 6', 0, ()),
        (REV_ALL_ARM, '473854ec', 0x4560, 'mrrc p8, 4, r3, r4, cr7', 0, ()),
        (REV_ALL_ARM, 'd3f021e3', 0x4560, 'msr cpsr_c, #0xd3', 0, ()),
        (REV_ALL_ARM, 'd3f022e3', 0x4560, 'msr cpsr_x, #0xd3', 0, ()),
        (REV_ALL_ARM, 'd3f024e3', 0x4560, 'msr cpsr_s, #0xd3', 0, ()),
        (REV_ALL_ARM, 'd3f028e3', 0x4560, 'msr cpsr_f, #0xd3', 0, ()),
        #not sure if these msr are correct?
        (REV_ALL_ARM, '03f021e1', 0x4560, 'msr cpsr_c, r3', 0, ()),
        (REV_ALL_ARM, '03f022e1', 0x4560, 'msr cpsr_x, r3', 0, ()),
        (REV_ALL_ARM, '03f024e1', 0x4560, 'msr cpsr_s, r3', 0, ()),
        (REV_ALL_ARM, '03f028e1', 0x4560, 'msr cpsr_f, r3', 0, ()),
        (REV_ALL_ARM, '940703e0', 0x4560, 'mul r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'ff3ce0e3', 0x4560, 'mvn r3, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3cf0e3', 0x4560, 'mvns r3, #0xff00', 0, ()),
        (REV_ALL_ARM, '013a84e3', 0x4560, 'orr r3, r4, #0x1000', 0, ()),
        (REV_ALL_ARM, '013a94e3', 0x4560, 'orrs r3, r4, #0x1000', 0, ()),
        (REV_ALL_ARM, 'ff3c64e2', 0x4560, 'rsb r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3c74e2', 0x4560, 'rsbs r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3ce4e2', 0x4560, 'rsc r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3cf4e2', 0x4560, 'rscs r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, '0730c4e0', 0x4560, 'sbc r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '0730d4e0', 0x4560, 'sbcs r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'ff3cc4e2', 0x4560, 'sbc r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3cd4e2', 0x4560, 'sbcs r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, '9637c4e0', 0x4560, 'smull r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '9637d4e0', 0x4560, 'smulls r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '3f3884ed', 0x4560, 'stc p8, cr3, [r4, #0xfc]', 0, ()),
        (REV_ALL_ARM, '3f3804ed', 0x4560, 'stc p8, cr3, [r4, #-0xfc]', 0, ()),
        (REV_ALL_ARM, '3f38a4ed', 0x4560, 'stc p8, cr3, [r4, #0xfc]!', 0, ()),
        (REV_ALL_ARM, '3f3824ed', 0x4560, 'stc p8, cr3, [r4, #-0xfc]!', 0, ()),
        (REV_ALL_ARM, '3f38a4ec', 0x4560, 'stc p8, cr3, [r4], #0xfc', 0, ()),
        (REV_ALL_ARM, '3f3824ec', 0x4560, 'stc p8, cr3, [r4], #-0xfc', 0, ()),
        (REV_ALL_ARM, '0f3884ec', 0x4560, 'stc p8, cr3, [r4], {15}', 0, ()),
        (REV_ALL_ARM, '940081e8', 0x4560, 'stm r1, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '9400a1e8', 0x4560, 'stm r1!, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '940001e8', 0x4560, 'stmda r1, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '940021e8', 0x4560, 'stmda r1!, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '940081e9', 0x4560, 'stmib r1, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '9400a1e9', 0x4560, 'stmib r1!, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '003084e5', 0x4560, 'str r3, [r4]', 0, ()),
        (REV_ALL_ARM, 'ff3084e5', 0x4560, 'str r3, [r4, #0xff]', 0, ()),
        (REV_ALL_ARM, 'ff3004e5', 0x4560, 'str r3, [r4, #-0xff]', 0, ()),
        (REV_ALL_ARM, 'ff3084e4', 0x4560, 'str r3, [r4], #0xff', 0, ()),
        (REV_ALL_ARM, 'ff3004e4', 0x4560, 'str r3, [r4], #-0xff', 0, ()),
        (REV_ALL_ARM, 'ff30a4e5', 0x4560, 'str r3, [r4, #0xff]!', 0, ()),
        (REV_ALL_ARM, '073084e7', 0x4560, 'str r3, [r4, r7]', 0, ()),
        (REV_ALL_ARM, '073004e7', 0x4560, 'str r3, [r4, -r7]', 0, ()),
        (REV_ALL_ARM, '073084e6', 0x4560, 'str r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '073004e6', 0x4560, 'str r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, '0030c4e5', 0x4560, 'strb r3, [r4]', 0, ()),
        (REV_ALL_ARM, 'ff30c4e5', 0x4560, 'strb r3, [r4, #0xff]', 0, ()),
        (REV_ALL_ARM, 'ff3044e5', 0x4560, 'strb r3, [r4, #-0xff]', 0, ()),
        (REV_ALL_ARM, 'ff30c4e4', 0x4560, 'strb r3, [r4], #0xff', 0, ()),
        (REV_ALL_ARM, 'ff3044e4', 0x4560, 'strb r3, [r4], #-0xff', 0, ()),
        (REV_ALL_ARM, 'ff30e4e5', 0x4560, 'strb r3, [r4, #0xff]!', 0, ()),
        (REV_ALL_ARM, '0730c4e7', 0x4560, 'strb r3, [r4, r7]', 0, ()),
        (REV_ALL_ARM, '073044e7', 0x4560, 'strb r3, [r4, -r7]', 0, ()),
        (REV_ALL_ARM, '0730C4e6', 0x4560, 'strb r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '073044e6', 0x4560, 'strb r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, 'ff30e4e4', 0x4560, 'strbt r3, [r4], #0xff', 0, ()),
        (REV_ALL_ARM, 'ff3064e4', 0x4560, 'strbt r3, [r4], #-0xff', 0, ()),
        (REV_ALL_ARM, '0730e4e6', 0x4560, 'strbt r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '073064e6', 0x4560, 'strbt r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, 'b030c7e1', 0x4560, 'strh r3, [r7]', 0, ()),
        (REV_ALL_ARM, 'b030e7e0', 0x4560, 'strht r3, [r7]', 0, ()),
        (REV_ALL_ARM, '0030a7e4', 0x4560, 'strt r3, [r7]', 0, ()),
        (REV_ALL_ARM, 'ff30a7e4', 0x4560, 'strt r3, [r7], #0xff', 0, ()),
        (REV_ALL_ARM, 'ff3027e4', 0x4560, 'strt r3, [r7], #-0xff', 0, ()),
        (REV_ALL_ARM, '0730a4e6', 0x4560, 'strt r3, [r4], r7', 0, ()),
        (REV_ALL_ARM, '073024e6', 0x4560, 'strt r3, [r4], -r7', 0, ()),
        (REV_ALL_ARM, 'ff3c44e2', 0x4560, 'sub r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3c54e2', 0x4560, 'subs r3, r4, #0xff00', 0, ()),
        (REV_ALL_ARM, '073044e0', 0x4560, 'sub r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '073054e0', 0x4560, 'subs r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'ff3c4de2', 0x4560, 'sub r3, sp, #0xff00', 0, ()),
        (REV_ALL_ARM, 'ff3c5de2', 0x4560, 'subs r3, sp, #0xff00', 0, ()),
        (REV_ALL_ARM, '04304de0', 0x4560, 'sub r3, sp, r4', 0, ()),
        (REV_ALL_ARM, '04305de0', 0x4560, 'subs r3, sp, r4', 0, ()),
        (REV_ALL_ARM, '44364de0', 0x4560, 'sub r3, sp, r4, asr #12', 0, ()),
        (REV_ALL_ARM, '44365de0', 0x4560, 'subs r3, sp, r4, asr #12', 0, ()),
        (REV_ALL_ARM, 'ff0c31e3', 0x4560, 'teq r1, #0xff00', 0, ()),
        (REV_ALL_ARM, '040031e1', 0x4560, 'teq r1, r4', 0, ()),
        (REV_ALL_ARM, 'ff0c11e3', 0x4560, 'tst r1, #0xff00', 0, ()),
        (REV_ALL_ARM, '040011e1', 0x4560, 'tst r1, r4', 0, ()),
        (REV_ALL_ARM, 'bc3c5fe1', 0x4560, 'ldrh  r3, [#0x449c]', 0, ()),
        (REV_ALL_ARM, 'bc3cdfe1', 0x4560, 'ldrh  r3, [#0x4634]', 0, ()),
        (REV_ALL_ARM, 'ff3f4fe3', 0x4560, 'movt r3, #0xffff', 0, ()),
        #rt must be even, less than r14, rt2 is r(t+1) per A8.8.210/A8.8.72
        (REV_ALL_ARM, 'f040c7e1', 0x4560, 'strd r4, r5, [r7]', 0, ()),
        (REV_ALL_ARM, 'ff4fc7e1', 0x4560, 'strd r4, r5, [r7, #0xff]', 0, ()),
        (REV_ALL_ARM, 'ff4f47e1', 0x4560, 'strd r4, r5, [r7, #-0xff]', 0, ()),
        (REV_ALL_ARM, 'ff4fe7e1', 0x4560, 'strd r4, r5, [r7, #0xff]!', 0, ()),
        (REV_ALL_ARM, 'ff4f67e1', 0x4560, 'strd r4, r5, [r7, #-0xff]!', 0, ()),
        (REV_ALL_ARM, 'ff4fc7e0', 0x4560, 'strd r4, r5, [r7], #0xff', 0, ()),
        (REV_ALL_ARM, 'ff4f47e0', 0x4560, 'strd r4, r5, [r7], #-0xff', 0, ()),
        (REV_ALL_ARM, 'f64087e1', 0x4560, 'strd r4, r5, [r7, r6]', 0, ()),
        (REV_ALL_ARM, 'f64007e1', 0x4560, 'strd r4, r5, [r7, -r6]', 0, ()),
        (REV_ALL_ARM, 'f640a7e1', 0x4560, 'strd r4, r5, [r7, r6]!', 0, ()),
        (REV_ALL_ARM, 'f64027e1', 0x4560, 'strd r4, r5, [r7, -r6]!', 0, ()),
        (REV_ALL_ARM, 'f64087e0', 0x4560, 'strd r4, r5, [r7], r6', 0, ()),
        (REV_ALL_ARM, 'f64007e0', 0x4560, 'strd r4, r5, [r7], -r6', 0, ()),
        (REV_ALL_ARM, '03f021e1', 0x4560, 'msr cpsr_c, r3', 0, ()),
        (REV_ALL_ARM, '03f022e1', 0x4560, 'msr cpsr_x, r3', 0, ()),
        (REV_ALL_ARM, '03f024e1', 0x4560, 'msr cpsr_s, r3', 0, ()),
        (REV_ALL_ARM, '03f028e1', 0x4560, 'msr cpsr_f, r3', 0, ()),
        (REV_ALL_ARM, '940001e9', 0x4560, 'stmdb r1, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, '940021e9', 0x4560, 'stmdb r1!, {r2, r4, r7}', 0, ()),
        (REV_ALL_ARM, 'dc3c5fe1', 0x4560, 'ldrsb  r3, [#0x449c]', 0, ()),
        (REV_ALL_ARM, 'dc3cdfe1', 0x4560, 'ldrsb  r3, [#0x4634]', 0, ()),
        (REV_ALL_ARM, 'ff3f4fe3', 0x4560, 'movt r3, #0xffff', 0, ()),
        #implimented in disasm but not yet in emu
        (REV_ALL_ARM, '70f02fe1', 0x4560, 'bkpt  #0xff00', 0, ()),
        (REV_ALL_ARM, '24ff2fe1', 0x4560, 'bxj  r4', 0, ()), # note this switches to jazelle
        (REV_ALL_ARM, '143f6fe1', 0x4560, 'clz r3, r4', 0, ()),
        (REV_ALL_ARM, '273764fe', 0x4560, 'cdp2  p7, 6, cr3, cr4, cr7, 1', 0, ()),
        (REV_ALL_ARM, '473b34fe', 0x4560, 'cdp2  p11, 3, cr3, cr4, cr7, 2', 0, ()),
        (REV_ALL_ARM, '073894fd', 0x4560, 'ldc2 p8, cr3, [r4, #0x1c]', 0, ()),
        (REV_ALL_ARM, '073814fd', 0x4560, 'ldc2 p8, cr3, [r4, #-0x1c]', 0, ()),
        (REV_ALL_ARM, '0738b4fd', 0x4560, 'ldc2 p8, cr3, [r4, #0x1c]!', 0, ()),
        (REV_ALL_ARM, '073834fd', 0x4560, 'ldc2 p8, cr3, [r4, #-0x1c]!', 0, ()),
        (REV_ALL_ARM, '0738b4fc', 0x4560, 'ldc2 p8, cr3, [r4], #0x1c', 0, ()),
        (REV_ALL_ARM, '073834fc', 0x4560, 'ldc2 p8, cr3, [r4], #-0x1c', 0, ()),
        (REV_ALL_ARM, '073894fc', 0x4560, 'ldc2 p8, cr3, [r4], #0x1c', 0, ()),  #option should not have # listed
        (REV_ALL_ARM, '0738d4fd', 0x4560, 'ldc2l p8, cr3, [r4, #0x1c]', 0, ()),
        (REV_ALL_ARM, '073854fd', 0x4560, 'ldc2l p8, cr3, [r4, #-0x1c]', 0, ()),
        (REV_ALL_ARM, '0738f4fd', 0x4560, 'ldc2l p8, cr3, [r4, #0x1c]!', 0, ()),
        (REV_ALL_ARM, '073874fd', 0x4560, 'ldc2l p8, cr3, [r4, #-0x1c]!', 0, ()),
        (REV_ALL_ARM, '0738f4fc', 0x4560, 'ldc2l p8, cr3, [r4], #0x1c', 0, ()),
        (REV_ALL_ARM, '073874fc', 0x4560, 'ldc2l p8, cr3, [r4], #-0x1c', 0, ()),
        (REV_ALL_ARM, '0738d4fc', 0x4560, 'ldc2l p8, cr3, [r4], #0x1c', 0, ()),  #option should not have # listed
        (REV_ALL_ARM, 'd73884fe', 0x4560, 'mcr2 p8, 4, r3, cr4, cr7, 6', 0, ()),
        (REV_ALL_ARM, '473844fc', 0x4560, 'mcrr2 p8, 4, r3, r4, cr7', 0, ()),
        (REV_ALL_ARM, 'ff3f0fe3', 0x4560, 'movw r3, #0xffff', 0, ()),
        (REV_ALL_ARM, 'd73894fe', 0x4560, 'mrc2 p8, 4, r3, cr4, cr7, 6', 0, ()),
        (REV_ALL_ARM, '473854fc', 0x4560, 'mrrc2 p8, 4, r3, r4, cr7', 0, ()),
        (REV_ALL_ARM, '00300fe1', 0x4560, 'mrs r3, cpsr', 0, ()),
        (REV_ALL_ARM, '00f020e3', 0x4560, 'nop', 0, ()),
        (REV_ALL_ARM, '173384e6', 0x4560, 'pkhbt r3, r4, r7, lsl #6', 0, ()),
        (REV_ALL_ARM, '173084e6', 0x4560, 'pkhbt r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '573384e6', 0x4560, 'pkhtb r3, r4, r7, asr #6', 0, ()),
        (REV_ALL_ARM, '573084e6', 0x4560, 'pkhtb r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '543007e1', 0x4560, 'qadd r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '173f24e6', 0x4560, 'qadd16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973f24e6', 0x4560, 'qadd8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '543027e1', 0x4560, 'qsub r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '773f24e6', 0x4560, 'qsub16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'f73f24e6', 0x4560, 'qsub8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '543047e1', 0x4560, 'qdadd r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '543067e1', 0x4560, 'qdsub r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '343fbfe6', 0x4560, 'rev r3, r4', 0, ()),
        (REV_ALL_ARM, 'b43fbfe6', 0x4560, 'rev16 r3, r4', 0, ()),
        (REV_ALL_ARM, 'b43fffe6', 0x4560, 'revsh r3, r4', 0, ()),
        (REV_ALL_ARM, '173f14e6', 0x4560, 'sadd16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973f14e6', 0x4560, 'sadd8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'b73f84e6', 0x4560, 'sel r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '000201F1', 0x4560, 'setend be', 0, ()),
        (REV_ALL_ARM, '000001F1', 0x4560, 'setend le', 0, ()),
        (REV_ALL_ARM, '04f020e3', 0x4560, 'sev', 0, ()),
        (REV_ALL_ARM, '173f34e6', 0x4560, 'shadd16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973f34e6', 0x4560, 'shadd8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '773f34e6', 0x4560, 'shsub16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'f73f34e6', 0x4560, 'shsub8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '846703e1', 0x4560, 'smlabb r3, r4, r7, r6', 0, ()),
        (REV_ALL_ARM, 'e46703e1', 0x4560, 'smlatt r3, r4, r7, r6', 0, ()),
        (REV_ALL_ARM, 'c46703e1', 0x4560, 'smlabt r3, r4, r7, r6', 0, ()),
        (REV_ALL_ARM, 'a46703e1', 0x4560, 'smlatb r3, r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '9637e4e0', 0x4560, 'smlal r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '9637f4e0', 0x4560, 'smlals r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '863744e1', 0x4560, 'smlalbb r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, 'e63744e1', 0x4560, 'smlaltt r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, 'c63744e1', 0x4560, 'smlalbt r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, 'a63744e1', 0x4560, 'smlaltb r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '847623e1', 0x4560, 'smlawb r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, 'c47623e1', 0x4560, 'smlawt r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, 'd47653e7', 0x4560, 'smmls r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, 'f47653e7', 0x4560, 'smmlsr r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '14f653e7', 0x4560, 'smmul r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '34f653e7', 0x4560, 'smmulr r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '146703e7', 0x4560, 'smlad r3, r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '346703e7', 0x4560, 'smladx r3, r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '163744e7', 0x4560, 'smlald r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '363744e7', 0x4560, 'smlaldx r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '547603e7', 0x4560, 'smlsd r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '747603e7', 0x4560, 'smlsdx r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '563744e7', 0x4560, 'smlsld r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '763744e7', 0x4560, 'smlsldx r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '147653e7', 0x4560, 'smmla r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '347653e7', 0x4560, 'smmlar r3, r4, r6, r7', 0, ()),
        (REV_ALL_ARM, '840663e1', 0x4560, 'smulbb r3, r4, r6', 0, ()),
        (REV_ALL_ARM, 'c40663e1', 0x4560, 'smulbt r3, r4, r6', 0, ()),
        (REV_ALL_ARM, 'a40663e1', 0x4560, 'smultb r3, r4, r6', 0, ()),
        (REV_ALL_ARM, 'e40663e1', 0x4560, 'smultt r3, r4, r6', 0, ()),
        (REV_ALL_ARM, 'a40623e1', 0x4560, 'smulwb r3, r4, r6', 0, ()),
        (REV_ALL_ARM, 'e40623e1', 0x4560, 'smulwt r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '54f603e7', 0x4560, 'smusd r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '74f603e7', 0x4560, 'smusdx r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '1430a6e6', 0x4560, 'ssat r3, #0x07, r4', 0, ()),
        (REV_ALL_ARM, '1433a6e6', 0x4560, 'ssat r3, #0x07, r4, lsl #6', 0, ()),
        (REV_ALL_ARM, '5433a6e6', 0x4560, 'ssat r3, #0x07, r4, asr #6', 0, ()),
        (REV_ALL_ARM, '5430a6e6', 0x4560, 'ssat r3, #0x07, r4, asr #32', 0, ()),
        (REV_ALL_ARM, '1730e4e6', 0x4560, 'usat r3, #0x04, r7', 0, ()),
        (REV_ALL_ARM, '1734e4e6', 0x4560, 'usat r3, #0x04, r7, lsl #8', 0, ()),
        (REV_ALL_ARM, '763f14e6', 0x4560, 'ssub16 r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '954007e1', 0x4560, 'swp r4, r5, [r7]', 0, ()),
        (REV_ALL_ARM, '954047e1', 0x4560, 'swpb r4, r5, [r7]', 0, ()),
        (REV_ALL_ARM, '02f020e3', 0x4560, 'wfe', 0, ()),
        (REV_ALL_ARM, '03f020e3', 0x4560, 'wfi', 0, ()),
        (REV_ALL_ARM, '01f020e3', 0x4560, 'yield', 0, ()),
        (REV_ALL_ARM, '173f54e6', 0x4560, 'uadd16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973f54e6', 0x4560, 'uadd8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '173f74e6', 0x4560, 'uhadd16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973f74e6', 0x4560, 'uhadd8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '773f74e6', 0x4560, 'uhsub16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973844e0', 0x4560, 'umaal r3, r4, r7, r8', 0, ()),
        (REV_ALL_ARM, '173f64e6', 0x4560, 'uqadd16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '973f64e6', 0x4560, 'uqadd8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '773f64e6', 0x4560, 'uqsub16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '148783e7', 0x4560, 'usada8 r3, r4, r7, r8', 0, ()),
        (REV_ALL_ARM, '373fe4e6', 0x4560, 'usat16 r3, #0x04, r7', 0, ()),
        (REV_ALL_ARM, '773f54e6', 0x4560, 'usub16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '1730e4e6', 0x4560, 'usat r3, #0x04, r7', 0, ()),
        (REV_ALL_ARM, '1734e4e6', 0x4560, 'usat r3, #0x04, r7, lsl #8', 0, ()),
        (REV_ALL_ARM, '373f24e6', 0x4560, 'qasx r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '573f24e6', 0x4560, 'qsax r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '373f14e6', 0x4560, 'sasx r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '373f34e6', 0x4560, 'shasx r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '573f34e6', 0x4560, 'shsax r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '00ff00ef', 0x4560, 'svc #0xff00', 0, ()),
        #need [] around last entry. Not sure how to accomplish yet for ldrex and strex
        (REV_ALL_ARM, '9f3f94e1', 0x4560, 'ldrex  r3, r4', 0, ()),
        (REV_ALL_ARM, '9f3fd4e1', 0x4560, 'ldrexb  r3, r4', 0, ()),
        (REV_ALL_ARM, '9f4fb6e1', 0x4560, 'ldrexd  r4, r5, r6', 0, ()),
        (REV_ALL_ARM, '9f3ff4e1', 0x4560, 'ldrexh  r3, r4', 0, ()),
        (REV_ALL_ARM, '943f87e1', 0x4560, 'strex r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '943fc7e1', 0x4560, 'strexb r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '943fa7e1', 0x4560, 'strexd r3, r4, r5, r7', 0, ()),
        (REV_ALL_ARM, '943fe7e1', 0x4560, 'strexh r3, r4, r7', 0, ()),
        #not sure if these msr are correct? Left here to be sorted out in emu. Disassembles correctly
        #fails in emu.getSPSR
        (REV_ALL_ARM, 'd3f061e3', 0x4560, 'msr spsr_c, #0xd3', 0, ()),
        (REV_ALL_ARM, 'd3f062e3', 0x4560, 'msr spsr_x, #0xd3', 0, ()),
        (REV_ALL_ARM, 'd3f064e3', 0x4560, 'msr spsr_s, #0xd3', 0, ()),
        (REV_ALL_ARM, 'd3d068e3', 0x4560, 'msr spsr_f, #0xd3', 0, ()),
        (REV_ALL_ARM, '03f061e1', 0x4560, 'msr spsr_c, r3', 0, ()),
        (REV_ALL_ARM, '03f062e1', 0x4560, 'msr spsr_x, r3', 0, ()),
        (REV_ALL_ARM, '03f064e1', 0x4560, 'msr spsr_s, r3', 0, ()),
        (REV_ALL_ARM, '03f068e1', 0x4560, 'msr spsr_f, r3', 0, ()),
        #same as mov with rotation but now is UAL
        (REV_ALL_ARM, '6745a3e1', 0x4560, 'ror r4, r7, #0x0a', 0, ()),
        (REV_ALL_ARM, '6745b3e1', 0x4560, 'rors r4, r7, #0x0a', 0, ()),
        (REV_ALL_ARM, '8745a3e1', 0x4560, 'lsl r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, '8745b3e1', 0x4560, 'lsls r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, 'a745a3e1', 0x4560, 'lsr r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, 'a745b3e1', 0x4560, 'lsrs r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, 'c745a3e1', 0x4560, 'asr r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, 'c745b3e1', 0x4560, 'asrs r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, 'e745a3e1', 0x4560, 'ror r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, 'e745b3e1', 0x4560, 'rors r4, r7, #0x0b', 0, ()),
        (REV_ALL_ARM, '0746a3e1', 0x4560, 'lsl r4, r7, #0x0c', 0, ()),
        (REV_ALL_ARM, '0746b3e1', 0x4560, 'lsls r4, r7, #0x0c', 0, ()),
        (REV_ALL_ARM, '7745a3e1', 0x4560, 'ror r4, r7, r5', 0, ()),
        (REV_ALL_ARM, '7745b3e1', 0x4560, 'rors r4, r7, r5', 0, ()),
        (REV_ALL_ARM, '1746a3e1', 0x4560, 'lsl r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '1746b3e1', 0x4560, 'lsls r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '2746a3e1', 0x4560, 'lsr r4, r7, #0x0c', 0, ()),
        (REV_ALL_ARM, '2746b3e1', 0x4560, 'lsrs r4, r7, #0x0c', 0, ()),
        (REV_ALL_ARM, '3746a3e1', 0x4560, 'lsr r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '3746b3e1', 0x4560, 'lsrs r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '4746a3e1', 0x4560, 'asr r4, r7, #0x0c', 0, ()),
        (REV_ALL_ARM, '4746b3e1', 0x4560, 'asrs r4, r7, #0x0c', 0, ()),
        (REV_ALL_ARM, '5746a3e1', 0x4560, 'asr r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '5746b3e1', 0x4560, 'asrs r4, r7, r6', 0, ()),
        (REV_ALL_ARM, '034fa0e1', 0x4560, 'lsl r4, r3, #0x1e', 0, ()),
        (REV_ALL_ARM, '034fb0e1', 0x4560, 'lsls r4, r3, #0x1e', 0, ()),
        (REV_ALL_ARM, '7347a0e1', 0x4560, 'ror r4, r3, r7', 0, ()),
        (REV_ALL_ARM, '7347b0e1', 0x4560, 'rors r4, r3, r7', 0, ()),
        (REV_ALL_ARM, '234fa0e1', 0x4560, 'lsr r4, r3, #0x1e', 0, ()),
        (REV_ALL_ARM, '234fb0e1', 0x4560, 'lsrs r4, r3, #0x1e', 0, ()),
        (REV_ALL_ARM, '3347a0e1', 0x4560, 'lsr r4, r3, r7', 0, ()),
        (REV_ALL_ARM, '3347b0e1', 0x4560, 'lsrs r4, r3, r7', 0, ()),
        (REV_ALL_ARM, 'e437a0e1', 0x4560, 'ror r3, r4, #0x0f', 0, ()),
        (REV_ALL_ARM, 'e437b0e1', 0x4560, 'rors r3, r4, #0x0f', 0, ()),
        (REV_ALL_ARM, '7437a0e1', 0x4560, 'ror r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7437b0e1', 0x4560, 'rors r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '6430a0e1', 0x4560, 'rrx r3, r4', 0, ()),
        (REV_ALL_ARM, '6430b0e1', 0x4560, 'rrxs r3, r4', 0, ()),
        (REV_ALL_ARM, '434fa0e1', 0x4560, 'asr  r4, r3, #0x1e', 0, ()),
        (REV_ALL_ARM, '434fb0e1', 0x4560, 'asrs  r4, r3, #0x1e', 0, ()),
        (REV_ALL_ARM, '5345a0e1', 0x4560, 'asr  r4, r3, r5', 0, ()),
        (REV_ALL_ARM, '5345b0e1', 0x4560, 'asrs  r4, r3, r5', 0, ()),
        (REV_ALL_ARM, '1f32cfe7', 0x4560, 'bfc r3, #0x04, #0x0f', 0, ()),
        (REV_ALL_ARM, '1432cfe7', 0x4560, 'bfi r3, r4, #0x04, #0x0f', 0, ()),
        (REV_ALL_ARM, 'fff053f5', 0x4560, 'pld [r3, #-0xff]', 0, ()),
        (REV_ALL_ARM, 'fff0d3f5', 0x4560, 'pld [r3, #0xff]', 0, ()),
        (REV_ALL_ARM, 'fff013f5', 0x4560, 'pldw [r3, #-0xff]', 0, ()),
        (REV_ALL_ARM, 'fff093f5', 0x4560, 'pldw [r3, #0xff]', 0, ()),
        (REV_ALL_ARM, '00f05ff5', 0x4560, 'pld [#0x4568]', 0, ()),
        (REV_ALL_ARM, '08f05ff5', 0x4560, 'pld [#0x4560]', 0, ()),
        (REV_ALL_ARM, '08f0dff5', 0x4560, 'pld [#0x4570]', 0, ()),
        (REV_ALL_ARM, '04f0d3f7', 0x4560, 'pld [r3, r4]', 0, ()),
        (REV_ALL_ARM, '04f053f7', 0x4560, 'pld [r3, -r4]', 0, ()),
        (REV_ALL_ARM, '24f3d3f7', 0x4560, 'pld [r3, r4, lsr #6]', 0, ()),
        (REV_ALL_ARM, '04f093f7', 0x4560, 'pldw [r3, r4]', 0, ()),
        (REV_ALL_ARM, '04f013f7', 0x4560, 'pldw [r3, -r4]', 0, ()),
        (REV_ALL_ARM, '44f393f7', 0x4560, 'pldw [r3, r4, asr #6]', 0, ()),
        (REV_ALL_ARM, '00f0d3f4', 0x4560, 'pli [r3]', 0, ()),
        (REV_ALL_ARM, 'fff0d3f4', 0x4560, 'pli [r3, #0xff]', 0, ()),
        (REV_ALL_ARM, 'fff053f4', 0x4560, 'pli [r3, #-0xff]', 0, ()),
        (REV_ALL_ARM, '0ff0dff4', 0x4560, 'pli [#0x4577]', 0, ()),
        (REV_ALL_ARM, '0ff05ff4', 0x4560, 'pli [#0x4559]', 0, ()),
        (REV_ALL_ARM, '04f053f6', 0x4560, 'pli [r3, -r4]', 0, ()),
        (REV_ALL_ARM, '04f0d3f6', 0x4560, 'pli [r3, r4]', 0, ()),
        (REV_ALL_ARM, 'a4f353f6', 0x4560, 'pli [r3, -r4, lsr #7]', 0, ()),
        (REV_ALL_ARM, 'e4f3d3f6', 0x4560, 'pli [r3, r4, ror #7]', 0, ()),
        (REV_ALL_ARM, '5436efe7', 0x4560, 'ubfx r3, r4, #0x0c, #0x0f', 0, ()),
        (REV_ALL_ARM, '14f603e7', 0x4560, 'smuad r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '34f603e7', 0x4560, 'smuadx r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '343fa6e6', 0x4560, 'ssat16 r3, #0x06, r4', 0, ()),
        (REV_ALL_ARM, '563f14e6', 0x4560, 'ssax r3, r4, r6', 0, ()),
        (REV_ALL_ARM, 'f63f14e6', 0x4560, 'ssub8 r3, r4, r6', 0, ()),
        (REV_ALL_ARM, '1730e4e6', 0x4560, 'usat r3, #0x04, r7', 0, ()),
        (REV_ALL_ARM, '1734e4e6', 0x4560, 'usat r3, #0x04, r7, lsl #8', 0, ()),
        (REV_ALL_ARM, '7730a4e6', 0x4560, 'sxtab r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7734a4e6', 0x4560, 'sxtab r3, r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7738a4e6', 0x4560, 'sxtab r3, r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '773ca4e6', 0x4560, 'sxtab r3, r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '773084e6', 0x4560, 'sxtab16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '773484e6', 0x4560, 'sxtab16 r3, r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '773884e6', 0x4560, 'sxtab16 r3, r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '773c84e6', 0x4560, 'sxtab16 r3, r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '7730b4e6', 0x4560, 'sxtah r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7734b4e6', 0x4560, 'sxtah r3, r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7738b4e6', 0x4560, 'sxtah r3, r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '773cb4e6', 0x4560, 'sxtah r3, r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '7740afe6', 0x4560, 'sxtb r4, r7', 0, ()),
        (REV_ALL_ARM, '7744afe6', 0x4560, 'sxtb r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7748afe6', 0x4560, 'sxtb r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '774cafe6', 0x4560, 'sxtb r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '77408fe6', 0x4560, 'sxtb16 r4, r7', 0, ()),
        (REV_ALL_ARM, '77448fe6', 0x4560, 'sxtb16 r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '77488fe6', 0x4560, 'sxtb16 r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '774c8fe6', 0x4560, 'sxtb16 r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '7740bfe6', 0x4560, 'sxth r4, r7', 0, ()),
        (REV_ALL_ARM, '7744bfe6', 0x4560, 'sxth r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7748bfe6', 0x4560, 'sxth r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '774cbfe6', 0x4560, 'sxth r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '373f54e6', 0x4560, 'uasx r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '373f74e6', 0x4560, 'uhasx r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '573f74e6', 0x4560, 'uhsax r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'f73f74e6', 0x4560, 'uhsub8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '373f64e6', 0x4560, 'uqasx r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '573f64e6', 0x4560, 'uqsax r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'f73f64e6', 0x4560, 'uqsub8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '14f783e7', 0x4560, 'usad8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '573f54e6', 0x4560, 'usax r3, r4, r7', 0, ()),
        (REV_ALL_ARM, 'f73f54e6', 0x4560, 'usub8 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7730e4e6', 0x4560, 'uxtab r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7734e4e6', 0x4560, 'uxtab r3, r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7738e4e6', 0x4560, 'uxtab r3, r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '773ce4e6', 0x4560, 'uxtab r3, r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '7730c4e6', 0x4560, 'uxtab16 r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7734c4e6', 0x4560, 'uxtab16 r3, r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7738c4e6', 0x4560, 'uxtab16 r3, r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '773cc4e6', 0x4560, 'uxtab16 r3, r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '7730f4e6', 0x4560, 'uxtah r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '7734f4e6', 0x4560, 'uxtah r3, r4, r7, ror #8', 0, ()),
        (REV_ALL_ARM, '7738f4e6', 0x4560, 'uxtah r3, r4, r7, ror #16', 0, ()),
        (REV_ALL_ARM, '773cf4e6', 0x4560, 'uxtah r3, r4, r7, ror #24', 0, ()),
        (REV_ALL_ARM, '7430efe6', 0x4560, 'uxtb r3, r4', 0, ()),
        (REV_ALL_ARM, '7434efe6', 0x4560, 'uxtb r3, r4, ror #8', 0, ()),
        (REV_ALL_ARM, '7438efe6', 0x4560, 'uxtb r3, r4, ror #16', 0, ()),
        (REV_ALL_ARM, '743cefe6', 0x4560, 'uxtb r3, r4, ror #24', 0, ()),
        (REV_ALL_ARM, '7430cfe6', 0x4560, 'uxtb16 r3, r4', 0, ()),
        (REV_ALL_ARM, '7434cfe6', 0x4560, 'uxtb16 r3, r4, ror #8', 0, ()),
        (REV_ALL_ARM, '7438cfe6', 0x4560, 'uxtb16 r3, r4, ror #16', 0, ()),
        (REV_ALL_ARM, '743ccfe6', 0x4560, 'uxtb16 r3, r4, ror #24', 0, ()),
        (REV_ALL_ARM, '7430ffe6', 0x4560, 'uxth r3, r4', 0, ()),
        (REV_ALL_ARM, '7434ffe6', 0x4560, 'uxth r3, r4, ror #8', 0, ()),
        (REV_ALL_ARM, '7438ffe6', 0x4560, 'uxth r3, r4, ror #16', 0, ()),
        (REV_ALL_ARM, '743cffe6', 0x4560, 'uxth r3, r4, ror #24', 0, ()),
        (REV_ALL_ARM, '1ff07ff5', 0x4560, 'clrex', 0, ()),
        (REV_ALL_ARM, 'f3f020e3', 0x4560, 'dbg  #0x03', 0, ()),
        (REV_ALL_ARM, '5ff07ff5', 0x4560, 'dmb sy', 0, ()),
        (REV_ALL_ARM, '5ef07ff5', 0x4560, 'dmb st', 0, ()),
        (REV_ALL_ARM, '5bf07ff5', 0x4560, 'dmb ish', 0, ()),
        (REV_ALL_ARM, '5af07ff5', 0x4560, 'dmb ishst', 0, ()),
        (REV_ALL_ARM, '57f07ff5', 0x4560, 'dmb nsh', 0, ()),
        (REV_ALL_ARM, '56f07ff5', 0x4560, 'dmb nshst', 0, ()),
        (REV_ALL_ARM, '53f07ff5', 0x4560, 'dmb osh', 0, ()),
        (REV_ALL_ARM, '42f07ff5', 0x4560, 'dsb oshst', 0, ()),
        (REV_ALL_ARM, '6ff07ff5', 0x4560, 'isb sy', 0, ()),
        (REV_ALL_ARM, '1600bde8', 0x4560, 'pop {r1, r2, r4}', 0, ()),
        (REV_ALL_ARM, '04609de4', 0x4560, 'pop r6', 0, ()),
        (REV_ALL_ARM, '16002de9', 0x4560, 'push {r1, r2, r4}', 0, ()),
        (REV_ALL_ARM, '04102de5', 0x4560, 'push r1', 0, ()),
        (REV_ALL_ARM, '343fffe6', 0x4560, 'rbit r3, r4', 0, ()),
        (REV_ALL_ARM, '5434a3e7', 0x4560, 'sbfx r3, r4, #0x08, #0x03', 0, ()),
        (REV_ALL_ARM, '14f713e7', 0x4560, 'sdiv r3, r4, r7', 0, ()),
        (REV_ALL_ARM, '14f733e7', 0x4560, 'udiv r3, r4, r7', 0, ()),
        #(REV_ALL_ARM, 'f000f0e7', 0x4560, 'udf #0', 0, ()), #This forces an undefined instruction. Commented out normally.
        #all v codes are suspect at this time - not implimented but may not be correct here either
        (REV_ALL_ARM, '173704f2', 0x4560, 'vaba.s8 d3, d4, d7', 0, ()),
        (REV_ALL_ARM, '173714f2', 0x4560, 'vaba.s16 d3, d4, d7', 0, ()),
        (REV_ALL_ARM, '173724f2', 0x4560, 'vaba.s32 d3, d4, d7', 0, ()),
        (REV_ALL_ARM, '173704f3', 0x4560, 'vaba.u8 d3, d4, d7', 0, ()),
        (REV_ALL_ARM, '173714f3', 0x4560, 'vaba.u16 d3, d4, d7', 0, ()),
        (REV_ALL_ARM, '173724f3', 0x4560, 'vaba.u32 d3, d4, d7', 0, ()),
        (REV_ALL_ARM, '5e6708f2', 0x4560, 'vaba.s8 q3, q4, q7', 0, ()),
        (REV_ALL_ARM, '5e6718f2', 0x4560, 'vaba.s16 q3, q4, q7', 0, ()),
        (REV_ALL_ARM, '5e6728f2', 0x4560, 'vaba.s32 q3, q4, q7', 0, ()),
        (REV_ALL_ARM, '5e6708f3', 0x4560, 'vaba.u8 q3, q4, q7', 0, ()),
        (REV_ALL_ARM, '5e6718f3', 0x4560, 'vaba.u16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6728f3', 0x4560, 'vaba.u32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '076584f2', 0x4560, 'vabal.s8 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076594f2', 0x4560, 'vabal.s16 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0765a4f2', 0x4560, 'vabal.s32 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076584f3', 0x4560, 'vabal.u8 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076594f3', 0x4560, 'vabal.u16 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0765a4f3', 0x4560, 'vabal.u32 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073704f2', 0x4560, 'vabd.s8 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073714f2', 0x4560, 'vabd.s16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073724f2', 0x4560, 'vabd.s32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073704f3', 0x4560, 'vabd.u8 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073714f3', 0x4560, 'vabd.u16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073724f3', 0x4560, 'vabd.u32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '4e6708f2', 0x4560, 'vabd.s8 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6718f2', 0x4560, 'vabd.s16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6728f2', 0x4560, 'vabd.s32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6708f3', 0x4560, 'vabd.u8 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6718f3', 0x4560, 'vabd.u16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6728f3', 0x4560, 'vabd.u32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '076784f2', 0x4560, 'vabdl.s8 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076794f2', 0x4560, 'vabdl.s16 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0767a4f2', 0x4560, 'vabdl.s32 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076784f3', 0x4560, 'vabdl.u8 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076794f3', 0x4560, 'vabdl.u16 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0767a4f3', 0x4560, 'vabdl.u32 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '4E6d28f3', 0x4560, 'vabd.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '073d24f3', 0x4560, 'vabd.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0433b1f3', 0x4560, 'vabs.s8 d3, d4', 0, ()),
        #(REV_ALL_ARM, '0433b5f3', 0x4560, 'vabs.s16 d3, d4', 0, ()),
        #(REV_ALL_ARM, '0433b9f3', 0x4560, 'vabs.s32 d3, d4', 0, ()),
        #(REV_ALL_ARM, '0437b9f3', 0x4560, 'vabs.f32 d3, d4', 0, ()),
        #(REV_ALL_ARM, 'c21af0ee', 0x4560, 'vabs.f32 s3, s4', 0, ()),
        #(REV_ALL_ARM, 'c43bb0ee', 0x4560, 'vabs.f64 d3, d4', 0, ()),
        #(REV_ALL_ARM, '173e04f3', 0x4560, 'vacge.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173e24f3', 0x4560, 'vacgt.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '143e07f3', 0x4560, 'vacle.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '143e27f3', 0x4560, 'vacle.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '5e6e08f3', 0x4560, 'vacge.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6e28f3', 0x4560, 'vacgt.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '586e0ff3', 0x4560, 'vacle.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '586e2ff3', 0x4560, 'vacle.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4E6808F2', 0x4560, 'vadd.i8  q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4E6818F2', 0x4560, 'vadd.i16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4E6828F2', 0x4560, 'vadd.i32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4E6838F2', 0x4560, 'vadd.i64 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '073804f2', 0x4560, 'vadd.i8  d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073814f2', 0x4560, 'vadd.i16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073824f2', 0x4560, 'vadd.i32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073834f2', 0x4560, 'vadd.i64 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '4e6d08f2', 0x4560, 'vadd.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '073d04f2', 0x4560, 'vadd.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '231a72ee', 0x4560, 'vadd.f32 s3, s4, s7', 0, ()),
        #(REV_ALL_ARM, '073b34ee', 0x4560, 'vadd.f64 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0e3488f2', 0x4560, 'vaddhn.i16 d3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '0e3498f2', 0x4560, 'vaddhn.i32 d3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '0e34a8f2', 0x4560, 'vaddhn.i64 d3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '076084f2', 0x4560, 'vaddl.s8 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076094f2', 0x4560, 'vaddl.s16 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0760a4f2', 0x4560, 'vaddl.s32 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076084f3', 0x4560, 'vaddl.u8 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076094f3', 0x4560, 'vaddl.u16 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0760a4f3', 0x4560, 'vaddl.u32 q3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '076188f2', 0x4560, 'vaddw.s8 q3, q4, d7', 0, ()),
        #(REV_ALL_ARM, '076198f2', 0x4560, 'vaddw.s16 q3, q4, d7', 0, ()),
        #(REV_ALL_ARM, '0761a8f2', 0x4560, 'vaddw.s32 q3, q4, d7', 0, ()),
        #(REV_ALL_ARM, '076188f2', 0x4560, 'vaddw.u8 q3, q4, d7', 0, ()),
        #(REV_ALL_ARM, '076198f3', 0x4560, 'vaddw.u16 q3, q4, d7', 0, ()),
        #(REV_ALL_ARM, '0761a8f3', 0x4560, 'vaddw.u32 q3, q4, d7', 0, ()),
        #(REV_ALL_ARM, '5e6108f2', 0x4560, 'vand q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '173104f2', 0x4560, 'vand d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '7a6980f2', 0x4560, 'vbic.i16 q3, #10', 0, ()),
        #(REV_ALL_ARM, '7a6180f2', 0x4560, 'vbic.i32 q3, #10', 0, ()),
        #(REV_ALL_ARM, '3a3980f2', 0x4560, 'vbic.i16 d3, #10', 0, ()),
        #(REV_ALL_ARM, '3a3180f2', 0x4560, 'vbic.i32 d3, #10', 0, ()),
        #(REV_ALL_ARM, '5e6118f2', 0x4560, 'vbic q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '173114f2', 0x4560, 'vbic d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173134f3', 0x4560, 'vbif d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173124f3', 0x4560, 'vbit d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173114f3', 0x4560, 'vbsl d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '5e6138f3', 0x4560, 'vbif q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6128f3', 0x4560, 'vbit q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6118f3', 0x4560, 'vbsl q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6808f3', 0x4560, 'vceq.i8 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6818f3', 0x4560, 'vceq.i16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6828f3', 0x4560, 'vceq.i32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6e08f2', 0x4560, 'vceq.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '173804f3', 0x4560, 'vceq.i8 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173814f3', 0x4560, 'vceq.i16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173824f3', 0x4560, 'vceq.i32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073e04f2', 0x4560, 'vceq.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '4861b1f3', 0x4560, 'vceq.i8 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4861b5f3', 0x4560, 'vceq.i16 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4861b9f3', 0x4560, 'vceq.i32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4865b9f3', 0x4560, 'vceq.f32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '0431b1f3', 0x4560, 'vceq.i8 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0431b5f3', 0x4560, 'vceq.i16 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0431b9f3', 0x4560, 'vceq.i32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0435b9f3', 0x4560, 'vceq.f32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '5e6308f2', 0x4560, 'vcge.s8  q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6318f2', 0x4560, 'vcge.s16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6328f2', 0x4560, 'vcge.s32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6308f3', 0x4560, 'vcge.u8  q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6318f3', 0x4560, 'vcge.u16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '5e6328f3', 0x4560, 'vcge.u32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6e08f3', 0x4560, 'vcge.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '173304f2', 0x4560, 'vcge.s8  d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173314f2', 0x4560, 'vcge.s16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173324f2', 0x4560, 'vcge.s32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173304f3', 0x4560, 'vcge.u8  d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173314f3', 0x4560, 'vcge.u16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '173324f3', 0x4560, 'vcge.u32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073e04f3', 0x4560, 'vcge.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '8430b1f3', 0x4560, 'vcge.s8  d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '8430b5f3', 0x4560, 'vcge.s16 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '8430b9f3', 0x4560, 'vcge.s32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '8434b9f3', 0x4560, 'vcge.f32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, 'c860b1f3', 0x4560, 'vcge.s8  q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, 'c860b5f3', 0x4560, 'vcge.s16 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, 'c860b9f3', 0x4560, 'vcge.s32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, 'c864b9f3', 0x4560, 'vcge.f32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4e6308f2', 0x4560, 'vcgt.s8  q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6318f2', 0x4560, 'vcge.s16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6328f2', 0x4560, 'vcgt.s32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6308f3', 0x4560, 'vcgt.u8  q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6318f3', 0x4560, 'vcgt.u16 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6328f3', 0x4560, 'vcgt.u32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '4e6e08f3', 0x4560, 'vcgt.f32 q3, q4, q7', 0, ()),
        #(REV_ALL_ARM, '073304f2', 0x4560, 'vcgt.s8  d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073314f2', 0x4560, 'vcgt.s16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073324f2', 0x4560, 'vcgt.s32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073304f3', 0x4560, 'vcgt.u8  d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073314f3', 0x4560, 'vcgt.u16 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073324f3', 0x4560, 'vcgt.u32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '073e24f3', 0x4560, 'vcgt.f32 d3, d4, d7', 0, ()),
        #(REV_ALL_ARM, '0430b1f3', 0x4560, 'vcgt.s8  d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0430b5f3', 0x4560, 'vcgt.s16 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0430b9f3', 0x4560, 'vcgt.s32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0434b9f3', 0x4560, 'vcgt.f32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '4860b1f3', 0x4560, 'vcgt.s8  q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4860b5f3', 0x4560, 'vcgt.s16 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4860b9f3', 0x4560, 'vcgt.s32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4864b9f3', 0x4560, 'vcgt.f32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '0434b0f3', 0x4560, 'vcls.s8  d3, d4', 0, ()),
        #(REV_ALL_ARM, '0434b4f3', 0x4560, 'vcls.s16 d3, d4', 0, ()),
        #(REV_ALL_ARM, '0434b8f3', 0x4560, 'vcls.s32 d3, d4', 0, ()),
        #(REV_ALL_ARM, '4864b0f3', 0x4560, 'vcls.s8  q3, q4', 0, ()),
        #(REV_ALL_ARM, '4864b4f3', 0x4560, 'vcls.s16 q3, q4', 0, ()),
        #(REV_ALL_ARM, '4864b8f3', 0x4560, 'vcls.s32 q3, q4', 0, ()),
        #(REV_ALL_ARM, '0432b1f3', 0x4560, 'vclt.s8  d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0432b5f3', 0x4560, 'vclt.s16 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0432b9f3', 0x4560, 'vclt.s32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '0436b9f3', 0x4560, 'vclt.f32 d3, d4, #0', 0, ()),
        #(REV_ALL_ARM, '4862b1f3', 0x4560, 'vclt.s8  q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4862b5f3', 0x4560, 'vclt.s16 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4862b9f3', 0x4560, 'vclt.s32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, '4866b9f3', 0x4560, 'vclt.f32 q3, q4, #0', 0, ()),
        #(REV_ALL_ARM, 'c864b0f3', 0x4560, 'vclz.i8 q3, q4', 0, ()),
        #(REV_ALL_ARM, 'c864b4f3', 0x4560, 'vclz.i16 q3, q4', 0, ()),
        #(REV_ALL_ARM, 'c864b8f3', 0x4560, 'vclz.i32 q3, q4', 0, ()),
        #(REV_ALL_ARM, '8434b0f3', 0x4560, 'vclz.i8  d3, d4', 0, ()),
        #(REV_ALL_ARM, '8434b4f3', 0x4560, 'vclz.i16 d3, d4', 0, ()),
        #(REV_ALL_ARM, '8434b8f3', 0x4560, 'vclz.i32 d3, d4', 0, ()),
        #(REV_ALL_ARM, '443bb4ee', 0x4560, 'vcmp.f64 d3, d4', 0, ()),
        #(REV_ALL_ARM, '421af4ee', 0x4560, 'vcmp.f32 s3, s4', 0, ()),
        #(REV_ALL_ARM, 'c43bb4ee', 0x4560, 'vcmpe.f64 d3, d4', 0, ()),
        #(REV_ALL_ARM, 'c21af4ee', 0x4560, 'vcmpe.f32 s3, s4', 0, ()),
        #(REV_ALL_ARM, '403bb5ee', 0x4560, 'vcmp.f64 d3, #0.0', 0, ()),
        #(REV_ALL_ARM, '401af5ee', 0x4560, 'vcmp.f32 s3, #0.0', 0, ()),
        #(REV_ALL_ARM, 'c03bb5ee', 0x4560, 'vcmpe.f64 d3, #0.0', 0, ()),
        #(REV_ALL_ARM, 'c01af5ee', 0x4560, 'vcmpe.f32 s3, #0.0', 0, ()),
        #(REV_ALL_ARM, '4865b0f3', 0x4560, 'vcnt.8 q3, q4',0, ()),
        #(REV_ALL_ARM, '0435b0f3', 0x4560, 'vcnt.8 d3, d4',0, ()),
        #(REV_ALL_ARM, '4867bbf3', 0x4560, 'vcvt.s32.f32 q3, q4',0, ()),
        #(REV_ALL_ARM, '0437bbf3', 0x4560, 'vcvt.s32.f32 d3, d4',0, ()),
        #(REV_ALL_ARM, 'c867bbf3', 0x4560, 'vcvt.u32.f32 q3, q4',0, ()),
        #(REV_ALL_ARM, '8437bbf3', 0x4560, 'vcvt.u32.f32 d3, d4',0, ()),
        #(REV_ALL_ARM, '4866bbf3', 0x4560, 'vcvt.f32.s32 q3, q4',0, ()),
        #(REV_ALL_ARM, '0436bbf3', 0x4560, 'vcvt.f32.s32 d3, d4',0, ()),
        #(REV_ALL_ARM, 'c866bbf3', 0x4560, 'vcvt.f32.u32 q3, q4',0, ()),
        #(REV_ALL_ARM, '8436bbf3', 0x4560, 'vcvt.f32.u32 d3, d4',0, ()),
        #(REV_ALL_ARM, 'c41bfdee', 0x4560, 'vcvt.s32.f64 s3, d4',0, ()),
        #(REV_ALL_ARM, '441bfdee', 0x4560, 'vcvtr.s32.f64 s3, d4',0, ()),
        #(REV_ALL_ARM, 'C21afdee', 0x4560, 'vcvt.s32.f32 s3, s4',0, ()),
        #(REV_ALL_ARM, '421afdee', 0x4560, 'vcvtr.s32.f32 s3, s4',0, ()),
        #(REV_ALL_ARM, 'c41bfcee', 0x4560, 'vcvt.u32.f64 s3, d4',0, ()),
        #(REV_ALL_ARM, '441bfcee', 0x4560, 'vcvtr.u32.f64 s3, d4',0, ()),
        #(REV_ALL_ARM, 'c21afcee', 0x4560, 'vcvt.u32.f32 s3, s4',0, ()),
        #(REV_ALL_ARM, '421afcee', 0x4560, 'vcvtf.u32.f32 s3, s4',0, ()),
        #(REV_ALL_ARM, 'c23bb8ee', 0x4560, 'vcvt.f64.s32 d3, s4',0, ()),
        #(REV_ALL_ARM, '423bb8ee', 0x4560, 'vcvt.f64.u32 d3, s4',0, ()),
        #(REV_ALL_ARM, 'c21af8ee', 0x4560, 'vcvt.f32.s32 s3, s4',0, ()),
        #(REV_ALL_ARM, '421af8ee', 0x4560, 'vcvt.f32.u32 s3, s4',0, ()),
        #(REV_ALL_ARM, '586fb4f2', 0x4560, 'vcvt.s32.f32 q3, q4, #12',0, ()),
        #(REV_ALL_ARM, '586fb4f3', 0x4560, 'vcvt.u32.f32 q3, q4, #12',0, ()),
        #(REV_ALL_ARM, '586eaef2', 0x4560, 'vcvt.f32.s32 q3, q4, #18',0, ()),
        #(REV_ALL_ARM, '586eb3f3', 0x4560, 'vcvt.f32.u32 q3, q4, #13',0, ()),
        #(REV_ALL_ARM, '143fbdf2', 0x4560, 'vcvt.s32.f32 d3, d4, #3',0, ()),
        #(REV_ALL_ARM, '143fa8f3', 0x4560, 'vcvt.u32.f32 d3, d4, #24',0, ()),
        #(REV_ALL_ARM, '143ea2f2', 0x4560, 'vcvt.f32.s32 d3, d4, #30',0, ()),
        #(REV_ALL_ARM, '143eb9f3', 0x4560, 'vcvt.f32.u32 d3, d4, #7',0, ()),
        #(REV_ALL_ARM, '643bbeee', 0x4560, 'vcvt.s16.f64 d3, d4, #7',0, ()),
        #(REV_ALL_ARM, '613bbfee', 0x4560, 'vcvt.u16.f64 d3, d4, #13',0, ()),
        #(REV_ALL_ARM, 'e83bbeee', 0x4560, 'vcvt.s32.f64 d3, d4, #15',0, ()),
        #(REV_ALL_ARM, 'e43bbfee', 0x4560, 'vcvt.u32.f64 d3, d4, #23',0, ()),
        #(REV_ALL_ARM, '641afeee', 0x4560, 'vcvt.s16.f32 s3, s4, #7',0, ()),
        #(REV_ALL_ARM, '611affee', 0x4560, 'vcvt.u16.f32 s3, s4, #13',0, ()),
        #(REV_ALL_ARM, 'e81afeee', 0x4560, 'vcvt.s32.f32 s3, s4, #15',0, ()),
        #(REV_ALL_ARM, 'e41affee', 0x4560, 'vcvt.u32.f32 s3, s4, #23',0, ()),
        #(REV_ALL_ARM, '643bbaee', 0x4560, 'vcvt.f64.s16 d3, d4, #7',0, ()),
        #(REV_ALL_ARM, '613bbbee', 0x4560, 'vcvt.f64.u16 d3, d4, #13',0, ()),
        #(REV_ALL_ARM, 'e83bbaee', 0x4560, 'vcvt.f64.s32 d3, d4, #15',0, ()),
        #(REV_ALL_ARM, 'e43bbbee', 0x4560, 'vcvt.f64.u32 d3, d4, #23',0, ()),
        #(REV_ALL_ARM, '641afaee', 0x4560, 'vcvt.f32.s16 s3, s4, #7',0, ()),
        #(REV_ALL_ARM, '611afbee', 0x4560, 'vcvt.f32.u16 s3, s4, #13',0, ()),
        #(REV_ALL_ARM, 'e81afaee', 0x4560, 'vcvt.f32.s32 s3, s4, #15',0, ()),
        #(REV_ALL_ARM, 'e41afbee', 0x4560, 'vcvt.f32.u32 s3, s4, #23',0, ()),
        # Following commands are VECTOR Instructions
        (REV_ALL_ARM, '3540f3f3', 0x4560, 'vshr.u32 d20, d21, #0x0d', 0, ()),
        (REV_ALL_ARM, 'f3ff3540', 0x4561, 'vshr.u32 d20, d21, #0x0d', 0, ()),
        (REV_ALL_ARM, '3544f3f3', 0x4560, 'vsri.32 d20, d21, #0x0d', 0, ()),
        (REV_ALL_ARM, 'f3ff3544', 0x4561, 'vsri.32 d20, d21, #0x0d', 0, ()),
        (REV_ALL_ARM, 'f3ff3546', 0x4561, 'vqshlu.s32 d20, d21, #0x13', 0, ()), # from ODAWEB
        # Following commands are THUMB commands
        ]


# temp scratch: generated these while testing
['0de803c0','8de903c0','ade903c0','2de803c0','1de803c0','3de803c0','9de903c0','bde903c0',]
['srsdb.w sp, svc',
         'srsia.w sp, svc',
          'srsia.w sp!, svc',
           'srsdb.w sp!, svc',
            'rfedb.w sp',
             'rfedb.w sp!',
              'rfeia.w sp',
               'rfeia.w sp!']

import struct
def getThumbStr(val, val2):
    return struct.pack('<HH', val, val2)

def getThumbOps(vw, numtups):
    return [vw.arch.archParseOpcode(getThumbStr(val,val2), 1, 0x8000001) for val,val2 in numtups]

# more scratch
#ops = getThumbOps(vw, [(0x0df7,0x03b0),(0x00f7,0xaa8a),(0xf7fe,0xbdbc),(0xf385,0x8424)]) ;op=ops[0];ops
#ops = getThumbOps(vw, [(0xf386,0x8424),(0xf385,0x8400)]) ;op=ops[0];ops
#Out[1]: [msr.w APSR_s, r5]

# testing PSR stuff - not actually working unittesting...
import envi.memcanvas as ememc
import envi.archs.thumb16.disasm as eatd
oper = eatd.ArmPgmStatRegOper(1,15)
#smc = ememc.StringMemoryCanvas(vw)
#oper.render(smc, None, 0)
#smc.strval == 'SPSR_fcxs'
###############################################33

class ArmInstructionSet(unittest.TestCase):
    ''' main unit test with all tests to run '''

    # defaults for settings - not fully implimented and won't be so until after ARMv8 is completed.
    armTestVersion = REV_ARMv7A
    armTestOnce = True

    def test_msr(self):
        # test the MSR instruction
        am = arm.ArmModule()
        op = am.archParseOpcode('d3f021e3'.decode('hex'))
        self.assertEqual('msr CPSR_c, #0xd3', repr(op))

    def test_BigEndian(self):
        am = arm.ArmModule()
        am.setEndian(ENDIAN_MSB)
        op = am.archParseOpcode('e321f0d3'.decode('hex'))
        self.assertEqual('msr CPSR_c, #0xd3', repr(op))

    def test_envi_arm_operands(self):
        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", "arm")
        vw.addMemoryMap(0, 7, 'firmware', '\xff' * 16384*1024)
        vw.addMemoryMap(0xbfb00000, 7, 'firmware', '\xfe' * 16384*1024)


        # testing the ArmImmOffsetOper

        # ldr r3, [#0xbfb00010]
        emu = vw.getEmulator()
        emu.setMeta('forrealz', True)
        emu._forrealz = True    # cause base_reg updates on certain Operands.

        emu.writeMemory(0xbfb00010, "abcdef98".decode('hex'))

        opstr = struct.pack('<I', 0xe59f3008)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)
        #print repr(op)
        #print hex(op.getOperValue(1, emu))

        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))



        # ldr r3, [r11, #0x8]!
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.setRegister(11, 0xbfb00010)

        opstr = struct.pack('<I', 0xe5bb3008)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(11))

        self.assertEqual(hex(0xccddeeff), hex(value))



        # ldr r3, [r11], #0x8
        emu.writeMemory(0xbfb00010, "ABCDEF10".decode('hex'))
        emu.setRegister(11, 0xbfb00010)

        opstr = struct.pack('<I', 0xe4bb3008)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(11))

        self.assertEqual(hex(0xbfb00018), hex(emu.getRegister(11)))
        self.assertEqual(hex(0x10efcdab), hex(value))


        # ldr r3, [r11], #-0x8
        emu.writeMemory(0xbfb00010, "ABCDEF10".decode('hex'))
        emu.setRegister(11, 0xbfb00010)

        opstr = struct.pack('<I', 0xe43b3008)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(11))

        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(11)))
        self.assertEqual(hex(0x10efcdab), hex(value))


        # testing the ArmScaledOffsetOper

        # ldr r2, [r10, r2 ]
        emu = vw.getEmulator()
        emu.setMeta('forrealz', True)
        emu._forrealz = True

        opstr = struct.pack('<I', 0xe79a2002)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00010, "abcdef98".decode('hex'))
        #print repr(op)
        #print hex(op.getOperValue(1, emu))

        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))
        self.assertEqual(hex(8), hex(emu.getRegister(2)))



        # ldrt r2, [r10], r2
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00008, "ABCDEF10".decode('hex'))

        opstr = struct.pack('<I', 0xe6ba2002)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0xbfb00010), hex(emu.getRegister(10)))
        self.assertEqual(hex(0x10efcdab), hex(value))



        # ldr r2, [r10, -r2 ]!
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.writeMemory(0xbfb00010, "55555555".decode('hex'))
        emu.writeMemory(0xbfb00008, "f000f000".decode('hex'))
        emu.setRegister(10, 0xbfb00010)
        emu.setRegister(2,  8)

        opstr = struct.pack('<I', 0xe73a2002)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0x00f000f0), hex(value))
        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))



        # ldr r2, [r10, r2 ]!
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.writeMemory(0xbfb00010, "55555555".decode('hex'))
        emu.setRegister(10, 0xbfb00010)
        emu.setRegister(2,  8)

        opstr = struct.pack('<I', 0xe7ba2002)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0xccddeeff), hex(value))
        self.assertEqual(hex(0xbfb00018), hex(emu.getRegister(10)))



        # Scaled with shifts/roll
        # ldr r3, [r10, r2 lsr #2]
        emu = vw.getEmulator()
        emu.setMeta('forrealz', True)
        emu._forrealz = True

        opstr = struct.pack('<I', 0xe79a3122)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  2)
        emu.writeMemory(0xbfb00008, "abcdef98".decode('hex'))
        #print repr(op)
        #print hex(op.getOperValue(1, emu))

        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))
        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(2), hex(emu.getRegister(2)))

        emu.executeOpcode(op)

        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))
        self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(2), hex(emu.getRegister(2)))



        # ldr r2, [r10], r2 , lsr 2
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  2)
        emu.writeMemory(0xbfb00008, "ABCDEF10".decode('hex'))

        opstr = struct.pack('<I', 0xe69a3122)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))
        #self.assertEqual(hex(0x98efcdab), hex(op.getOperValue(1, emu)))
        self.assertEqual(hex(2), hex(emu.getRegister(2)))
        self.assertEqual(hex(0x10efcdab), hex(value))



        # testing the ArmRegOffsetOper

        # (131071, 'b2451ae1', 17760, 'ldrh r4, [r10, -r2] ', 0, ())
        # (131071, 'b2459ae1', 17760, 'ldrh r4, [r10, r2] ', 0, ())

        # ldrh r3, [r10], -r2
        #b2451ae0
        emu = vw.getEmulator()
        emu.setMeta('forrealz', True)
        emu._forrealz = True

        opstr = struct.pack('<I', 0xe03a30b2)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00000, "abcdef98".decode('hex'))
        emu.writeMemory(0xbfb00008, "12345678".decode('hex'))
        #print repr(op)
        val = op.getOperValue(1, emu)
        #print hex(val)

        self.assertEqual(hex(0x3412), hex(val))
        self.assertEqual(hex(0xbfb00000), hex(emu.getRegister(10)))
        self.assertEqual(hex(8), hex(emu.getRegister(2)))



        # ldr r3, [r10], r2
        # (131071, 'b2359ae0', 17760, 'ldrh r4, [r10], r2 ', 0, ())
        emu.setRegister(10, 0xbfb00008)
        emu.setRegister(2,  8)
        emu.writeMemory(0xbfb00008, "ABCDEF10".decode('hex'))

        opstr = struct.pack('<I', 0xe0ba35b2)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0xbfb00010), hex(emu.getRegister(10)))
        self.assertEqual(hex(0xcdab), hex(value))



        # ldr r2, [r10, -r2 ]!
        # (131071, 'b2453ae1', 17760, 'ldrh r4, [r10, -r2]! ', 0, ())
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.writeMemory(0xbfb00010, "55555555".decode('hex'))
        emu.writeMemValue(0xbfb00008, 0xf030e040, 4)
        emu.setRegister(10, 0xbfb00010)
        emu.setRegister(2,  8)

        opstr = struct.pack('<I', 0xe13a45b2)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0xe040), hex(value))
        self.assertEqual(hex(0xbfb00008), hex(emu.getRegister(10)))



        # ldr r2, [r10, r2 ]!
        # (131071, 'b245bae1', 17760, 'ldrh r4, [r10, r2]! ', 0, ())
        emu.writeMemory(0xbfb00018, "FFEEDDCC".decode('hex'))
        emu.writeMemory(0xbfb00010, "55555555".decode('hex'))
        emu.setRegister(10, 0xbfb00010)
        emu.setRegister(2,  8)

        opstr = struct.pack('<I', 0xe1ba45b2)
        op = vw.arch.archParseOpcode(opstr, va=0xbfb00000)

        value = op.getOperValue(1, emu)
        #print repr(op)
        #print hex(value)
        #print hex(emu.getRegister(10))

        self.assertEqual(hex(0xeeff), hex(value))
        self.assertEqual(hex(0xbfb00018), hex(emu.getRegister(10)))





    def test_envi_arm_assorted_instrs(self):
        #print "\n\n\nstart of test_envi_arm_assorted_instrs"
        #setup initial work space for test
        vw = vivisect.VivWorkspace()
        vw.setMeta("Architecture", "arm")
        vw.addMemoryMap(0, 7, 'firmware', '\xff' * 16384*1024)
        vw.addMemoryMap(0x400000, 7, 'firmware', '\xff' * 16384*1024)
        emu = vw.getEmulator()
        emu.setMeta('forrealz', True)
        emu._forrealz = True
        emu.logread = emu.logwrite = True
        badcount = 0  # Note: doesn't really do anything since we error out right away
        goodcount = 0
        for archz, bytez, va, reprOp, iflags, emutests in instrs:
            ranAlready = False  # support for run once only
            #itterate through architectures
            for key in ARCH_REVS:
                test_arch = ARCH_REVS[key]
                if ((not ranAlready) or (not self.armTestOnce)) and ((archz & test_arch & self.armTestVersion) != 0):
                    ranAlready = True
                    #num, = struct.unpack("<I", bytez.decode('hex'))
                    #bs = bin(num)[2:].zfill(32)
                    #print bytez, bs
                    #print reprOp
                    op = vw.arch.archParseOpcode(bytez.decode('hex'), 0, va)
                    #print repr(op)
                    redoprepr = repr(op).replace(' ','').lower()
                    redgoodop = reprOp.replace(' ','')
                    if redoprepr != redgoodop:
                        print(bytez,redgoodop)
                        print(bytez,redoprepr)
                        print()
                        #print out binary representation of opcode for checking
                        num, = struct.unpack("<I", bytez.decode('hex'))
                        print(hex(num))
                        bs = bin(num)[2:].zfill(32)
                        print(bs)

                        badcount += 1

                        raise Exception("FAILED to decode instr:  %.8x %s - should be: %s  - is: %s" % \
                                ( va, bytez, reprOp, repr(op) ) )
                        self.assertEqual((bytez, redoprepr), (bytez, redgoodop))
                    #print bytez, op
                    if not len(emutests):
                        try:
                            # if we don't have special tests, let's just run it in the emulator anyway and see if things break
                            if not self.validateEmulation(emu, op, (), ()):
                                goodcount += 1
                            else:
                                badcount += 1
                        except envi.UnsupportedInstruction:
                            print("Instruction not in Emulator - ", repr(op))
                            badcount += 1
                        except Exception as exp:
                            print("Exception in Emulator for command - ",repr(op))
                            print("  ", exp)
                            badcount += 1
                    else:
                        # if we have a special test lets run it
                        for sCase in emutests:
                            #allows us to just have a result to check if no setup needed
                            if 'tests' in sCase:
                                setters = ()
                                if 'setup' in sCase:
                                    setters = sCase['setup']
                                tests = sCase['tests']
                                if not self.validateEmulation(emu, op, (setters), (tests)):
                                    goodcount += 1
                                else:
                                    badcount += 1
                                    raise Exception( "FAILED emulation (special case): %.8x %s - %s" % (va, bytez, op) )

                            else:
                                badcount += 1
                                raise Exception( "FAILED special case test format bad:  Instruction test does not have a 'tests' field: %.8x %s - %s" % (va, bytez, op))


        print("Done with assorted instructions test. ", str(goodcount)+" tests passed. ", str(badcount) + " tests failed.")
        print("Total of ", str(goodcount + badcount) + " tests completed.")

        #pending deletion of following comments. Please comment if they need to stay or I will delete in following commit
        #op = vw.arch.archParseOpcode('12c3'.decode('hex'))
        ##rotl.b #2, r3h
        ##print( op, hex(0x7a) )
        #emu.setRegisterByName('r3h', 0x7a)
        #emu.executeOpcode(op)
        ##print( hex(emu.getRegisterByName('r3h')), emu.getFlag(CCR_C) )
        ##0xef False

    def test_envi_arm_thumb_switches(self):
        pass

    def validateEmulation(self, emu, op, setters, tests):
        # first set any environment stuff necessary
        ## defaults
        emu.setRegister(REG_R3, 0x414141)
        emu.setRegister(REG_R4, 0x444444)
        emu.setRegister(REG_R5, 0x10)
        emu.setRegister(REG_R6, 0x464646)
        emu.setRegister(REG_R7, 0x474747)
        emu.setRegister(REG_SP, 0x450000)
        ## special cases
        # setup flags and registers
        for tgt, val in setters:
            try:
                # try register first
                emu.setRegisterByName(tgt, val)
            except e_reg.InvalidRegisterName as e:
                # it's not a register
                if type(tgt) == str and tgt.startswith("PSR_"):
                    # it's a flag
                    emu.setFlag(eval(tgt), val)
                elif type(tgt) in (int):
                    # it's an address
                    #For this couldn't we set a temp value equal to endian and write that? Assuming byte order is issue with this one
                    emu.writeMemValue(tgt, val, 1) # limited to 1-byte writes currently
                else:
                    raise Exception( "Funkt up Setting:  %s = 0x%x" % (tgt, val) )
        emu.executeOpcode(op)
        if not len(tests):
            success = 0
        else:
            success = 1
        for tgt, val in tests:
            try:
                # try register first
                testval = emu.getRegisterByName(tgt)
                if testval == val:
                    #print("SUCCESS(reg): %s  ==  0x%x" % (tgt, val))
                    success = 0
                else:  # should be an else
                    raise Exception("FAILED(reg): %s  !=  0x%x (observed: 0x%x)" % (tgt, val, testval))
            except e_reg.InvalidRegisterName as e:
                # it's not a register
                if type(tgt) == str and tgt.startswith("PSR_"):
                    # it's a flag
                    testval = emu.getFlag(eval(tgt))
                    if testval == val:
                        #print("SUCCESS(flag): %s  ==  0x%x" % (tgt, val))
                        success = 0
                    else:
                        raise Exception("FAILED(flag): %s  !=  0x%x (observed: 0x%x)" % (tgt, val, testval))
                elif type(tgt) in (int):
                    # it's an address
                    testval = emu.readMemValue(tgt, 1)
                    if testval == val:
                        #print("SUCCESS(addr): 0x%x  ==  0x%x" % (tgt, val))
                        success = 0
                    raise Exception("FAILED(mem): 0x%x  !=  0x%x (observed: 0x%x)" % (tgt, val, testval))

                else:
                    raise Exception( "Funkt up test: %s == %s" % (tgt, val) )

        # NOTE: Not sure how to test this to see if working
        # do some read/write tracking/testing
        #print emu.curpath
        if len(emu.curpath[2]['readlog']):
            outstr = emu.curpath[2]['readlog']
            if len(outstr) > 10000: outstr = outstr[:10000]
            #print( repr(op) + '\t\tRead: ' + repr(outstr) )
        if len(emu.curpath[2]['writelog']):
            outstr = emu.curpath[2]['writelog']
            if len(outstr) > 10000: outstr = outstr[:10000]
            #print( repr(op) + '\t\tWrite: '+ repr(outstr) )
        emu.curpath[2]['readlog'] = []
        emu.curpath[2]['writelog'] = []

        return success

"""
def generateTestInfo(ophexbytez='6e'):
    '''
    Helper function to help generate test cases that can easily be copy-pasta
    '''
    h8 = e_h8.H8Module()
    opbytez = ophexbytez
    op = h8.archParseOpcode(opbytez.decode('hex'), 0, 0x4000)
    #print( "opbytez = '%s'\noprepr = '%s'"%(opbytez,repr(op)) )
    opvars=vars(op)
    opers = opvars.pop('opers')
    #print( "opcheck = ",repr(opvars) )

    opersvars = []
    for x in range(len(opers)):
        opervars = vars(opers[x])
        opervars.pop('_dis_regctx')
        opersvars.append(opervars)

    #print( "opercheck = %s" % (repr(opersvars)) )

"""

raw_instrs = [
    ]


def genDPArm():
    out = []
    for z in range(16):
        for x in range(32):
            y = 0xe0034567 + (x<<20) + (z<<4)
            try:
                bytez = struct.pack("<I", y)
                out.append(bytez)
                op = vw.arch.archParseOpcode(bytez)
                print("%x %s" % (y, op))

            except:
                print("%x error" % y)

    open('dpArmTest','w').write(''.join(out))


def genMediaInstructionBytes():
    # Media Instructions
    out = []
    for x in range(32):
        for z in range(8):
            y = 0xe6034f17 + (x<<20) + (z<<5)
            try:
                bytez = struct.pack("<I", y)
                out.append(bytez)
                op = vw.arch.archParseOpcode(bytez)
                print("%x %s" % (y, op))

            except:
                print("%x error" % y)

    open('mediaArmTest','w').write(''.join(out))

def genAdvSIMD():
    # thumb
    outthumb = []
    outarm = []
    base = 0xe0043002 # generic Adv SIMD with Vn=8, Vd=6, Vm=4 (or 4,3,2, depending)
    # thumb dp, arm dp (with both 0/1 for U)
    for option in (0xf000000, 0x2000000, 0x3000000, 0x1f000000):
        for A in range(16): # three registers of same length
            for B in range(16): # three registers of same length
                for C in range(16):
                    val = base + (A<<19) + (B<<8) + (C<<4)
                    bytez = struct.pack("<I", val)
                    outarm.append(bytez)
                    bytez = struct.pack("<HH", val>>16, val&0xffff)
                    outthumb.append(bytez)

                    #op = vw.arch.archParseOpcode(bytez)
                    #print "%x %s" % (val, op)

    out = outarm
    out.extend(outthumb)
    open('advSIMD', 'wb').write(''.join(out))



# thumb 16bit IT, CNBZ, CBZ
