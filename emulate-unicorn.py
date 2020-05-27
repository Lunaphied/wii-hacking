#!/usr/bin/env python
# Sample code for ARM big endian of Unicorn. zhangwm <rustydaar@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from struct import pack, unpack, unpack_from

# code to be emulated
BOOT1_FILENAME = 'boot1-dec.bin'

# memory address where emulation starts
ADDRESS = 0x0D400000
TIMER_BASE = 0x0d800010
PANIC_BLINKER = 0x0d8000e0

# Just tick this every time we try to read the timer
stupid_timer = 0

# This really only reflects a flow of function calls
# more detailed inner function flow could be useful but would require more work and probably
# would want to only be implemented for specific functions

# XXX: something like that more detailed flow (and even here for at least R0-R3 and SP) would
# be helpful to record full function state (registers at each instruction and path) which could
# then be stepped through seperately or at least matched up with instructions from a disassembly
# or Ghidra to follow code as it executes (i.e. tracing) like microsofts back in time debugging thing 
code_flow = []

# Do extra dump of state for hooks at this addr
# note this is for a PC! of the read/write not the address (specific accesses are what we want to dump)
enhanced_hook_addrs = set([
    
])

# Don't log these IO addresses (probably only useful for timer)
# in the future once more are known a whitelist could be more useful
skip_print = set([
    TIMER_BASE
])

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    #pass
    #print(">>> Tracing basic block at 0x%x, blo6ck size = 0x%x" %(address, size))
    from_addr = uc.reg_read(UC_ARM_REG_LR)
    if len(code_flow) > 0:
        # Don't record infinite loops more than once
        # also use the fact that LR is only updated during function calls (at least for non-leaf)
        # so if LR is the same we're really still in the same function block and avoid logging
        if code_flow[-1][0] != address and code_flow[-1][0] != from_addr:
            code_flow.append((from_addr,address))
    else:
        code_flow.append((from_addr, address))

def dump_state(uc, dump_context="UNKNOWN", address=0xABADC0DE):
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    lr = uc.reg_read(UC_ARM_REG_LR)
    sp = uc.reg_read(UC_ARM_REG_SP)
    pc = uc.reg_read(UC_ARM_REG_PC)
    cpsr = uc.reg_read(UC_ARM_REG_CPSR)
    print("[%s] ADDR=%08x | R0 = 0x%08x | R1 = 0x%08x | R2 = 0x%08x | R3 = 0x%08x | LR = 0x%08x" % 
        (dump_context, address, r0, r1, r2, r3, lr))
    print("       PC=0x{:08x} | SP=0x{:08x} | CPSR=0x{:08x}".format(pc, sp, cpsr))

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    # dump state after every instruction
    dump_state(uc, "CODE", address)

# Handle special IO reads (like timer/etc)
def special_case_read(uc, address, size, value):
    if address == TIMER_BASE:
        # tick every time we read it, (might need to increase tick rate sometimes)
        global stupid_timer
        stupid_timer += 1
        stupid_timer &= 0xFFFFFFFF
        uc.mem_write(TIMER_BASE, pack('>I', stupid_timer))
    

# Handle special IO writes (...)
def special_case_write(uc, address, size, value):
    pass

def hook_mem_invalid(uc, access, address, size, value, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    if pc in enhanced_hook_addrs:
        print('[IO] ENHANCED DUMP START')
        dump_state(uc, "IO", address)
    if access == UC_MEM_READ:
        special_case_read(uc, address, size, value)
        # Actually get the value that will be read, which is why this happens after the read handler
        try:
            value, = unpack('>I',uc.mem_read(address, 4))
        except:
            value = 0xBADADD4
        # XXX: Make better
        if address not in skip_print:
            if address not in symbol_map:
                print('[IO][READ] (%d) %08x: %08x @ PC=%08x' % (size, address, value, pc))
            else:
                print('[IO][READ] (%d) %s: %08x @ PC=%08x' % (size, symbol_map[address], value, pc))
    elif access == UC_MEM_WRITE:
        if address not in skip_print:
            if address not in symbol_map:
                print('[IO][WRITE] (%d) %08x: %08x @ PC=%08x' % (size, address, value, pc))
            else:
                print('[IO][WRITE] (%d) %s: %08x @ PC=%08x' % (size, symbol_map[address], value, pc))
        special_case_write(uc, address, size, value)
    else:
        if address not in skip_print:
            print('[IO][UNKNOWN] Probably bad address=0x{:08x} access @ PC=0x{:08x}'.format(address,pc))
        dump_state(uc, "IO", address)
    if address in enhanced_hook_addrs:
        print('[IO] ENHANCED DUMP END')
    return False



# Test ARM
def test_arm():
    print("Emulate ARM Big-Endian code")
    # Read Boot1 into memory
    with open(BOOT1_FILENAME,'rb') as f:
        boot1_data = f.read()
    
    # Initialize emulator in ARM mode
    boot1_size = len(boot1_data)
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_BIG_ENDIAN)
    print('boot1 size: 0x{0:08x} ({0:d}): {1:f}KiB'.format(boot1_size, boot1_size/1024.0))
    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 0x10000)
    mu.mem_map(0x0d800000, 0x100000, UC_PROT_ALL)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, boot1_data)

    # initialize machine registers with garbage to see changes at tested code
    # TODO: make this do all registers not just param passing registers
    for reg in [UC_ARM_REG_R0, UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]:
        mu.reg_write(reg, 0xDEADBABE)
    # init sp
    # Give us a stack at the end of the SRAM for testing individual functions
    stack_base = ADDRESS+0x10000
    stack_size = 0x1000
    mu.reg_write(UC_ARM_REG_SP, stack_base)
    # Assume a 0x1000 byte stack and allocate a 0x1000 byte data area
    data_size = 0x1000
    some_space = stack_base - stack_size - data_size

    # tracing all basic blocks with customized callback
    mu.hook_add(UC_HOOK_BLOCK, hook_block)
    mu.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE, hook_mem_invalid, begin=0x0d800000,end=0x0d900000)
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

    # tracing one instruction at ADDRESS with customized callback
    custom_start = 0x0d401488
    custom_end = 0x0d40149a
    CUSTOM = 0
    if CUSTOM:
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=custom_start, end=custom_end)
        # XXX: Add user code to run in custom mode here
        mu.reg_write(UC_ARM_REG_R0, some_space)
        mu.reg_write(UC_ARM_REG_R1, some_space+4)
        mu.mem_write(0x0d800214, b'\xDA\x3E\xCA\x5E')

    # emulate machine code in infinite time
    
    pc = ADDRESS
    if CUSTOM:
        pc = custom_start|1 
    while True:
        try:
            if not CUSTOM:
                mu.emu_start(pc, pc+0x10000, count=100000)
            else:
                mu.emu_start(pc, pc+0x10000, count=30)
        except UcError as e:
            print(e)
        print('Code Flow:')
        for i in code_flow:
            # Todo fix hacky mess that uses tuples and only deals with target not from
            if i[1] in symbol_map:
                symbol = symbol_map[i[1]]
            else:
                symbol = 'block_0x{:08x}'.format(i[1])
            print('0x{:08x} -> 0x{:08x} : {}'.format(i[0],i[1], symbol))
        # User code to run after exit for custom runs
        if CUSTOM:
            v1, = unpack('>I', mu.mem_read(some_space,4))
            v2, = unpack('>I', mu.mem_read(some_space+4,4))
            print('v1: 0x%08x' % (v1))
            print('v2: 0x%08x' % (v2))
        # XXX: for running multiple loops (was a plan for handling buggy invalid read detection)
        break
        pc = mu.reg_read(UC_ARM_REG_PC)
        if (mu.reg_read(UC_ARM_REG_CPSR)&(1<<5)):
            pc |= 1

    # now print out some registers
    print(">>> Emulation done. Below is the CPU context")
    dump_state(mu)


if __name__ == '__main__':
    # XXX: this is very bad and terrible but hey it works!
    global symbol_map
    symbol_map = {}
    with open('symbol_map.txt','r') as symbol_file:
        for line in symbol_file:
            line = line.strip()
            # Empty lines or comments get skipped
            if len(line) == 0 or line[0] == '#':
                continue
            try:
                addr, symbol_name = line.split('\t')
                addr = int(addr, 16) # XXX: should we handle 0x type symbols too?
                symbol_map[addr] = symbol_name
            except Exception as e:
                print(f'Badly formatted line: {line!r}, error={e}')
    test_arm()