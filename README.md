# nopfuscator

A Proof of Concept for hiding instructions inside multi-byte NOP instructions.

It works by splitting up each line of your custom assembly, inserting them into the "wasted" bytes of the NOP instructions, and jumping between them using the 2 byte `JMP rel8`. 

Basically Jump-Oriented Programming (JOP), but with the fun of NOP.

The source assembly cannot have a single instruction that surpasses 3 bytes, which is both a pain and really fun to program around.

This works really well for demotivating reverse engineers, but is in no way an advanced form of obfuscation.

# How to use

```sh
python3 ./nopfuscator.py
```

If the assembling takes a long time, try running as root. Pwntool's `asm()` is special like that.

# Example disassembled code

```c
pwndbg> disass main+500, main+700
Dump of assembler code from 0x55555555532f to 0x5555555553f7:
   0x000055555555532f <main+500>:       nop    edi
   0x0000555555555332 <main+503>:       data16 nop WORD PTR [rcx+0x20692df2]
   0x000055555555533b <main+512>:       data16 nop WORD PTR [rdi]
   0x0000555555555340 <main+517>:       data16 nop dx
   0x0000555555555345 <main+522>:       nop    WORD PTR [rbp+0x1c73eb58]
   0x000055555555534d <main+530>:       nop    DWORD PTR [rbx+rdi*8-0x1ee48473]
   0x0000555555555355 <main+538>:       nop    sp
   0x0000555555555359 <main+542>:       nop    DWORD PTR [rsi]
   0x000055555555535c <main+545>:       data16 nop WORD PTR [rcx-0x67bb780a]
   0x0000555555555365 <main+554>:       nop    DWORD PTR [rcx]
   0x0000555555555368 <main+557>:       data16 nop WORD PTR [rip+0xffffffff8b5592ac]
   0x0000555555555371 <main+566>:       nop    WORD PTR [rsi-0x7110f5ba]
   0x0000555555555379 <main+574>:       nop    WORD PTR [rip+0xffffffffe9369d8c]
   0x0000555555555381 <main+582>:       nop    DWORD PTR [rbx+rsi*1-0x7b]
   0x0000555555555386 <main+587>:       nop    DWORD PTR [rcx+0x7cb21f3d]
   0x000055555555538d <main+594>:       nop    dx
   0x0000555555555391 <main+598>:       nop    DWORD PTR [rsi-0x79fd4e4e]
   0x0000555555555398 <main+605>:       data16 nop ax
   0x000055555555539d <main+610>:       data16 nop WORD PTR [rdi]
   0x00005555555553a2 <main+615>:       nop    DWORD PTR [rcx]
   0x00005555555553a5 <main+618>:       data16 nop WORD PTR [rax]
   0x00005555555553aa <main+623>:       data16 nop cx
   0x00005555555553af <main+628>:       nop    WORD PTR [rcx]
   0x00005555555553b3 <main+632>:       nop    DWORD PTR [rip+0x3f62e2f5]        # 0x555594b836af
   0x00005555555553ba <main+639>:       data16 nop WORD PTR [rax+rcx*2+0x7aebc601]
   0x00005555555553c4 <main+649>:       nop    edx
   0x00005555555553c7 <main+652>:       data16 nop dx
   0x00005555555553cc <main+657>:       data16 nop bp
   0x00005555555553d1 <main+662>:       nop    DWORD PTR [rcx-0x3b026203]
   0x00005555555553d8 <main+669>:       nop    WORD PTR [rdi-0x9e000ff]
   0x00005555555553e0 <main+677>:       nop    DWORD PTR [rbx]
   0x00005555555553e3 <main+680>:       nop    DWORD PTR [rdi-0x3dc04327]
   0x00005555555553ea <main+687>:       nop    si
   0x00005555555553ee <main+691>:       nop    edi
   0x00005555555553f1 <main+694>:       nop    DWORD PTR [rdx-0x2ead4337]
```

# Inspired by
- https://github.com/woodruffw/steg86
- https://github.com/xoreaxeaxeax/movfuscator