import random
from pwn import *
from valid_nops import all_nops

context.update(
    os="linux",
    arch="amd64"
)

def replace_nullbytes_with_random(data):
    return bytes([random.randint(1, 255) if b == 0 else b for b in data])

def generate_random_nop_mix(desired_length):
    selected_instructions = []
    def backtrack(total_bytes):
        if total_bytes == desired_length:
            return True
        random.shuffle(all_nops)
        for inst in all_nops:
            next_total = total_bytes + len(inst)
            if next_total <= desired_length:
                selected_instructions.append(inst)
                if backtrack(next_total):
                    return True
                selected_instructions.pop()
        return False
    backtrack(0)
    random.shuffle(selected_instructions)
    return bytearray([byte for sublist in selected_instructions for byte in sublist])

flag_bytes = [0x90 - b for b in b"flag{NOP_is_just_an_alias_mnemonic_for_the_XCHG_EAX_EAX_instruction}"]
wrong_string = b"NOP, that's wrong!\n"
right_string = b"0x90 Correct! 0x90\n"

argc_check = """
    cmp edi, 0x2
    stc ; jne $+4
"""

get_argv_flag = """
    push 0x8
    pop rax
    add rsi, rax
    mov r12, [rsi]
"""

debug_check = """
    xor r10d, r10d
    xor edx, edx
    xor esi, esi
    xor edi, edi
    push SYS_ptrace
    pop rax
    syscall

    test eax, eax
    stc ; js $+4

    push PTRACE_DETACH
    pop rdx
    xor esi, esi
    xor edi, edi
    push SYS_ptrace
    pop rax
    syscall
"""

mmmap_mem = """
    xor r9d, r9d
    xor r8d, r8d
    push (MAP_PRIVATE | MAP_ANONYMOUS)
    pop r10
    push (PROT_READ | PROT_WRITE)
    pop rdx
    push 9
    pop rsi
    shl esi, 4
    
    mov al, 0x90
    mov ah, 0x90
    bswap eax
    mov ah, 0x90
    mov edi, eax

    push SYS_mmap
    pop rax
    syscall

    mov rdi, rax
"""

read_flag = f"""
    push rdi

    {shellcraft.mmap_rwx()}
    mov rsi, rax
    push 0x20
    pop rdx
    xor edi, edi
    xor eax, eax
    syscall
    
    mov rbx, rsi
    pop rdi
"""

check_flag_bytes = """
    xor eax, eax
    xor ecx, ecx
    mov rbx, r12
    mov al, 0x90
"""

for b in flag_bytes:
    check_flag_bytes += f"""
        movb cl, [rbx]
        inc rbx
        add cl, {b}
        cmp cl, al
        sete [rdi]
        inc rdi
    """

check_if_flag_correct = f"""
    nop ; nop /* crucial lol */
    xor eax, eax
    inc al
    push {len(flag_bytes)}
    pop rcx
    dec rdi
    sub rbx, rcx

    std
    repe scasb
    sete [rbx]
"""

create_string = """
    xor eax, eax
    inc rdi
"""

for wrong, right in zip(wrong_string, right_string):
    create_string += f"""
        mov al, {wrong}
        mov cl, {right}
        cmpb [rbx], 0x1
        cmove eax, ecx
        movb [rdi], al
        inc rdi
    """

print_string = f"""
    push {len(right_string)}
    pop rdx

    mov rsi, rdi
    sub rsi, rdx

    push STDOUT_FILENO
    pop rdi

    push SYS_write
    pop rax
    syscall

    stc ; jmp $+4
"""

shellcode = "".join([
    argc_check,
    get_argv_flag,
    debug_check,
    mmmap_mem,
    check_flag_bytes,
    check_if_flag_correct,
    create_string,
    print_string,
])

print(disasm(asm(shellcode)))
assert b"\x00" not in asm(shellcode), "Shellcode has nullbytes"

#with gdb.debug_assembly(shellcode) as p:
#    p.sendline(b"flag{NOP}")
#    p.interactive()
#exit()

instruction_bytes = []
with log.progress("Assembling shellcode") as p:
    for i, line in enumerate(shellcode.split("\n")):
        if line.strip():
            instruction_bytes.append(asm(line)) # if asm() is really slow, run as root
            p.status(f"{i}")
            
for instruction in instruction_bytes: assert len(instruction) <= 3, "Instruction exceeds 3 bytes"

start_instr = b"\x90"
shellcode = generate_random_nop_mix(127)
start_index = previous_index = shellcode.index(b"\0" * (len(start_instr) + 2))
shellcode[start_index:start_index+len(start_instr)] = start_instr

previous_index = start_index
previous_instr_len = len(start_instr)

info("Encoding instructions into nops:")
for instruction in instruction_bytes:

    print(disasm(instruction))
    found = False

    while not found:

        chunk = generate_random_nop_mix(127)
        test_shellcode = shellcode + chunk

        try:
            insertion_point = test_shellcode[len(shellcode):].index(b"\0"*(len(instruction) + 2))
            insertion_index = len(shellcode) + insertion_point
            
            jump_distance = insertion_index - (previous_index + previous_instr_len)
            if jump_distance > 127: continue

            test_shellcode[previous_index+previous_instr_len:previous_index+previous_instr_len + 2] = bytes([0xeb, jump_distance - 2])
            test_shellcode[insertion_index:insertion_index+len(instruction)] = instruction
            
            previous_index = insertion_index
            previous_instr_len = len(instruction)

            shellcode = test_shellcode
            found = True
            
        except ValueError as e:
            pass


shellcode = replace_nullbytes_with_random(shellcode)
shellcode_bytes = ".byte " + ",".join(f"0x{b:02x}" for b in shellcode)
print(disasm(shellcode))

c_file = f"""
#include <stdio.h>
#include <stdint.h>

void nop();
char _nop __attribute__((section(".nop")));
void __attribute__((constructor)) __nop__() {{
    _nop = 0x90; /* serves no purpose, mostly for fun */
}}

void __attribute__((naked)) main() {{
    __asm__(
        "{shellcode_bytes}\\n"
        "call nop   \\n" 
        "nop        \\n" 
        "ret        \\n"
    );
}}
 

void __attribute__((naked)) nop() {{

    /* 
        We use the carry flag to check if we've been in nop() before.
        Does an invalid syscall to get the value of RIP in RCX, then does a call to the start of out NOP chain
    */
    
    __asm__(
        ".intel_syntax noprefix                 \\n"
        "jb .Lret                               \\n"
        "or ah, -1                              \\n"
        "syscall                                \\n"
        "sub rcx, . - main - 4 - {start_index}  \\n"
        "call rcx                               \\n"
        ".Lret: ret                             \\n"
    );
}}
"""

print(c_file)
print("Start @:", start_index)

with open("nop.c", "w") as f:
    f.write(c_file)

os.system("make")