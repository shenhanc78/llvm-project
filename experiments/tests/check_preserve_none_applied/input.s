
input.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <opt_add>:
   0:	53                   	push   %rbx
   1:	48 89 f8             	mov    %rdi,%rax
   4:	48 01 f0             	add    %rsi,%rax
   7:	5b                   	pop    %rbx
   8:	c3                   	ret
   9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000000010 <caller>:
  10:	50                   	push   %rax
  11:	e8 ea ff ff ff       	call   0 <opt_add>
  16:	59                   	pop    %rcx
  17:	c3                   	ret
