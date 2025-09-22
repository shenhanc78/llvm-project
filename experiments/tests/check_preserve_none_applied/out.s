
out.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <opt_add>:
   0:	4c 89 e0             	mov    %r12,%rax
   3:	4c 01 e8             	add    %r13,%rax
   6:	c3                   	ret
   7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
   e:	00 00 

0000000000000010 <caller>:
  10:	41 57                	push   %r15
  12:	41 56                	push   %r14
  14:	41 55                	push   %r13
  16:	41 54                	push   %r12
  18:	53                   	push   %rbx
  19:	49 89 f5             	mov    %rsi,%r13
  1c:	49 89 fc             	mov    %rdi,%r12
  1f:	e8 dc ff ff ff       	call   0 <opt_add>
  24:	5b                   	pop    %rbx
  25:	41 5c                	pop    %r12
  27:	41 5d                	pop    %r13
  29:	41 5e                	pop    %r14
  2b:	41 5f                	pop    %r15
  2d:	c3                   	ret
