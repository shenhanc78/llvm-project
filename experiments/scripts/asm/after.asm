000000000306d990 <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjS3_bjPKNS_11MCSymbolELFE>:
 306d990:	55                   	push   %rbp
 306d991:	41 57                	push   %r15
 306d993:	41 56                	push   %r14
 306d995:	41 55                	push   %r13
 306d997:	41 54                	push   %r12
 306d999:	53                   	push   %rbx
 306d99a:	48 83 ec 28          	sub    $0x28,%rsp
 306d99e:	48 89 fb             	mov    %rdi,%rbx
 306d9a1:	4c 8b 5c 24 70       	mov    0x70(%rsp),%r11
 306d9a6:	44 8b 54 24 68       	mov    0x68(%rsp),%r10d
 306d9ab:	8a 44 24 60          	mov    0x60(%rsp),%al
 306d9af:	41 80 79 20 02       	cmpb   $0x2,0x20(%r9)
 306d9b4:	0f 82 82 00 00 00    	jb     306da3c <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjS3_bjPKNS_11MCSymbolELFE+0xac>
 306d9ba:	4d 89 ce             	mov    %r9,%r14
 306d9bd:	48 89 34 24          	mov    %rsi,(%rsp)
 306d9c1:	41 89 d5             	mov    %edx,%r13d
 306d9c4:	89 cd                	mov    %ecx,%ebp
 306d9c6:	45 89 c4             	mov    %r8d,%r12d
 306d9c9:	4c 8d 7c 24 08       	lea    0x8(%rsp),%r15
 306d9ce:	4c 89 ff             	mov    %r15,%rdi
 306d9d1:	4c 89 ce             	mov    %r9,%rsi
 306d9d4:	e8 d7 1d ea fe       	call   1f0f7b0 <_ZNK4llvm5Twine3strB5cxx11Ev>
 306d9d9:	49 8b 3f             	mov    (%r15),%rdi
 306d9dc:	4d 8b 7f 08          	mov    0x8(%r15),%r15
 306d9e0:	48 8d 44 24 18       	lea    0x18(%rsp),%rax
 306d9e5:	48 39 c7             	cmp    %rax,%rdi
 306d9e8:	74 0d                	je     306d9f7 <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjS3_bjPKNS_11MCSymbolELFE+0x67>
 306d9ea:	48 8b 74 24 18       	mov    0x18(%rsp),%rsi
 306d9ef:	48 ff c6             	inc    %rsi
 306d9f2:	e8 b9 b0 f4 02       	call   5fb8ab0 <_ZdlPvm@plt>
 306d9f7:	4d 85 ff             	test   %r15,%r15
 306d9fa:	75 45                	jne    306da41 <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjS3_bjPKNS_11MCSymbolELFE+0xb1>
 306d9fc:	45 31 c9             	xor    %r9d,%r9d
 306d9ff:	45 89 e0             	mov    %r12d,%r8d
 306da02:	89 e9                	mov    %ebp,%ecx
 306da04:	44 89 ea             	mov    %r13d,%edx
 306da07:	48 8b 34 24          	mov    (%rsp),%rsi
 306da0b:	44 8b 54 24 68       	mov    0x68(%rsp),%r10d
 306da10:	4c 8b 5c 24 70       	mov    0x70(%rsp),%r11
 306da15:	8a 44 24 60          	mov    0x60(%rsp),%al
 306da19:	48 83 ec 08          	sub    $0x8,%rsp
 306da1d:	0f b6 c0             	movzbl %al,%eax
 306da20:	48 89 df             	mov    %rbx,%rdi
 306da23:	41 53                	push   %r11
 306da25:	41 52                	push   %r10
 306da27:	50                   	push   %rax
 306da28:	e8 33 00 00 00       	call   306da60 <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjPKNS_11MCSymbolELFEbjS6_>
 306da2d:	48 83 c4 48          	add    $0x48,%rsp
 306da31:	5b                   	pop    %rbx
 306da32:	41 5c                	pop    %r12
 306da34:	41 5d                	pop    %r13
 306da36:	41 5e                	pop    %r14
 306da38:	41 5f                	pop    %r15
 306da3a:	5d                   	pop    %rbp
 306da3b:	c3                   	ret
 306da3c:	45 31 c9             	xor    %r9d,%r9d
 306da3f:	eb d8                	jmp    306da19 <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjS3_bjPKNS_11MCSymbolELFE+0x89>
 306da41:	48 89 df             	mov    %rbx,%rdi
 306da44:	4c 89 f6             	mov    %r14,%rsi
 306da47:	e8 24 2e ff ff       	call   3060870 <_ZN4llvm9MCContext17getOrCreateSymbolERKNS_5TwineE>
 306da4c:	49 89 c1             	mov    %rax,%r9
 306da4f:	eb ae                	jmp    306d9ff <_ZN4llvm9MCContext13getELFSectionERKNS_5TwineEjjjS3_bjPKNS_11MCSymbolELFE+0x6f>
 306da51:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 306da58:	0f 1f 84 00 00 00 00 
 306da5f:	00
