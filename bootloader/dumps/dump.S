../bootloader/bootloader.elf
architecture: avr:51, flags 0x00000102:
EXEC_P, D_PAGED
start address 0x0001e000

Program Header:
    LOAD off    0x000000b4 vaddr 0x0001e000 paddr 0x0001e000 align 2**1
         filesz 0x00000b24 memsz 0x00000b24 flags r-x
    LOAD off    0x00000bd8 vaddr 0x00800100 paddr 0x0001eb24 align 2**0
         filesz 0x00000000 memsz 0x00000000 flags rw-
    LOAD off    0x00000bd8 vaddr 0x00800100 paddr 0x0001eb24 align 2**0
         filesz 0x00000000 memsz 0x007e198f flags rw-
    LOAD off    0x00000bd8 vaddr 0x00810000 paddr 0x00810000 align 2**0
         filesz 0x00000303 memsz 0x00000303 flags rw-
Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .data         00000000  00800100  0001eb24  00000bd8  2**0
                  CONTENTS, ALLOC, LOAD, DATA
  1 .text         00000b24  0001e000  0001e000  000000b4  2**1
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  2 .bss          000003b3  00800100  0001eb24  00000bd8  2**0
                  ALLOC
  3 .eeprom       00000303  00810000  00810000  00000bd8  2**0
                  CONTENTS, ALLOC, LOAD, DATA
  4 .comment      00000011  00000000  00000000  00000edb  2**0
                  CONTENTS, READONLY
SYMBOL TABLE:
no symbols



Disassembly of section .text:

0001e000 <.text>:
   1e000:	14 be       	out	0x34, r1	; 52
   1e002:	88 e1       	ldi	r24, 0x18	; 24
   1e004:	80 93 60 00 	sts	0x0060, r24
   1e008:	10 92 60 00 	sts	0x0060, r1
   1e00c:	00 c0       	rjmp	.+0      	;  0x1e00e
   1e00e:	24 e0       	ldi	r18, 0x04	; 4
   1e010:	a0 e0       	ldi	r26, 0x00	; 0
   1e012:	b1 e0       	ldi	r27, 0x01	; 1
   1e014:	01 c0       	rjmp	.+2      	;  0x1e018
   1e016:	1d 92       	st	X+, r1
   1e018:	a3 3b       	cpi	r26, 0xB3	; 179
   1e01a:	b2 07       	cpc	r27, r18
   1e01c:	e1 f7       	brne	.-8      	;  0x1e016
   1e01e:	f4 c4       	rjmp	.+2536   	;  0x1ea08
   1e020:	10 92 cd 00 	sts	0x00CD, r1
   1e024:	8a e0       	ldi	r24, 0x0A	; 10
   1e026:	80 93 cc 00 	sts	0x00CC, r24
   1e02a:	e8 ec       	ldi	r30, 0xC8	; 200
   1e02c:	f0 e0       	ldi	r31, 0x00	; 0
   1e02e:	80 81       	ld	r24, Z
   1e030:	8d 7f       	andi	r24, 0xFD	; 253
   1e032:	80 83       	st	Z, r24
   1e034:	88 e1       	ldi	r24, 0x18	; 24
   1e036:	80 93 c9 00 	sts	0x00C9, r24
   1e03a:	86 e0       	ldi	r24, 0x06	; 6
   1e03c:	80 93 ca 00 	sts	0x00CA, r24
   1e040:	08 95       	ret
   1e042:	90 91 c8 00 	lds	r25, 0x00C8
   1e046:	95 ff       	sbrs	r25, 5
   1e048:	fc cf       	rjmp	.-8      	;  0x1e042
   1e04a:	80 93 ce 00 	sts	0x00CE, r24
   1e04e:	08 95       	ret
   1e050:	80 91 c8 00 	lds	r24, 0x00C8
   1e054:	88 1f       	adc	r24, r24
   1e056:	88 27       	eor	r24, r24
   1e058:	88 1f       	adc	r24, r24
   1e05a:	08 95       	ret
   1e05c:	80 91 c8 00 	lds	r24, 0x00C8
   1e060:	87 ff       	sbrs	r24, 7
   1e062:	fc cf       	rjmp	.-8      	;  0x1e05c
   1e064:	80 91 ce 00 	lds	r24, 0x00CE
   1e068:	08 95       	ret
   1e06a:	80 91 c8 00 	lds	r24, 0x00C8
   1e06e:	87 ff       	sbrs	r24, 7
   1e070:	03 c0       	rjmp	.+6      	;  0x1e078
   1e072:	80 91 ce 00 	lds	r24, 0x00CE
   1e076:	f9 cf       	rjmp	.-14     	;  0x1e06a
   1e078:	08 95       	ret
   1e07a:	cf 93       	push	r28
   1e07c:	df 93       	push	r29
   1e07e:	ec 01       	movw	r28, r24
   1e080:	89 91       	ld	r24, Y+
   1e082:	88 23       	and	r24, r24
   1e084:	19 f0       	breq	.+6      	;  0x1e08c
   1e086:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1e08a:	fa cf       	rjmp	.-12     	;  0x1e080
   1e08c:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1e090:	df 91       	pop	r29
   1e092:	cf 91       	pop	r28
   1e094:	08 95       	ret
   1e096:	10 92 c5 00 	sts	0x00C5, r1
   1e09a:	8a e0       	ldi	r24, 0x0A	; 10
   1e09c:	80 93 c4 00 	sts	0x00C4, r24
   1e0a0:	e0 ec       	ldi	r30, 0xC0	; 192
   1e0a2:	f0 e0       	ldi	r31, 0x00	; 0
   1e0a4:	80 81       	ld	r24, Z
   1e0a6:	8d 7f       	andi	r24, 0xFD	; 253
   1e0a8:	80 83       	st	Z, r24
   1e0aa:	88 e1       	ldi	r24, 0x18	; 24
   1e0ac:	80 93 c1 00 	sts	0x00C1, r24
   1e0b0:	86 e0       	ldi	r24, 0x06	; 6
   1e0b2:	80 93 c2 00 	sts	0x00C2, r24
   1e0b6:	08 95       	ret
   1e0b8:	90 91 c0 00 	lds	r25, 0x00C0
   1e0bc:	95 ff       	sbrs	r25, 5
   1e0be:	fc cf       	rjmp	.-8      	;  0x1e0b8
   1e0c0:	80 93 c6 00 	sts	0x00C6, r24
   1e0c4:	08 95       	ret
   1e0c6:	80 91 c0 00 	lds	r24, 0x00C0
   1e0ca:	88 1f       	adc	r24, r24
   1e0cc:	88 27       	eor	r24, r24
   1e0ce:	88 1f       	adc	r24, r24
   1e0d0:	08 95       	ret
   1e0d2:	80 91 c0 00 	lds	r24, 0x00C0
   1e0d6:	87 ff       	sbrs	r24, 7
   1e0d8:	fc cf       	rjmp	.-8      	;  0x1e0d2
   1e0da:	80 91 c6 00 	lds	r24, 0x00C6
   1e0de:	08 95       	ret
   1e0e0:	80 91 c0 00 	lds	r24, 0x00C0
   1e0e4:	87 ff       	sbrs	r24, 7
   1e0e6:	03 c0       	rjmp	.+6      	;  0x1e0ee
   1e0e8:	80 91 c6 00 	lds	r24, 0x00C6
   1e0ec:	f9 cf       	rjmp	.-14     	;  0x1e0e0
   1e0ee:	08 95       	ret
   1e0f0:	cf 93       	push	r28
   1e0f2:	df 93       	push	r29
   1e0f4:	ec 01       	movw	r28, r24
   1e0f6:	89 91       	ld	r24, Y+
   1e0f8:	88 23       	and	r24, r24
   1e0fa:	19 f0       	breq	.+6      	;  0x1e102
   1e0fc:	0e 94 5c f0 	call	0x1e0b8	;  0x1e0b8
   1e100:	fa cf       	rjmp	.-12     	;  0x1e0f6
   1e102:	0e 94 5c f0 	call	0x1e0b8	;  0x1e0b8
   1e106:	df 91       	pop	r29
   1e108:	cf 91       	pop	r28
   1e10a:	08 95       	ret
   1e10c:	cf 92       	push	r12
   1e10e:	df 92       	push	r13
   1e110:	ef 92       	push	r14
   1e112:	ff 92       	push	r15
   1e114:	cf 93       	push	r28
   1e116:	9f e0       	ldi	r25, 0x0F	; 15
   1e118:	88 e1       	ldi	r24, 0x18	; 24
   1e11a:	0f b6       	in	r0, 0x3f	; 63
   1e11c:	f8 94       	cli
   1e11e:	a8 95       	wdr
   1e120:	80 93 60 00 	sts	0x0060, r24
   1e124:	0f be       	out	0x3f, r0	; 63
   1e126:	90 93 60 00 	sts	0x0060, r25
   1e12a:	82 e0       	ldi	r24, 0x02	; 2
   1e12c:	90 e0       	ldi	r25, 0x00	; 0
   1e12e:	0e 94 64 f5 	call	0x1eac8	;  0x1eac8
   1e132:	6c 01       	movw	r12, r24
   1e134:	e1 2c       	mov	r14, r1
   1e136:	f1 2c       	mov	r15, r1
   1e138:	c1 14       	cp	r12, r1
   1e13a:	d1 04       	cpc	r13, r1
   1e13c:	e1 04       	cpc	r14, r1
   1e13e:	f1 04       	cpc	r15, r1
   1e140:	09 f4       	brne	.+2      	;  0x1e144
   1e142:	ff cf       	rjmp	.-2      	;  0x1e142
   1e144:	a8 95       	wdr
   1e146:	eb be       	out	0x3b, r14	; 59
   1e148:	f6 01       	movw	r30, r12
   1e14a:	c7 91       	elpm	r28, Z+
   1e14c:	8c 2f       	mov	r24, r28
   1e14e:	0e 94 5c f0 	call	0x1e0b8	;  0x1e0b8
   1e152:	8f ef       	ldi	r24, 0xFF	; 255
   1e154:	c8 1a       	sub	r12, r24
   1e156:	d8 0a       	sbc	r13, r24
   1e158:	e8 0a       	sbc	r14, r24
   1e15a:	f8 0a       	sbc	r15, r24
   1e15c:	c1 11       	cpse	r28, r1
   1e15e:	f3 cf       	rjmp	.-26     	;  0x1e146
   1e160:	a8 95       	wdr
   1e162:	0f b6       	in	r0, 0x3f	; 63
   1e164:	f8 94       	cli
   1e166:	a8 95       	wdr
   1e168:	80 91 60 00 	lds	r24, 0x0060
   1e16c:	88 61       	ori	r24, 0x18	; 24
   1e16e:	80 93 60 00 	sts	0x0060, r24
   1e172:	10 92 60 00 	sts	0x0060, r1
   1e176:	0f be       	out	0x3f, r0	; 63
   1e178:	0c 94 00 00 	jmp	0	;  0x0
   1e17c:	cf 91       	pop	r28
   1e17e:	ff 90       	pop	r15
   1e180:	ef 90       	pop	r14
   1e182:	df 90       	pop	r13
   1e184:	cf 90       	pop	r12
   1e186:	08 95       	ret
   1e188:	9f e0       	ldi	r25, 0x0F	; 15
   1e18a:	88 e1       	ldi	r24, 0x18	; 24
   1e18c:	0f b6       	in	r0, 0x3f	; 63
   1e18e:	f8 94       	cli
   1e190:	a8 95       	wdr
   1e192:	80 93 60 00 	sts	0x0060, r24
   1e196:	0f be       	out	0x3f, r0	; 63
   1e198:	90 93 60 00 	sts	0x0060, r25
   1e19c:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1a0:	c8 2e       	mov	r12, r24
   1e1a2:	d1 2c       	mov	r13, r1
   1e1a4:	e1 2c       	mov	r14, r1
   1e1a6:	f1 2c       	mov	r15, r1
   1e1a8:	fc 2c       	mov	r15, r12
   1e1aa:	ee 24       	eor	r14, r14
   1e1ac:	dd 24       	eor	r13, r13
   1e1ae:	cc 24       	eor	r12, r12
   1e1b0:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1b4:	e8 2a       	or	r14, r24
   1e1b6:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1ba:	c8 2f       	mov	r28, r24
   1e1bc:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1c0:	c8 2a       	or	r12, r24
   1e1c2:	dc 2a       	or	r13, r28
   1e1c4:	a8 95       	wdr
   1e1c6:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1ca:	88 2e       	mov	r8, r24
   1e1cc:	91 2c       	mov	r9, r1
   1e1ce:	a1 2c       	mov	r10, r1
   1e1d0:	b1 2c       	mov	r11, r1
   1e1d2:	b8 2c       	mov	r11, r8
   1e1d4:	aa 24       	eor	r10, r10
   1e1d6:	99 24       	eor	r9, r9
   1e1d8:	88 24       	eor	r8, r8
   1e1da:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1de:	a8 2a       	or	r10, r24
   1e1e0:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1e4:	c8 2f       	mov	r28, r24
   1e1e6:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e1ea:	88 2a       	or	r8, r24
   1e1ec:	9c 2a       	or	r9, r28
   1e1ee:	a8 95       	wdr
   1e1f0:	8c 0c       	add	r8, r12
   1e1f2:	9d 1c       	adc	r9, r13
   1e1f4:	ae 1c       	adc	r10, r14
   1e1f6:	bf 1c       	adc	r11, r15
   1e1f8:	c8 14       	cp	r12, r8
   1e1fa:	d9 04       	cpc	r13, r9
   1e1fc:	ea 04       	cpc	r14, r10
   1e1fe:	fb 04       	cpc	r15, r11
   1e200:	68 f4       	brcc	.+26     	;  0x1e21c
   1e202:	eb be       	out	0x3b, r14	; 59
   1e204:	f6 01       	movw	r30, r12
   1e206:	87 91       	elpm	r24, Z+
   1e208:	a8 95       	wdr
   1e20a:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1e20e:	a8 95       	wdr
   1e210:	8f ef       	ldi	r24, 0xFF	; 255
   1e212:	c8 1a       	sub	r12, r24
   1e214:	d8 0a       	sbc	r13, r24
   1e216:	e8 0a       	sbc	r14, r24
   1e218:	f8 0a       	sbc	r15, r24
   1e21a:	ee cf       	rjmp	.-36     	;  0x1e1f8
   1e21c:	ff cf       	rjmp	.-2      	;  0x1e21c
   1e21e:	a0 e0       	ldi	r26, 0x00	; 0
   1e220:	b0 e0       	ldi	r27, 0x00	; 0
   1e222:	e5 e1       	ldi	r30, 0x15	; 21
   1e224:	f1 ef       	ldi	r31, 0xF1	; 241
   1e226:	0c 94 2f f5 	jmp	0x1ea5e	;  0x1ea5e
   1e22a:	8c 01       	movw	r16, r24
   1e22c:	7b 01       	movw	r14, r22
   1e22e:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e232:	c8 2f       	mov	r28, r24
   1e234:	d0 e0       	ldi	r29, 0x00	; 0
   1e236:	dc 2f       	mov	r29, r28
   1e238:	cc 27       	eor	r28, r28
   1e23a:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e23e:	c8 0f       	add	r28, r24
   1e240:	d1 1d       	adc	r29, r1
   1e242:	c1 2c       	mov	r12, r1
   1e244:	d1 2c       	mov	r13, r1
   1e246:	a8 95       	wdr
   1e248:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e24c:	f6 01       	movw	r30, r12
   1e24e:	ee 0d       	add	r30, r14
   1e250:	ff 1d       	adc	r31, r15
   1e252:	e0 0f       	add	r30, r16
   1e254:	f1 1f       	adc	r31, r17
   1e256:	80 83       	st	Z, r24
   1e258:	8f ef       	ldi	r24, 0xFF	; 255
   1e25a:	c8 1a       	sub	r12, r24
   1e25c:	d8 0a       	sbc	r13, r24
   1e25e:	80 e1       	ldi	r24, 0x10	; 16
   1e260:	c8 16       	cp	r12, r24
   1e262:	d1 04       	cpc	r13, r1
   1e264:	81 f7       	brne	.-32     	;  0x1e246
   1e266:	ce 01       	movw	r24, r28
   1e268:	cd b7       	in	r28, 0x3d	; 61
   1e26a:	de b7       	in	r29, 0x3e	; 62
   1e26c:	e8 e0       	ldi	r30, 0x08	; 8
   1e26e:	0c 94 4b f5 	jmp	0x1ea96	;  0x1ea96
   1e272:	8f 92       	push	r8
   1e274:	9f 92       	push	r9
   1e276:	af 92       	push	r10
   1e278:	bf 92       	push	r11
   1e27a:	ef 92       	push	r14
   1e27c:	ff 92       	push	r15
   1e27e:	07 b6       	in	r0, 0x37	; 55
   1e280:	00 fc       	sbrc	r0, 0
   1e282:	fd cf       	rjmp	.-6      	;  0x1e27e
   1e284:	f9 99       	sbic	0x1f, 1	; 31
   1e286:	fe cf       	rjmp	.-4      	;  0x1e284
   1e288:	23 e0       	ldi	r18, 0x03	; 3
   1e28a:	fb 01       	movw	r30, r22
   1e28c:	80 93 5b 00 	sts	0x005B, r24
   1e290:	20 93 57 00 	sts	0x0057, r18
   1e294:	e8 95       	spm
   1e296:	4b 01       	movw	r8, r22
   1e298:	5c 01       	movw	r10, r24
   1e29a:	20 e0       	ldi	r18, 0x00	; 0
   1e29c:	30 e0       	ldi	r19, 0x00	; 0
   1e29e:	a1 e0       	ldi	r26, 0x01	; 1
   1e2a0:	fa 01       	movw	r30, r20
   1e2a2:	e2 0f       	add	r30, r18
   1e2a4:	f3 1f       	adc	r31, r19
   1e2a6:	b0 81       	ld	r27, Z
   1e2a8:	e1 81       	ldd	r30, Z+1	; 0x01
   1e2aa:	f0 e0       	ldi	r31, 0x00	; 0
   1e2ac:	fe 2f       	mov	r31, r30
   1e2ae:	ee 27       	eor	r30, r30
   1e2b0:	7f 01       	movw	r14, r30
   1e2b2:	eb 0e       	add	r14, r27
   1e2b4:	f1 1c       	adc	r15, r1
   1e2b6:	07 b6       	in	r0, 0x37	; 55
   1e2b8:	00 fc       	sbrc	r0, 0
   1e2ba:	fd cf       	rjmp	.-6      	;  0x1e2b6
   1e2bc:	f9 99       	sbic	0x1f, 1	; 31
   1e2be:	fe cf       	rjmp	.-4      	;  0x1e2bc
   1e2c0:	07 01       	movw	r0, r14
   1e2c2:	f4 01       	movw	r30, r8
   1e2c4:	a0 92 5b 00 	sts	0x005B, r10
   1e2c8:	a0 93 57 00 	sts	0x0057, r26
   1e2cc:	e8 95       	spm
   1e2ce:	11 24       	eor	r1, r1
   1e2d0:	2e 5f       	subi	r18, 0xFE	; 254
   1e2d2:	3f 4f       	sbci	r19, 0xFF	; 255
   1e2d4:	e2 e0       	ldi	r30, 0x02	; 2
   1e2d6:	8e 0e       	add	r8, r30
   1e2d8:	91 1c       	adc	r9, r1
   1e2da:	a1 1c       	adc	r10, r1
   1e2dc:	b1 1c       	adc	r11, r1
   1e2de:	21 15       	cp	r18, r1
   1e2e0:	e1 e0       	ldi	r30, 0x01	; 1
   1e2e2:	3e 07       	cpc	r19, r30
   1e2e4:	e9 f6       	brne	.-70     	;  0x1e2a0
   1e2e6:	07 b6       	in	r0, 0x37	; 55
   1e2e8:	00 fc       	sbrc	r0, 0
   1e2ea:	fd cf       	rjmp	.-6      	;  0x1e2e6
   1e2ec:	f9 99       	sbic	0x1f, 1	; 31
   1e2ee:	fe cf       	rjmp	.-4      	;  0x1e2ec
   1e2f0:	25 e0       	ldi	r18, 0x05	; 5
   1e2f2:	fb 01       	movw	r30, r22
   1e2f4:	80 93 5b 00 	sts	0x005B, r24
   1e2f8:	20 93 57 00 	sts	0x0057, r18
   1e2fc:	e8 95       	spm
   1e2fe:	07 b6       	in	r0, 0x37	; 55
   1e300:	00 fc       	sbrc	r0, 0
   1e302:	fd cf       	rjmp	.-6      	;  0x1e2fe
   1e304:	f9 99       	sbic	0x1f, 1	; 31
   1e306:	fe cf       	rjmp	.-4      	;  0x1e304
   1e308:	81 e1       	ldi	r24, 0x11	; 17
   1e30a:	80 93 57 00 	sts	0x0057, r24
   1e30e:	e8 95       	spm
   1e310:	ff 90       	pop	r15
   1e312:	ef 90       	pop	r14
   1e314:	bf 90       	pop	r11
   1e316:	af 90       	pop	r10
   1e318:	9f 90       	pop	r9
   1e31a:	8f 90       	pop	r8
   1e31c:	08 95       	ret
   1e31e:	a0 e0       	ldi	r26, 0x00	; 0
   1e320:	b1 e0       	ldi	r27, 0x01	; 1
   1e322:	e5 e9       	ldi	r30, 0x95	; 149
   1e324:	f1 ef       	ldi	r31, 0xF1	; 241
   1e326:	0c 94 31 f5 	jmp	0x1ea62	;  0x1ea62
   1e32a:	9f e0       	ldi	r25, 0x0F	; 15
   1e32c:	88 e1       	ldi	r24, 0x18	; 24
   1e32e:	0f b6       	in	r0, 0x3f	; 63
   1e330:	f8 94       	cli
   1e332:	a8 95       	wdr
   1e334:	80 93 60 00 	sts	0x0060, r24
   1e338:	0f be       	out	0x3f, r0	; 63
   1e33a:	90 93 60 00 	sts	0x0060, r25
   1e33e:	0e 94 28 f0 	call	0x1e050	;  0x1e050
   1e342:	81 11       	cpse	r24, r1
   1e344:	01 c0       	rjmp	.+2      	;  0x1e348
   1e346:	fb cf       	rjmp	.-10     	;  0x1e33e
   1e348:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e34c:	08 2f       	mov	r16, r24
   1e34e:	10 e0       	ldi	r17, 0x00	; 0
   1e350:	10 2f       	mov	r17, r16
   1e352:	00 27       	eor	r16, r16
   1e354:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e358:	08 2b       	or	r16, r24
   1e35a:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e35e:	e8 2e       	mov	r14, r24
   1e360:	f1 2c       	mov	r15, r1
   1e362:	fe 2c       	mov	r15, r14
   1e364:	ee 24       	eor	r14, r14
   1e366:	0e 94 2e f0 	call	0x1e05c	;  0x1e05c
   1e36a:	e8 2a       	or	r14, r24
   1e36c:	01 15       	cp	r16, r1
   1e36e:	11 05       	cpc	r17, r1
   1e370:	89 f0       	breq	.+34     	;  0x1e394
   1e372:	80 e0       	ldi	r24, 0x00	; 0
   1e374:	90 e0       	ldi	r25, 0x00	; 0
   1e376:	0e 94 64 f5 	call	0x1eac8	;  0x1eac8
   1e37a:	08 17       	cp	r16, r24
   1e37c:	19 07       	cpc	r17, r25
   1e37e:	20 f4       	brcc	.+8      	;  0x1e388
   1e380:	81 e0       	ldi	r24, 0x01	; 1
   1e382:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1e386:	ff cf       	rjmp	.-2      	;  0x1e386
   1e388:	a8 95       	wdr
   1e38a:	b8 01       	movw	r22, r16
   1e38c:	80 e0       	ldi	r24, 0x00	; 0
   1e38e:	90 e0       	ldi	r25, 0x00	; 0
   1e390:	0e 94 6a f5 	call	0x1ead4	;  0x1ead4
   1e394:	a8 95       	wdr
   1e396:	b7 01       	movw	r22, r14
   1e398:	82 e0       	ldi	r24, 0x02	; 2
   1e39a:	90 e0       	ldi	r25, 0x00	; 0
   1e39c:	0e 94 6a f5 	call	0x1ead4	;  0x1ead4
   1e3a0:	a8 95       	wdr
   1e3a2:	80 e0       	ldi	r24, 0x00	; 0
   1e3a4:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1e3a8:	00 e0       	ldi	r16, 0x00	; 0
   1e3aa:	10 e0       	ldi	r17, 0x00	; 0
   1e3ac:	a8 95       	wdr
   1e3ae:	60 e0       	ldi	r22, 0x00	; 0
   1e3b0:	70 e0       	ldi	r23, 0x00	; 0
   1e3b2:	ce 01       	movw	r24, r28
   1e3b4:	01 96       	adiw	r24, 0x01	; 1
   1e3b6:	0e 94 0f f1 	call	0x1e21e	;  0x1e21e
   1e3ba:	a8 95       	wdr
   1e3bc:	b8 01       	movw	r22, r16
   1e3be:	80 e0       	ldi	r24, 0x00	; 0
   1e3c0:	90 e0       	ldi	r25, 0x00	; 0
   1e3c2:	ae 01       	movw	r20, r28
   1e3c4:	4f 5f       	subi	r20, 0xFF	; 255
   1e3c6:	5f 4f       	sbci	r21, 0xFF	; 255
   1e3c8:	0e 94 39 f1 	call	0x1e272	;  0x1e272
   1e3cc:	13 95       	inc	r17
   1e3ce:	80 e5       	ldi	r24, 0x50	; 80
   1e3d0:	0e 94 5c f0 	call	0x1e0b8	;  0x1e0b8
   1e3d4:	81 2f       	mov	r24, r17
   1e3d6:	0e 94 5c f0 	call	0x1e0b8	;  0x1e0b8
   1e3da:	80 e0       	ldi	r24, 0x00	; 0
   1e3dc:	0e 94 5c f0 	call	0x1e0b8	;  0x1e0b8
   1e3e0:	a8 95       	wdr
   1e3e2:	80 e0       	ldi	r24, 0x00	; 0
   1e3e4:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1e3e8:	e1 cf       	rjmp	.-62     	;  0x1e3ac
   1e3ea:	cf 93       	push	r28
   1e3ec:	df 93       	push	r29
   1e3ee:	60 91 b2 01 	lds	r22, 0x01B2
   1e3f2:	70 91 b3 01 	lds	r23, 0x01B3
   1e3f6:	90 e1       	ldi	r25, 0x10	; 16
   1e3f8:	89 9f       	mul	r24, r25
   1e3fa:	e0 01       	movw	r28, r0
   1e3fc:	11 24       	eor	r1, r1
   1e3fe:	40 e0       	ldi	r20, 0x00	; 0
   1e400:	50 e0       	ldi	r21, 0x00	; 0
   1e402:	fa 01       	movw	r30, r20
   1e404:	ec 0f       	add	r30, r28
   1e406:	fd 1f       	adc	r31, r29
   1e408:	ee 5f       	subi	r30, 0xFE	; 254
   1e40a:	fe 4f       	sbci	r31, 0xFE	; 254
   1e40c:	20 e0       	ldi	r18, 0x00	; 0
   1e40e:	30 e0       	ldi	r19, 0x00	; 0
   1e410:	db 01       	movw	r26, r22
   1e412:	a2 0f       	add	r26, r18
   1e414:	b3 1f       	adc	r27, r19
   1e416:	91 91       	ld	r25, Z+
   1e418:	8c 91       	ld	r24, X
   1e41a:	98 27       	eor	r25, r24
   1e41c:	9c 93       	st	X, r25
   1e41e:	2f 5f       	subi	r18, 0xFF	; 255
   1e420:	3f 4f       	sbci	r19, 0xFF	; 255
   1e422:	24 30       	cpi	r18, 0x04	; 4
   1e424:	31 05       	cpc	r19, r1
   1e426:	a1 f7       	brne	.-24     	;  0x1e410
   1e428:	4c 5f       	subi	r20, 0xFC	; 252
   1e42a:	5f 4f       	sbci	r21, 0xFF	; 255
   1e42c:	6c 5f       	subi	r22, 0xFC	; 252
   1e42e:	7f 4f       	sbci	r23, 0xFF	; 255
   1e430:	40 31       	cpi	r20, 0x10	; 16
   1e432:	51 05       	cpc	r21, r1
   1e434:	31 f7       	brne	.-52     	;  0x1e402
   1e436:	df 91       	pop	r29
   1e438:	cf 91       	pop	r28
   1e43a:	08 95       	ret
   1e43c:	e0 91 b2 01 	lds	r30, 0x01B2
   1e440:	f0 91 b3 01 	lds	r31, 0x01B3
   1e444:	81 81       	ldd	r24, Z+1	; 0x01
   1e446:	95 81       	ldd	r25, Z+5	; 0x05
   1e448:	91 83       	std	Z+1, r25	; 0x01
   1e44a:	91 85       	ldd	r25, Z+9	; 0x09
   1e44c:	95 83       	std	Z+5, r25	; 0x05
   1e44e:	95 85       	ldd	r25, Z+13	; 0x0d
   1e450:	91 87       	std	Z+9, r25	; 0x09
   1e452:	85 87       	std	Z+13, r24	; 0x0d
   1e454:	82 81       	ldd	r24, Z+2	; 0x02
   1e456:	92 85       	ldd	r25, Z+10	; 0x0a
   1e458:	92 83       	std	Z+2, r25	; 0x02
   1e45a:	82 87       	std	Z+10, r24	; 0x0a
   1e45c:	86 81       	ldd	r24, Z+6	; 0x06
   1e45e:	96 85       	ldd	r25, Z+14	; 0x0e
   1e460:	96 83       	std	Z+6, r25	; 0x06
   1e462:	86 87       	std	Z+14, r24	; 0x0e
   1e464:	83 81       	ldd	r24, Z+3	; 0x03
   1e466:	97 85       	ldd	r25, Z+15	; 0x0f
   1e468:	93 83       	std	Z+3, r25	; 0x03
   1e46a:	93 85       	ldd	r25, Z+11	; 0x0b
   1e46c:	97 87       	std	Z+15, r25	; 0x0f
   1e46e:	97 81       	ldd	r25, Z+7	; 0x07
   1e470:	93 87       	std	Z+11, r25	; 0x0b
   1e472:	87 83       	std	Z+7, r24	; 0x07
   1e474:	08 95       	ret
   1e476:	98 2f       	mov	r25, r24
   1e478:	99 1f       	adc	r25, r25
   1e47a:	99 27       	eor	r25, r25
   1e47c:	99 1f       	adc	r25, r25
   1e47e:	2b e1       	ldi	r18, 0x1B	; 27
   1e480:	92 9f       	mul	r25, r18
   1e482:	90 2d       	mov	r25, r0
   1e484:	11 24       	eor	r1, r1
   1e486:	88 0f       	add	r24, r24
   1e488:	89 27       	eor	r24, r25
   1e48a:	08 95       	ret
   1e48c:	20 91 b2 01 	lds	r18, 0x01B2
   1e490:	30 91 b3 01 	lds	r19, 0x01B3
   1e494:	94 e0       	ldi	r25, 0x04	; 4
   1e496:	d9 01       	movw	r26, r18
   1e498:	80 e0       	ldi	r24, 0x00	; 0
   1e49a:	ec 91       	ld	r30, X
   1e49c:	f0 e0       	ldi	r31, 0x00	; 0
   1e49e:	ed 54       	subi	r30, 0x4D	; 77
   1e4a0:	fc 4f       	sbci	r31, 0xFC	; 252
   1e4a2:	40 81       	ld	r20, Z
   1e4a4:	4c 93       	st	X, r20
   1e4a6:	8f 5f       	subi	r24, 0xFF	; 255
   1e4a8:	14 96       	adiw	r26, 0x04	; 4
   1e4aa:	84 30       	cpi	r24, 0x04	; 4
   1e4ac:	b1 f7       	brne	.-20     	;  0x1e49a
   1e4ae:	91 50       	subi	r25, 0x01	; 1
   1e4b0:	2f 5f       	subi	r18, 0xFF	; 255
   1e4b2:	3f 4f       	sbci	r19, 0xFF	; 255
   1e4b4:	91 11       	cpse	r25, r1
   1e4b6:	ef cf       	rjmp	.-34     	;  0x1e496
   1e4b8:	08 95       	ret
   1e4ba:	e0 91 b2 01 	lds	r30, 0x01B2
   1e4be:	f0 91 b3 01 	lds	r31, 0x01B3
   1e4c2:	85 85       	ldd	r24, Z+13	; 0x0d
   1e4c4:	91 85       	ldd	r25, Z+9	; 0x09
   1e4c6:	95 87       	std	Z+13, r25	; 0x0d
   1e4c8:	95 81       	ldd	r25, Z+5	; 0x05
   1e4ca:	91 87       	std	Z+9, r25	; 0x09
   1e4cc:	91 81       	ldd	r25, Z+1	; 0x01
   1e4ce:	95 83       	std	Z+5, r25	; 0x05
   1e4d0:	81 83       	std	Z+1, r24	; 0x01
   1e4d2:	82 81       	ldd	r24, Z+2	; 0x02
   1e4d4:	92 85       	ldd	r25, Z+10	; 0x0a
   1e4d6:	92 83       	std	Z+2, r25	; 0x02
   1e4d8:	82 87       	std	Z+10, r24	; 0x0a
   1e4da:	86 81       	ldd	r24, Z+6	; 0x06
   1e4dc:	96 85       	ldd	r25, Z+14	; 0x0e
   1e4de:	96 83       	std	Z+6, r25	; 0x06
   1e4e0:	86 87       	std	Z+14, r24	; 0x0e
   1e4e2:	83 81       	ldd	r24, Z+3	; 0x03
   1e4e4:	97 81       	ldd	r25, Z+7	; 0x07
   1e4e6:	93 83       	std	Z+3, r25	; 0x03
   1e4e8:	93 85       	ldd	r25, Z+11	; 0x0b
   1e4ea:	97 83       	std	Z+7, r25	; 0x07
   1e4ec:	97 85       	ldd	r25, Z+15	; 0x0f
   1e4ee:	93 87       	std	Z+11, r25	; 0x0b
   1e4f0:	87 87       	std	Z+15, r24	; 0x0f
   1e4f2:	08 95       	ret
   1e4f4:	20 91 b2 01 	lds	r18, 0x01B2
   1e4f8:	30 91 b3 01 	lds	r19, 0x01B3
   1e4fc:	94 e0       	ldi	r25, 0x04	; 4
   1e4fe:	d9 01       	movw	r26, r18
   1e500:	80 e0       	ldi	r24, 0x00	; 0
   1e502:	ec 91       	ld	r30, X
   1e504:	f0 e0       	ldi	r31, 0x00	; 0
   1e506:	ec 54       	subi	r30, 0x4C	; 76
   1e508:	fe 4f       	sbci	r31, 0xFE	; 254
   1e50a:	40 81       	ld	r20, Z
   1e50c:	4c 93       	st	X, r20
   1e50e:	8f 5f       	subi	r24, 0xFF	; 255
   1e510:	14 96       	adiw	r26, 0x04	; 4
   1e512:	84 30       	cpi	r24, 0x04	; 4
   1e514:	b1 f7       	brne	.-20     	;  0x1e502
   1e516:	91 50       	subi	r25, 0x01	; 1
   1e518:	2f 5f       	subi	r18, 0xFF	; 255
   1e51a:	3f 4f       	sbci	r19, 0xFF	; 255
   1e51c:	91 11       	cpse	r25, r1
   1e51e:	ef cf       	rjmp	.-34     	;  0x1e4fe
   1e520:	08 95       	ret
   1e522:	a4 e0       	ldi	r26, 0x04	; 4
   1e524:	b0 e0       	ldi	r27, 0x00	; 0
   1e526:	e7 e9       	ldi	r30, 0x97	; 151
   1e528:	f2 ef       	ldi	r31, 0xF2	; 242
   1e52a:	0c 94 2f f5 	jmp	0x1ea5e	;  0x1ea5e
   1e52e:	e0 91 00 01 	lds	r30, 0x0100
   1e532:	f0 91 01 01 	lds	r31, 0x0101
   1e536:	33 96       	adiw	r30, 0x03	; 3
   1e538:	80 e0       	ldi	r24, 0x00	; 0
   1e53a:	90 e0       	ldi	r25, 0x00	; 0
   1e53c:	df 01       	movw	r26, r30
   1e53e:	13 97       	sbiw	r26, 0x03	; 3
   1e540:	2c 91       	ld	r18, X
   1e542:	ac 01       	movw	r20, r24
   1e544:	4e 5f       	subi	r20, 0xFE	; 254
   1e546:	5e 4f       	sbci	r21, 0xFE	; 254
   1e548:	da 01       	movw	r26, r20
   1e54a:	2c 93       	st	X, r18
   1e54c:	9f 01       	movw	r18, r30
   1e54e:	22 50       	subi	r18, 0x02	; 2
   1e550:	31 09       	sbc	r19, r1
   1e552:	d9 01       	movw	r26, r18
   1e554:	2c 91       	ld	r18, X
   1e556:	da 01       	movw	r26, r20
   1e558:	11 96       	adiw	r26, 0x01	; 1
   1e55a:	2c 93       	st	X, r18
   1e55c:	9f 01       	movw	r18, r30
   1e55e:	21 50       	subi	r18, 0x01	; 1
   1e560:	31 09       	sbc	r19, r1
   1e562:	d9 01       	movw	r26, r18
   1e564:	2c 91       	ld	r18, X
   1e566:	da 01       	movw	r26, r20
   1e568:	12 96       	adiw	r26, 0x02	; 2
   1e56a:	2c 93       	st	X, r18
   1e56c:	12 97       	sbiw	r26, 0x02	; 2
   1e56e:	20 81       	ld	r18, Z
   1e570:	13 96       	adiw	r26, 0x03	; 3
   1e572:	2c 93       	st	X, r18
   1e574:	04 96       	adiw	r24, 0x04	; 4
   1e576:	34 96       	adiw	r30, 0x04	; 4
   1e578:	80 31       	cpi	r24, 0x10	; 16
   1e57a:	91 05       	cpc	r25, r1
   1e57c:	f9 f6       	brne	.-66     	;  0x1e53c
   1e57e:	e5 e1       	ldi	r30, 0x15	; 21
   1e580:	f1 e0       	ldi	r31, 0x01	; 1
   1e582:	94 e0       	ldi	r25, 0x04	; 4
   1e584:	c9 2e       	mov	r12, r25
   1e586:	d1 2c       	mov	r13, r1
   1e588:	e1 2c       	mov	r14, r1
   1e58a:	f1 2c       	mov	r15, r1
   1e58c:	ae 01       	movw	r20, r28
   1e58e:	4f 5f       	subi	r20, 0xFF	; 255
   1e590:	5f 4f       	sbci	r21, 0xFF	; 255
   1e592:	20 e0       	ldi	r18, 0x00	; 0
   1e594:	30 e0       	ldi	r19, 0x00	; 0
   1e596:	bf 01       	movw	r22, r30
   1e598:	67 50       	subi	r22, 0x07	; 7
   1e59a:	71 09       	sbc	r23, r1
   1e59c:	8b 01       	movw	r16, r22
   1e59e:	02 0f       	add	r16, r18
   1e5a0:	13 1f       	adc	r17, r19
   1e5a2:	d8 01       	movw	r26, r16
   1e5a4:	1c 91       	ld	r17, X
   1e5a6:	da 01       	movw	r26, r20
   1e5a8:	1d 93       	st	X+, r17
   1e5aa:	ad 01       	movw	r20, r26
   1e5ac:	2f 5f       	subi	r18, 0xFF	; 255
   1e5ae:	3f 4f       	sbci	r19, 0xFF	; 255
   1e5b0:	24 30       	cpi	r18, 0x04	; 4
   1e5b2:	31 05       	cpc	r19, r1
   1e5b4:	99 f7       	brne	.-26     	;  0x1e59c
   1e5b6:	b7 01       	movw	r22, r14
   1e5b8:	a6 01       	movw	r20, r12
   1e5ba:	43 70       	andi	r20, 0x03	; 3
   1e5bc:	55 27       	eor	r21, r21
   1e5be:	66 27       	eor	r22, r22
   1e5c0:	77 27       	eor	r23, r23
   1e5c2:	45 2b       	or	r20, r21
   1e5c4:	46 2b       	or	r20, r22
   1e5c6:	47 2b       	or	r20, r23
   1e5c8:	51 f5       	brne	.+84     	;  0x1e61e
   1e5ca:	29 81       	ldd	r18, Y+1	; 0x01
   1e5cc:	4c 81       	ldd	r20, Y+4	; 0x04
   1e5ce:	6a 81       	ldd	r22, Y+2	; 0x02
   1e5d0:	70 e0       	ldi	r23, 0x00	; 0
   1e5d2:	6c 54       	subi	r22, 0x4C	; 76
   1e5d4:	7e 4f       	sbci	r23, 0xFE	; 254
   1e5d6:	db 01       	movw	r26, r22
   1e5d8:	1c 91       	ld	r17, X
   1e5da:	6b 81       	ldd	r22, Y+3	; 0x03
   1e5dc:	70 e0       	ldi	r23, 0x00	; 0
   1e5de:	6c 54       	subi	r22, 0x4C	; 76
   1e5e0:	7e 4f       	sbci	r23, 0xFE	; 254
   1e5e2:	db 01       	movw	r26, r22
   1e5e4:	3c 91       	ld	r19, X
   1e5e6:	3a 83       	std	Y+2, r19	; 0x02
   1e5e8:	50 e0       	ldi	r21, 0x00	; 0
   1e5ea:	4c 54       	subi	r20, 0x4C	; 76
   1e5ec:	5e 4f       	sbci	r21, 0xFE	; 254
   1e5ee:	da 01       	movw	r26, r20
   1e5f0:	3c 91       	ld	r19, X
   1e5f2:	3b 83       	std	Y+3, r19	; 0x03
   1e5f4:	30 e0       	ldi	r19, 0x00	; 0
   1e5f6:	2c 54       	subi	r18, 0x4C	; 76
   1e5f8:	3e 4f       	sbci	r19, 0xFE	; 254
   1e5fa:	d9 01       	movw	r26, r18
   1e5fc:	2c 91       	ld	r18, X
   1e5fe:	2c 83       	std	Y+4, r18	; 0x04
   1e600:	b7 01       	movw	r22, r14
   1e602:	a6 01       	movw	r20, r12
   1e604:	82 e0       	ldi	r24, 0x02	; 2
   1e606:	76 95       	lsr	r23
   1e608:	67 95       	ror	r22
   1e60a:	57 95       	ror	r21
   1e60c:	47 95       	ror	r20
   1e60e:	8a 95       	dec	r24
   1e610:	d1 f7       	brne	.-12     	;  0x1e606
   1e612:	4c 54       	subi	r20, 0x4C	; 76
   1e614:	5d 4f       	sbci	r21, 0xFD	; 253
   1e616:	da 01       	movw	r26, r20
   1e618:	2c 91       	ld	r18, X
   1e61a:	21 27       	eor	r18, r17
   1e61c:	29 83       	std	Y+1, r18	; 0x01
   1e61e:	af 01       	movw	r20, r30
   1e620:	43 50       	subi	r20, 0x03	; 3
   1e622:	51 09       	sbc	r21, r1
   1e624:	9f 01       	movw	r18, r30
   1e626:	23 51       	subi	r18, 0x13	; 19
   1e628:	31 09       	sbc	r19, r1
   1e62a:	d9 01       	movw	r26, r18
   1e62c:	3c 91       	ld	r19, X
   1e62e:	29 81       	ldd	r18, Y+1	; 0x01
   1e630:	23 27       	eor	r18, r19
   1e632:	da 01       	movw	r26, r20
   1e634:	2c 93       	st	X, r18
   1e636:	4f 5f       	subi	r20, 0xFF	; 255
   1e638:	5f 4f       	sbci	r21, 0xFF	; 255
   1e63a:	9f 01       	movw	r18, r30
   1e63c:	22 51       	subi	r18, 0x12	; 18
   1e63e:	31 09       	sbc	r19, r1
   1e640:	d9 01       	movw	r26, r18
   1e642:	3c 91       	ld	r19, X
   1e644:	2a 81       	ldd	r18, Y+2	; 0x02
   1e646:	23 27       	eor	r18, r19
   1e648:	da 01       	movw	r26, r20
   1e64a:	2c 93       	st	X, r18
   1e64c:	4f 5f       	subi	r20, 0xFF	; 255
   1e64e:	5f 4f       	sbci	r21, 0xFF	; 255
   1e650:	9f 01       	movw	r18, r30
   1e652:	21 51       	subi	r18, 0x11	; 17
   1e654:	31 09       	sbc	r19, r1
   1e656:	d9 01       	movw	r26, r18
   1e658:	3c 91       	ld	r19, X
   1e65a:	2b 81       	ldd	r18, Y+3	; 0x03
   1e65c:	23 27       	eor	r18, r19
   1e65e:	da 01       	movw	r26, r20
   1e660:	2c 93       	st	X, r18
   1e662:	9f 01       	movw	r18, r30
   1e664:	20 51       	subi	r18, 0x10	; 16
   1e666:	31 09       	sbc	r19, r1
   1e668:	d9 01       	movw	r26, r18
   1e66a:	3c 91       	ld	r19, X
   1e66c:	2c 81       	ldd	r18, Y+4	; 0x04
   1e66e:	23 27       	eor	r18, r19
   1e670:	20 83       	st	Z, r18
   1e672:	bf ef       	ldi	r27, 0xFF	; 255
   1e674:	cb 1a       	sub	r12, r27
   1e676:	db 0a       	sbc	r13, r27
   1e678:	eb 0a       	sbc	r14, r27
   1e67a:	fb 0a       	sbc	r15, r27
   1e67c:	34 96       	adiw	r30, 0x04	; 4
   1e67e:	8c e2       	ldi	r24, 0x2C	; 44
   1e680:	c8 16       	cp	r12, r24
   1e682:	d1 04       	cpc	r13, r1
   1e684:	e1 04       	cpc	r14, r1
   1e686:	f1 04       	cpc	r15, r1
   1e688:	09 f0       	breq	.+2      	;  0x1e68c
   1e68a:	80 cf       	rjmp	.-256    	;  0x1e58c
   1e68c:	24 96       	adiw	r28, 0x04	; 4
   1e68e:	e8 e0       	ldi	r30, 0x08	; 8
   1e690:	0c 94 4b f5 	jmp	0x1ea96	;  0x1ea96
   1e694:	a6 e0       	ldi	r26, 0x06	; 6
   1e696:	b0 e0       	ldi	r27, 0x00	; 0
   1e698:	e0 e5       	ldi	r30, 0x50	; 80
   1e69a:	f3 ef       	ldi	r31, 0xF3	; 243
   1e69c:	0c 94 25 f5 	jmp	0x1ea4a	;  0x1ea4a
   1e6a0:	5b 01       	movw	r10, r22
   1e6a2:	5e 83       	std	Y+6, r21	; 0x06
   1e6a4:	4d 83       	std	Y+5, r20	; 0x05
   1e6a6:	9c 01       	movw	r18, r24
   1e6a8:	20 5f       	subi	r18, 0xF0	; 240
   1e6aa:	3f 4f       	sbci	r19, 0xFF	; 255
   1e6ac:	fa 01       	movw	r30, r20
   1e6ae:	dc 01       	movw	r26, r24
   1e6b0:	4d 91       	ld	r20, X+
   1e6b2:	cd 01       	movw	r24, r26
   1e6b4:	41 93       	st	Z+, r20
   1e6b6:	a2 17       	cp	r26, r18
   1e6b8:	b3 07       	cpc	r27, r19
   1e6ba:	c9 f7       	brne	.-14     	;  0x1e6ae
   1e6bc:	ed 81       	ldd	r30, Y+5	; 0x05
   1e6be:	fe 81       	ldd	r31, Y+6	; 0x06
   1e6c0:	f0 93 b3 01 	sts	0x01B3, r31
   1e6c4:	e0 93 b2 01 	sts	0x01B2, r30
   1e6c8:	84 eb       	ldi	r24, 0xB4	; 180
   1e6ca:	c8 2e       	mov	r12, r24
   1e6cc:	81 e0       	ldi	r24, 0x01	; 1
   1e6ce:	d8 2e       	mov	r13, r24
   1e6d0:	93 eb       	ldi	r25, 0xB3	; 179
   1e6d2:	e9 2e       	mov	r14, r25
   1e6d4:	93 e0       	ldi	r25, 0x03	; 3
   1e6d6:	f9 2e       	mov	r15, r25
   1e6d8:	00 e0       	ldi	r16, 0x00	; 0
   1e6da:	10 e0       	ldi	r17, 0x00	; 0
   1e6dc:	c8 01       	movw	r24, r16
   1e6de:	8d 5f       	subi	r24, 0xFD	; 253
   1e6e0:	9d 4f       	sbci	r25, 0xFD	; 253
   1e6e2:	0e 94 5c f5 	call	0x1eab8	;  0x1eab8
   1e6e6:	d6 01       	movw	r26, r12
   1e6e8:	8d 93       	st	X+, r24
   1e6ea:	6d 01       	movw	r12, r26
   1e6ec:	c8 01       	movw	r24, r16
   1e6ee:	8d 5f       	subi	r24, 0xFD	; 253
   1e6f0:	9e 4f       	sbci	r25, 0xFE	; 254
   1e6f2:	0e 94 5c f5 	call	0x1eab8	;  0x1eab8
   1e6f6:	f7 01       	movw	r30, r14
   1e6f8:	81 93       	st	Z+, r24
   1e6fa:	7f 01       	movw	r14, r30
   1e6fc:	0f 3f       	cpi	r16, 0xFF	; 255
   1e6fe:	11 05       	cpc	r17, r1
   1e700:	49 f0       	breq	.+18     	;  0x1e714
   1e702:	c8 01       	movw	r24, r16
   1e704:	8c 5f       	subi	r24, 0xFC	; 252
   1e706:	9f 4f       	sbci	r25, 0xFF	; 255
   1e708:	0e 94 5c f5 	call	0x1eab8	;  0x1eab8
   1e70c:	f8 01       	movw	r30, r16
   1e70e:	ec 54       	subi	r30, 0x4C	; 76
   1e710:	fd 4f       	sbci	r31, 0xFD	; 253
   1e712:	80 83       	st	Z, r24
   1e714:	0f 5f       	subi	r16, 0xFF	; 255
   1e716:	1f 4f       	sbci	r17, 0xFF	; 255
   1e718:	01 15       	cp	r16, r1
   1e71a:	f1 e0       	ldi	r31, 0x01	; 1
   1e71c:	1f 07       	cpc	r17, r31
   1e71e:	f1 f6       	brne	.-68     	;  0x1e6dc
   1e720:	b0 92 01 01 	sts	0x0101, r11
   1e724:	a0 92 00 01 	sts	0x0100, r10
   1e728:	0e 94 91 f2 	call	0x1e522	;  0x1e522
   1e72c:	80 e0       	ldi	r24, 0x00	; 0
   1e72e:	0e 94 f5 f1 	call	0x1e3ea	;  0x1e3ea
   1e732:	91 e0       	ldi	r25, 0x01	; 1
   1e734:	99 83       	std	Y+1, r25	; 0x01
   1e736:	ad 81       	ldd	r26, Y+5	; 0x05
   1e738:	be 81       	ldd	r27, Y+6	; 0x06
   1e73a:	11 96       	adiw	r26, 0x01	; 1
   1e73c:	bb 83       	std	Y+3, r27	; 0x03
   1e73e:	aa 83       	std	Y+2, r26	; 0x02
   1e740:	6d 80       	ldd	r6, Y+5	; 0x05
   1e742:	7e 80       	ldd	r7, Y+6	; 0x06
   1e744:	b2 e0       	ldi	r27, 0x02	; 2
   1e746:	6b 0e       	add	r6, r27
   1e748:	71 1c       	adc	r7, r1
   1e74a:	ad 80       	ldd	r10, Y+5	; 0x05
   1e74c:	be 80       	ldd	r11, Y+6	; 0x06
   1e74e:	e3 e0       	ldi	r30, 0x03	; 3
   1e750:	ae 0e       	add	r10, r30
   1e752:	b1 1c       	adc	r11, r1
   1e754:	8d 80       	ldd	r8, Y+5	; 0x05
   1e756:	9e 80       	ldd	r9, Y+6	; 0x06
   1e758:	f0 e1       	ldi	r31, 0x10	; 16
   1e75a:	8f 0e       	add	r8, r31
   1e75c:	91 1c       	adc	r9, r1
   1e75e:	0e 94 7a f2 	call	0x1e4f4	;  0x1e4f4
   1e762:	0e 94 1e f2 	call	0x1e43c	;  0x1e43c
   1e766:	ca 80       	ldd	r12, Y+2	; 0x02
   1e768:	db 80       	ldd	r13, Y+3	; 0x03
   1e76a:	73 01       	movw	r14, r6
   1e76c:	85 01       	movw	r16, r10
   1e76e:	2d 80       	ldd	r2, Y+5	; 0x05
   1e770:	3e 80       	ldd	r3, Y+6	; 0x06
   1e772:	d1 01       	movw	r26, r2
   1e774:	4c 90       	ld	r4, X
   1e776:	f6 01       	movw	r30, r12
   1e778:	80 81       	ld	r24, Z
   1e77a:	84 25       	eor	r24, r4
   1e77c:	d8 01       	movw	r26, r16
   1e77e:	5c 90       	ld	r5, X
   1e780:	f7 01       	movw	r30, r14
   1e782:	90 81       	ld	r25, Z
   1e784:	59 26       	eor	r5, r25
   1e786:	58 26       	eor	r5, r24
   1e788:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e78c:	84 25       	eor	r24, r4
   1e78e:	85 25       	eor	r24, r5
   1e790:	d1 01       	movw	r26, r2
   1e792:	8c 93       	st	X, r24
   1e794:	f6 01       	movw	r30, r12
   1e796:	90 81       	ld	r25, Z
   1e798:	d7 01       	movw	r26, r14
   1e79a:	8c 91       	ld	r24, X
   1e79c:	89 27       	eor	r24, r25
   1e79e:	9c 83       	std	Y+4, r25	; 0x04
   1e7a0:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e7a4:	9c 81       	ldd	r25, Y+4	; 0x04
   1e7a6:	89 27       	eor	r24, r25
   1e7a8:	85 25       	eor	r24, r5
   1e7aa:	f6 01       	movw	r30, r12
   1e7ac:	80 83       	st	Z, r24
   1e7ae:	d7 01       	movw	r26, r14
   1e7b0:	9c 91       	ld	r25, X
   1e7b2:	f8 01       	movw	r30, r16
   1e7b4:	80 81       	ld	r24, Z
   1e7b6:	89 27       	eor	r24, r25
   1e7b8:	9c 83       	std	Y+4, r25	; 0x04
   1e7ba:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e7be:	9c 81       	ldd	r25, Y+4	; 0x04
   1e7c0:	89 27       	eor	r24, r25
   1e7c2:	98 2f       	mov	r25, r24
   1e7c4:	95 25       	eor	r25, r5
   1e7c6:	d7 01       	movw	r26, r14
   1e7c8:	9c 93       	st	X, r25
   1e7ca:	f8 01       	movw	r30, r16
   1e7cc:	90 81       	ld	r25, Z
   1e7ce:	89 2f       	mov	r24, r25
   1e7d0:	84 25       	eor	r24, r4
   1e7d2:	9c 83       	std	Y+4, r25	; 0x04
   1e7d4:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e7d8:	9c 81       	ldd	r25, Y+4	; 0x04
   1e7da:	89 27       	eor	r24, r25
   1e7dc:	58 26       	eor	r5, r24
   1e7de:	d8 01       	movw	r26, r16
   1e7e0:	5c 92       	st	X, r5
   1e7e2:	b4 e0       	ldi	r27, 0x04	; 4
   1e7e4:	2b 0e       	add	r2, r27
   1e7e6:	31 1c       	adc	r3, r1
   1e7e8:	e4 e0       	ldi	r30, 0x04	; 4
   1e7ea:	ce 0e       	add	r12, r30
   1e7ec:	d1 1c       	adc	r13, r1
   1e7ee:	f4 e0       	ldi	r31, 0x04	; 4
   1e7f0:	ef 0e       	add	r14, r31
   1e7f2:	f1 1c       	adc	r15, r1
   1e7f4:	0c 5f       	subi	r16, 0xFC	; 252
   1e7f6:	1f 4f       	sbci	r17, 0xFF	; 255
   1e7f8:	28 14       	cp	r2, r8
   1e7fa:	39 04       	cpc	r3, r9
   1e7fc:	09 f0       	breq	.+2      	;  0x1e800
   1e7fe:	b9 cf       	rjmp	.-142    	;  0x1e772
   1e800:	89 81       	ldd	r24, Y+1	; 0x01
   1e802:	0e 94 f5 f1 	call	0x1e3ea	;  0x1e3ea
   1e806:	99 81       	ldd	r25, Y+1	; 0x01
   1e808:	9f 5f       	subi	r25, 0xFF	; 255
   1e80a:	99 83       	std	Y+1, r25	; 0x01
   1e80c:	9a 30       	cpi	r25, 0x0A	; 10
   1e80e:	09 f0       	breq	.+2      	;  0x1e812
   1e810:	a6 cf       	rjmp	.-180    	;  0x1e75e
   1e812:	0e 94 7a f2 	call	0x1e4f4	;  0x1e4f4
   1e816:	0e 94 1e f2 	call	0x1e43c	;  0x1e43c
   1e81a:	8a e0       	ldi	r24, 0x0A	; 10
   1e81c:	0e 94 f5 f1 	call	0x1e3ea	;  0x1e3ea
   1e820:	26 96       	adiw	r28, 0x06	; 6
   1e822:	e2 e1       	ldi	r30, 0x12	; 18
   1e824:	0c 94 41 f5 	jmp	0x1ea82	;  0x1ea82
   1e828:	ae e0       	ldi	r26, 0x0E	; 14
   1e82a:	b0 e0       	ldi	r27, 0x00	; 0
   1e82c:	ea e1       	ldi	r30, 0x1A	; 26
   1e82e:	f4 ef       	ldi	r31, 0xF4	; 244
   1e830:	0c 94 25 f5 	jmp	0x1ea4a	;  0x1ea4a
   1e834:	6b 01       	movw	r12, r22
   1e836:	5a 01       	movw	r10, r20
   1e838:	9c 01       	movw	r18, r24
   1e83a:	20 5f       	subi	r18, 0xF0	; 240
   1e83c:	3f 4f       	sbci	r19, 0xFF	; 255
   1e83e:	fa 01       	movw	r30, r20
   1e840:	dc 01       	movw	r26, r24
   1e842:	4d 91       	ld	r20, X+
   1e844:	cd 01       	movw	r24, r26
   1e846:	41 93       	st	Z+, r20
   1e848:	a2 17       	cp	r26, r18
   1e84a:	b3 07       	cpc	r27, r19
   1e84c:	c9 f7       	brne	.-14     	;  0x1e840
   1e84e:	b0 92 b3 01 	sts	0x01B3, r11
   1e852:	a0 92 b2 01 	sts	0x01B2, r10
   1e856:	94 eb       	ldi	r25, 0xB4	; 180
   1e858:	e9 2e       	mov	r14, r25
   1e85a:	91 e0       	ldi	r25, 0x01	; 1
   1e85c:	f9 2e       	mov	r15, r25
   1e85e:	03 eb       	ldi	r16, 0xB3	; 179
   1e860:	13 e0       	ldi	r17, 0x03	; 3
   1e862:	81 2c       	mov	r8, r1
   1e864:	91 2c       	mov	r9, r1
   1e866:	c4 01       	movw	r24, r8
   1e868:	8d 5f       	subi	r24, 0xFD	; 253
   1e86a:	9d 4f       	sbci	r25, 0xFD	; 253
   1e86c:	0e 94 5c f5 	call	0x1eab8	;  0x1eab8
   1e870:	f7 01       	movw	r30, r14
   1e872:	81 93       	st	Z+, r24
   1e874:	7f 01       	movw	r14, r30
   1e876:	c4 01       	movw	r24, r8
   1e878:	8d 5f       	subi	r24, 0xFD	; 253
   1e87a:	9e 4f       	sbci	r25, 0xFE	; 254
   1e87c:	0e 94 5c f5 	call	0x1eab8	;  0x1eab8
   1e880:	d8 01       	movw	r26, r16
   1e882:	8d 93       	st	X+, r24
   1e884:	8d 01       	movw	r16, r26
   1e886:	bf ef       	ldi	r27, 0xFF	; 255
   1e888:	8b 16       	cp	r8, r27
   1e88a:	91 04       	cpc	r9, r1
   1e88c:	49 f0       	breq	.+18     	;  0x1e8a0
   1e88e:	c4 01       	movw	r24, r8
   1e890:	8c 5f       	subi	r24, 0xFC	; 252
   1e892:	9f 4f       	sbci	r25, 0xFF	; 255
   1e894:	0e 94 5c f5 	call	0x1eab8	;  0x1eab8
   1e898:	f4 01       	movw	r30, r8
   1e89a:	ec 54       	subi	r30, 0x4C	; 76
   1e89c:	fd 4f       	sbci	r31, 0xFD	; 253
   1e89e:	80 83       	st	Z, r24
   1e8a0:	ef ef       	ldi	r30, 0xFF	; 255
   1e8a2:	8e 1a       	sub	r8, r30
   1e8a4:	9e 0a       	sbc	r9, r30
   1e8a6:	81 14       	cp	r8, r1
   1e8a8:	f1 e0       	ldi	r31, 0x01	; 1
   1e8aa:	9f 06       	cpc	r9, r31
   1e8ac:	e1 f6       	brne	.-72     	;  0x1e866
   1e8ae:	d0 92 01 01 	sts	0x0101, r13
   1e8b2:	c0 92 00 01 	sts	0x0100, r12
   1e8b6:	0e 94 91 f2 	call	0x1e522	;  0x1e522
   1e8ba:	8a e0       	ldi	r24, 0x0A	; 10
   1e8bc:	0e 94 f5 f1 	call	0x1e3ea	;  0x1e3ea
   1e8c0:	89 e0       	ldi	r24, 0x09	; 9
   1e8c2:	28 2e       	mov	r2, r24
   1e8c4:	c5 01       	movw	r24, r10
   1e8c6:	03 96       	adiw	r24, 0x03	; 3
   1e8c8:	9c 83       	std	Y+4, r25	; 0x04
   1e8ca:	8b 83       	std	Y+3, r24	; 0x03
   1e8cc:	d5 01       	movw	r26, r10
   1e8ce:	50 96       	adiw	r26, 0x10	; 16
   1e8d0:	be 83       	std	Y+6, r27	; 0x06
   1e8d2:	ad 83       	std	Y+5, r26	; 0x05
   1e8d4:	0e 94 5d f2 	call	0x1e4ba	;  0x1e4ba
   1e8d8:	0e 94 46 f2 	call	0x1e48c	;  0x1e48c
   1e8dc:	82 2d       	mov	r24, r2
   1e8de:	0e 94 f5 f1 	call	0x1e3ea	;  0x1e3ea
   1e8e2:	cb 80       	ldd	r12, Y+3	; 0x03
   1e8e4:	dc 80       	ldd	r13, Y+4	; 0x04
   1e8e6:	25 01       	movw	r4, r10
   1e8e8:	f2 01       	movw	r30, r4
   1e8ea:	10 81       	ld	r17, Z
   1e8ec:	c6 01       	movw	r24, r12
   1e8ee:	02 97       	sbiw	r24, 0x02	; 2
   1e8f0:	9a 83       	std	Y+2, r25	; 0x02
   1e8f2:	89 83       	std	Y+1, r24	; 0x01
   1e8f4:	dc 01       	movw	r26, r24
   1e8f6:	6c 91       	ld	r22, X
   1e8f8:	f6 01       	movw	r30, r12
   1e8fa:	e2 90       	ld	r14, -Z
   1e8fc:	4f 01       	movw	r8, r30
   1e8fe:	d6 01       	movw	r26, r12
   1e900:	0c 91       	ld	r16, X
   1e902:	81 2f       	mov	r24, r17
   1e904:	6c 87       	std	Y+12, r22	; 0x0c
   1e906:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e90a:	38 2f       	mov	r19, r24
   1e90c:	3b 87       	std	Y+11, r19	; 0x0b
   1e90e:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e912:	f8 2e       	mov	r15, r24
   1e914:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e918:	58 2f       	mov	r21, r24
   1e91a:	6c 85       	ldd	r22, Y+12	; 0x0c
   1e91c:	86 2f       	mov	r24, r22
   1e91e:	5a 87       	std	Y+10, r21	; 0x0a
   1e920:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e924:	8d 87       	std	Y+13, r24	; 0x0d
   1e926:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e92a:	28 2f       	mov	r18, r24
   1e92c:	29 87       	std	Y+9, r18	; 0x09
   1e92e:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e932:	68 2e       	mov	r6, r24
   1e934:	8e 2d       	mov	r24, r14
   1e936:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e93a:	48 2f       	mov	r20, r24
   1e93c:	48 87       	std	Y+8, r20	; 0x08
   1e93e:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e942:	8e 87       	std	Y+14, r24	; 0x0e
   1e944:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e948:	78 2e       	mov	r7, r24
   1e94a:	80 2f       	mov	r24, r16
   1e94c:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e950:	98 2f       	mov	r25, r24
   1e952:	9f 83       	std	Y+7, r25	; 0x07
   1e954:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e958:	38 2e       	mov	r3, r24
   1e95a:	0e 94 3b f2 	call	0x1e476	;  0x1e476
   1e95e:	3b 85       	ldd	r19, Y+11	; 0x0b
   1e960:	7f 2d       	mov	r23, r15
   1e962:	73 27       	eor	r23, r19
   1e964:	5a 85       	ldd	r21, Y+10	; 0x0a
   1e966:	75 27       	eor	r23, r21
   1e968:	bd 85       	ldd	r27, Y+13	; 0x0d
   1e96a:	7b 27       	eor	r23, r27
   1e96c:	76 25       	eor	r23, r6
   1e96e:	ee 85       	ldd	r30, Y+14	; 0x0e
   1e970:	7e 27       	eor	r23, r30
   1e972:	77 25       	eor	r23, r7
   1e974:	78 27       	eor	r23, r24
   1e976:	70 27       	eor	r23, r16
   1e978:	6c 85       	ldd	r22, Y+12	; 0x0c
   1e97a:	76 27       	eor	r23, r22
   1e97c:	7e 25       	eor	r23, r14
   1e97e:	d2 01       	movw	r26, r4
   1e980:	7c 93       	st	X, r23
   1e982:	7d 85       	ldd	r23, Y+13	; 0x0d
   1e984:	75 27       	eor	r23, r21
   1e986:	29 85       	ldd	r18, Y+9	; 0x09
   1e988:	72 27       	eor	r23, r18
   1e98a:	76 25       	eor	r23, r6
   1e98c:	48 85       	ldd	r20, Y+8	; 0x08
   1e98e:	74 27       	eor	r23, r20
   1e990:	77 25       	eor	r23, r7
   1e992:	73 25       	eor	r23, r3
   1e994:	78 27       	eor	r23, r24
   1e996:	71 27       	eor	r23, r17
   1e998:	70 27       	eor	r23, r16
   1e99a:	7e 25       	eor	r23, r14
   1e99c:	e9 81       	ldd	r30, Y+1	; 0x01
   1e99e:	fa 81       	ldd	r31, Y+2	; 0x02
   1e9a0:	70 83       	st	Z, r23
   1e9a2:	16 27       	eor	r17, r22
   1e9a4:	f5 26       	eor	r15, r21
   1e9a6:	f6 24       	eor	r15, r6
   1e9a8:	4f 25       	eor	r20, r15
   1e9aa:	6e 85       	ldd	r22, Y+14	; 0x0e
   1e9ac:	46 27       	eor	r20, r22
   1e9ae:	47 25       	eor	r20, r7
   1e9b0:	9f 81       	ldd	r25, Y+7	; 0x07
   1e9b2:	49 27       	eor	r20, r25
   1e9b4:	48 27       	eor	r20, r24
   1e9b6:	04 27       	eor	r16, r20
   1e9b8:	01 27       	eor	r16, r17
   1e9ba:	d4 01       	movw	r26, r8
   1e9bc:	0c 93       	st	X, r16
   1e9be:	35 27       	eor	r19, r21
   1e9c0:	23 27       	eor	r18, r19
   1e9c2:	62 26       	eor	r6, r18
   1e9c4:	76 24       	eor	r7, r6
   1e9c6:	79 26       	eor	r7, r25
   1e9c8:	37 24       	eor	r3, r7
   1e9ca:	83 25       	eor	r24, r3
   1e9cc:	e8 26       	eor	r14, r24
   1e9ce:	1e 25       	eor	r17, r14
   1e9d0:	f6 01       	movw	r30, r12
   1e9d2:	10 83       	st	Z, r17
   1e9d4:	f4 e0       	ldi	r31, 0x04	; 4
   1e9d6:	4f 0e       	add	r4, r31
   1e9d8:	51 1c       	adc	r5, r1
   1e9da:	64 e0       	ldi	r22, 0x04	; 4
   1e9dc:	c6 0e       	add	r12, r22
   1e9de:	d1 1c       	adc	r13, r1
   1e9e0:	8d 81       	ldd	r24, Y+5	; 0x05
   1e9e2:	9e 81       	ldd	r25, Y+6	; 0x06
   1e9e4:	48 16       	cp	r4, r24
   1e9e6:	59 06       	cpc	r5, r25
   1e9e8:	09 f0       	breq	.+2      	;  0x1e9ec
   1e9ea:	7e cf       	rjmp	.-260    	;  0x1e8e8
   1e9ec:	2a 94       	dec	r2
   1e9ee:	21 10       	cpse	r2, r1
   1e9f0:	71 cf       	rjmp	.-286    	;  0x1e8d4
   1e9f2:	0e 94 5d f2 	call	0x1e4ba	;  0x1e4ba
   1e9f6:	0e 94 46 f2 	call	0x1e48c	;  0x1e48c
   1e9fa:	80 e0       	ldi	r24, 0x00	; 0
   1e9fc:	0e 94 f5 f1 	call	0x1e3ea	;  0x1e3ea
   1ea00:	2e 96       	adiw	r28, 0x0e	; 14
   1ea02:	e2 e1       	ldi	r30, 0x12	; 18
   1ea04:	0c 94 41 f5 	jmp	0x1ea82	;  0x1ea82
   1ea08:	0e 94 10 f0 	call	0x1e020	;  0x1e020
   1ea0c:	0e 94 4b f0 	call	0x1e096	;  0x1e096
   1ea10:	a8 95       	wdr
   1ea12:	84 b1       	in	r24, 0x04	; 4
   1ea14:	83 7f       	andi	r24, 0xF3	; 243
   1ea16:	84 b9       	out	0x04, r24	; 4
   1ea18:	85 b1       	in	r24, 0x05	; 5
   1ea1a:	8c 60       	ori	r24, 0x0C	; 12
   1ea1c:	85 b9       	out	0x05, r24	; 5
   1ea1e:	1a 99       	sbic	0x03, 2	; 3
   1ea20:	05 c0       	rjmp	.+10     	;  0x1ea2c
   1ea22:	85 e5       	ldi	r24, 0x55	; 85
   1ea24:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1ea28:	0e 94 8f f1 	call	0x1e31e	;  0x1e31e
   1ea2c:	1b 99       	sbic	0x03, 3	; 3
   1ea2e:	05 c0       	rjmp	.+10     	;  0x1ea3a
   1ea30:	82 e5       	ldi	r24, 0x52	; 82
   1ea32:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1ea36:	0e 94 c4 f0 	call	0x1e188	;  0x1e188
   1ea3a:	82 e4       	ldi	r24, 0x42	; 66
   1ea3c:	0e 94 21 f0 	call	0x1e042	;  0x1e042
   1ea40:	0e 94 86 f0 	call	0x1e10c	;  0x1e10c
   1ea44:	80 e0       	ldi	r24, 0x00	; 0
   1ea46:	90 e0       	ldi	r25, 0x00	; 0
   1ea48:	08 95       	ret
   1ea4a:	2f 92       	push	r2
   1ea4c:	3f 92       	push	r3
   1ea4e:	4f 92       	push	r4
   1ea50:	5f 92       	push	r5
   1ea52:	6f 92       	push	r6
   1ea54:	7f 92       	push	r7
   1ea56:	8f 92       	push	r8
   1ea58:	9f 92       	push	r9
   1ea5a:	af 92       	push	r10
   1ea5c:	bf 92       	push	r11
   1ea5e:	cf 92       	push	r12
   1ea60:	df 92       	push	r13
   1ea62:	ef 92       	push	r14
   1ea64:	ff 92       	push	r15
   1ea66:	0f 93       	push	r16
   1ea68:	1f 93       	push	r17
   1ea6a:	cf 93       	push	r28
   1ea6c:	df 93       	push	r29
   1ea6e:	cd b7       	in	r28, 0x3d	; 61
   1ea70:	de b7       	in	r29, 0x3e	; 62
   1ea72:	ca 1b       	sub	r28, r26
   1ea74:	db 0b       	sbc	r29, r27
   1ea76:	0f b6       	in	r0, 0x3f	; 63
   1ea78:	f8 94       	cli
   1ea7a:	de bf       	out	0x3e, r29	; 62
   1ea7c:	0f be       	out	0x3f, r0	; 63
   1ea7e:	cd bf       	out	0x3d, r28	; 61
   1ea80:	09 94       	ijmp
   1ea82:	2a 88       	ldd	r2, Y+18	; 0x12
   1ea84:	39 88       	ldd	r3, Y+17	; 0x11
   1ea86:	48 88       	ldd	r4, Y+16	; 0x10
   1ea88:	5f 84       	ldd	r5, Y+15	; 0x0f
   1ea8a:	6e 84       	ldd	r6, Y+14	; 0x0e
   1ea8c:	7d 84       	ldd	r7, Y+13	; 0x0d
   1ea8e:	8c 84       	ldd	r8, Y+12	; 0x0c
   1ea90:	9b 84       	ldd	r9, Y+11	; 0x0b
   1ea92:	aa 84       	ldd	r10, Y+10	; 0x0a
   1ea94:	b9 84       	ldd	r11, Y+9	; 0x09
   1ea96:	c8 84       	ldd	r12, Y+8	; 0x08
   1ea98:	df 80       	ldd	r13, Y+7	; 0x07
   1ea9a:	ee 80       	ldd	r14, Y+6	; 0x06
   1ea9c:	fd 80       	ldd	r15, Y+5	; 0x05
   1ea9e:	0c 81       	ldd	r16, Y+4	; 0x04
   1eaa0:	1b 81       	ldd	r17, Y+3	; 0x03
   1eaa2:	aa 81       	ldd	r26, Y+2	; 0x02
   1eaa4:	b9 81       	ldd	r27, Y+1	; 0x01
   1eaa6:	ce 0f       	add	r28, r30
   1eaa8:	d1 1d       	adc	r29, r1
   1eaaa:	0f b6       	in	r0, 0x3f	; 63
   1eaac:	f8 94       	cli
   1eaae:	de bf       	out	0x3e, r29	; 62
   1eab0:	0f be       	out	0x3f, r0	; 63
   1eab2:	cd bf       	out	0x3d, r28	; 61
   1eab4:	ed 01       	movw	r28, r26
   1eab6:	08 95       	ret
   1eab8:	f9 99       	sbic	0x1f, 1	; 31
   1eaba:	fe cf       	rjmp	.-4      	;  0x1eab8
   1eabc:	92 bd       	out	0x22, r25	; 34
   1eabe:	81 bd       	out	0x21, r24	; 33
   1eac0:	f8 9a       	sbi	0x1f, 0	; 31
   1eac2:	99 27       	eor	r25, r25
   1eac4:	80 b5       	in	r24, 0x20	; 32
   1eac6:	08 95       	ret
   1eac8:	a8 e1       	ldi	r26, 0x18	; 24
   1eaca:	b0 e0       	ldi	r27, 0x00	; 0
   1eacc:	42 e0       	ldi	r20, 0x02	; 2
   1eace:	50 e0       	ldi	r21, 0x00	; 0
   1ead0:	0c 94 72 f5 	jmp	0x1eae4	;  0x1eae4
   1ead4:	01 96       	adiw	r24, 0x01	; 1
   1ead6:	27 2f       	mov	r18, r23
   1ead8:	0e 94 81 f5 	call	0x1eb02	;  0x1eb02
   1eadc:	0c 94 80 f5 	jmp	0x1eb00	;  0x1eb00
   1eae0:	dc 01       	movw	r26, r24
   1eae2:	cb 01       	movw	r24, r22
   1eae4:	fc 01       	movw	r30, r24
   1eae6:	f9 99       	sbic	0x1f, 1	; 31
   1eae8:	fe cf       	rjmp	.-4      	;  0x1eae6
   1eaea:	06 c0       	rjmp	.+12     	;  0x1eaf8
   1eaec:	f2 bd       	out	0x22, r31	; 34
   1eaee:	e1 bd       	out	0x21, r30	; 33
   1eaf0:	f8 9a       	sbi	0x1f, 0	; 31
   1eaf2:	31 96       	adiw	r30, 0x01	; 1
   1eaf4:	00 b4       	in	r0, 0x20	; 32
   1eaf6:	0d 92       	st	X+, r0
   1eaf8:	41 50       	subi	r20, 0x01	; 1
   1eafa:	50 40       	sbci	r21, 0x00	; 0
   1eafc:	b8 f7       	brcc	.-18     	;  0x1eaec
   1eafe:	08 95       	ret
   1eb00:	26 2f       	mov	r18, r22
   1eb02:	f9 99       	sbic	0x1f, 1	; 31
   1eb04:	fe cf       	rjmp	.-4      	;  0x1eb02
   1eb06:	92 bd       	out	0x22, r25	; 34
   1eb08:	81 bd       	out	0x21, r24	; 33
   1eb0a:	f8 9a       	sbi	0x1f, 0	; 31
   1eb0c:	01 97       	sbiw	r24, 0x01	; 1
   1eb0e:	00 b4       	in	r0, 0x20	; 32
   1eb10:	02 16       	cp	r0, r18
   1eb12:	39 f0       	breq	.+14     	;  0x1eb22
   1eb14:	1f ba       	out	0x1f, r1	; 31
   1eb16:	20 bd       	out	0x20, r18	; 32
   1eb18:	0f b6       	in	r0, 0x3f	; 63
   1eb1a:	f8 94       	cli
   1eb1c:	fa 9a       	sbi	0x1f, 2	; 31
   1eb1e:	f9 9a       	sbi	0x1f, 1	; 31
   1eb20:	0f be       	out	0x3f, r0	; 63
   1eb22:	08 95       	ret

Disassembly of section .bss:

00800100 <.bss>:
	...

Disassembly of section .eeprom:

00810000 <.eeprom>:
  810000:	00 00       	nop
  810002:	00 00       	nop
  810004:	8d 01       	movw	r16, r26
  810006:	02 04       	cpc	r0, r2
  810008:	08 10       	cpse	r0, r8
  81000a:	20 40       	sbci	r18, 0x00	; 0
  81000c:	80 1b       	sub	r24, r16
  81000e:	36 6c       	ori	r19, 0xC6	; 198
  810010:	d8 ab       	std	Y+48, r29	; 0x30
  810012:	4d 9a       	sbi	0x09, 5	; 9
  810014:	2f 5e       	subi	r18, 0xEF	; 239
  810016:	bc 63       	ori	r27, 0x3C	; 60
  810018:	c6 97       	sbiw	r24, 0x36	; 54
  81001a:	35 6a       	ori	r19, 0xA5	; 165
  81001c:	d4 b3       	in	r29, 0x14	; 20
  81001e:	7d fa       	.word	0xfa7d	; ????
  810020:	ef c5       	rjmp	.+3038   	;  0x810c00
  810022:	91 39       	cpi	r25, 0x91	; 145
  810024:	72 e4       	ldi	r23, 0x42	; 66
  810026:	d3 bd       	out	0x23, r29	; 35
  810028:	61 c2       	rjmp	.+1218   	;  0x8104ec
  81002a:	9f 25       	eor	r25, r15
  81002c:	4a 94       	dec	r4
  81002e:	33 66       	ori	r19, 0x63	; 99
  810030:	cc 83       	std	Y+4, r28	; 0x04
  810032:	1d 3a       	cpi	r17, 0xAD	; 173
  810034:	74 e8       	ldi	r23, 0x84	; 132
  810036:	cb 8d       	ldd	r28, Y+27	; 0x1b
  810038:	01 02       	muls	r16, r17
  81003a:	04 08       	sbc	r0, r4
  81003c:	10 20       	and	r1, r0
  81003e:	40 80       	ld	r4, Z
  810040:	1b 36       	cpi	r17, 0x6B	; 107
  810042:	6c d8       	rcall	.-3880   	;  0x80f11c
  810044:	ab 4d       	sbci	r26, 0xDB	; 219
  810046:	9a 2f       	mov	r25, r26
  810048:	5e bc       	out	0x2e, r5	; 46
  81004a:	63 c6       	rjmp	.+3270   	;  0x810d12
  81004c:	97 35       	cpi	r25, 0x57	; 87
  81004e:	6a d4       	rcall	.+2260   	;  0x810924
  810050:	b3 7d       	andi	r27, 0xD3	; 211
  810052:	fa ef       	ldi	r31, 0xFA	; 250
  810054:	c5 91       	lpm	r28, Z+
  810056:	39 72       	andi	r19, 0x29	; 41
  810058:	e4 d3       	rcall	.+1992   	;  0x810822
  81005a:	bd 61       	ori	r27, 0x1D	; 29
  81005c:	c2 9f       	mul	r28, r18
  81005e:	25 4a       	sbci	r18, 0xA5	; 165
  810060:	94 33       	cpi	r25, 0x34	; 52
  810062:	66 cc       	rjmp	.-1844   	;  0x80f930
  810064:	83 1d       	adc	r24, r3
  810066:	3a 74       	andi	r19, 0x4A	; 74
  810068:	e8 cb       	rjmp	.-2096   	;  0x80f83a
  81006a:	8d 01       	movw	r16, r26
  81006c:	02 04       	cpc	r0, r2
  81006e:	08 10       	cpse	r0, r8
  810070:	20 40       	sbci	r18, 0x00	; 0
  810072:	80 1b       	sub	r24, r16
  810074:	36 6c       	ori	r19, 0xC6	; 198
  810076:	d8 ab       	std	Y+48, r29	; 0x30
  810078:	4d 9a       	sbi	0x09, 5	; 9
  81007a:	2f 5e       	subi	r18, 0xEF	; 239
  81007c:	bc 63       	ori	r27, 0x3C	; 60
  81007e:	c6 97       	sbiw	r24, 0x36	; 54
  810080:	35 6a       	ori	r19, 0xA5	; 165
  810082:	d4 b3       	in	r29, 0x14	; 20
  810084:	7d fa       	.word	0xfa7d	; ????
  810086:	ef c5       	rjmp	.+3038   	;  0x810c66
  810088:	91 39       	cpi	r25, 0x91	; 145
  81008a:	72 e4       	ldi	r23, 0x42	; 66
  81008c:	d3 bd       	out	0x23, r29	; 35
  81008e:	61 c2       	rjmp	.+1218   	;  0x810552
  810090:	9f 25       	eor	r25, r15
  810092:	4a 94       	dec	r4
  810094:	33 66       	ori	r19, 0x63	; 99
  810096:	cc 83       	std	Y+4, r28	; 0x04
  810098:	1d 3a       	cpi	r17, 0xAD	; 173
  81009a:	74 e8       	ldi	r23, 0x84	; 132
  81009c:	cb 8d       	ldd	r28, Y+27	; 0x1b
  81009e:	01 02       	muls	r16, r17
  8100a0:	04 08       	sbc	r0, r4
  8100a2:	10 20       	and	r1, r0
  8100a4:	40 80       	ld	r4, Z
  8100a6:	1b 36       	cpi	r17, 0x6B	; 107
  8100a8:	6c d8       	rcall	.-3880   	;  0x80f182
  8100aa:	ab 4d       	sbci	r26, 0xDB	; 219
  8100ac:	9a 2f       	mov	r25, r26
  8100ae:	5e bc       	out	0x2e, r5	; 46
  8100b0:	63 c6       	rjmp	.+3270   	;  0x810d78
  8100b2:	97 35       	cpi	r25, 0x57	; 87
  8100b4:	6a d4       	rcall	.+2260   	;  0x81098a
  8100b6:	b3 7d       	andi	r27, 0xD3	; 211
  8100b8:	fa ef       	ldi	r31, 0xFA	; 250
  8100ba:	c5 91       	lpm	r28, Z+
  8100bc:	39 72       	andi	r19, 0x29	; 41
  8100be:	e4 d3       	rcall	.+1992   	;  0x810888
  8100c0:	bd 61       	ori	r27, 0x1D	; 29
  8100c2:	c2 9f       	mul	r28, r18
  8100c4:	25 4a       	sbci	r18, 0xA5	; 165
  8100c6:	94 33       	cpi	r25, 0x34	; 52
  8100c8:	66 cc       	rjmp	.-1844   	;  0x80f996
  8100ca:	83 1d       	adc	r24, r3
  8100cc:	3a 74       	andi	r19, 0x4A	; 74
  8100ce:	e8 cb       	rjmp	.-2096   	;  0x80f8a0
  8100d0:	8d 01       	movw	r16, r26
  8100d2:	02 04       	cpc	r0, r2
  8100d4:	08 10       	cpse	r0, r8
  8100d6:	20 40       	sbci	r18, 0x00	; 0
  8100d8:	80 1b       	sub	r24, r16
  8100da:	36 6c       	ori	r19, 0xC6	; 198
  8100dc:	d8 ab       	std	Y+48, r29	; 0x30
  8100de:	4d 9a       	sbi	0x09, 5	; 9
  8100e0:	2f 5e       	subi	r18, 0xEF	; 239
  8100e2:	bc 63       	ori	r27, 0x3C	; 60
  8100e4:	c6 97       	sbiw	r24, 0x36	; 54
  8100e6:	35 6a       	ori	r19, 0xA5	; 165
  8100e8:	d4 b3       	in	r29, 0x14	; 20
  8100ea:	7d fa       	.word	0xfa7d	; ????
  8100ec:	ef c5       	rjmp	.+3038   	;  0x810ccc
  8100ee:	91 39       	cpi	r25, 0x91	; 145
  8100f0:	72 e4       	ldi	r23, 0x42	; 66
  8100f2:	d3 bd       	out	0x23, r29	; 35
  8100f4:	61 c2       	rjmp	.+1218   	;  0x8105b8
  8100f6:	9f 25       	eor	r25, r15
  8100f8:	4a 94       	dec	r4
  8100fa:	33 66       	ori	r19, 0x63	; 99
  8100fc:	cc 83       	std	Y+4, r28	; 0x04
  8100fe:	1d 3a       	cpi	r17, 0xAD	; 173
  810100:	74 e8       	ldi	r23, 0x84	; 132
  810102:	cb 52       	subi	r28, 0x2B	; 43
  810104:	09 6a       	ori	r16, 0xA9	; 169
  810106:	d5 30       	cpi	r29, 0x05	; 5
  810108:	36 a5       	ldd	r19, Z+46	; 0x2e
  81010a:	38 bf       	out	0x38, r19	; 56
  81010c:	40 a3       	std	Z+32, r20	; 0x20
  81010e:	9e 81       	ldd	r25, Y+6	; 0x06
  810110:	f3 d7       	rcall	.+4070   	;  0x8110f8
  810112:	fb 7c       	andi	r31, 0xCB	; 203
  810114:	e3 39       	cpi	r30, 0x93	; 147
  810116:	82 9b       	sbis	0x10, 2	; 16
  810118:	2f ff       	.word	0xff2f	; ????
  81011a:	87 34       	cpi	r24, 0x47	; 71
  81011c:	8e 43       	sbci	r24, 0x3E	; 62
  81011e:	44 c4       	rjmp	.+2184   	;  0x8109a8
  810120:	de e9       	ldi	r29, 0x9E	; 158
  810122:	cb 54       	subi	r28, 0x4B	; 75
  810124:	7b 94       	des	7
  810126:	32 a6       	std	Z+42, r3	; 0x2a
  810128:	c2 23       	and	r28, r18
  81012a:	3d ee       	ldi	r19, 0xED	; 237
  81012c:	4c 95 0b 42 	jmp	0x508416	;  0x508416
  810130:	fa c3       	rjmp	.+2036   	;  0x810926
  810132:	4e 08       	sbc	r4, r14
  810134:	2e a1       	ldd	r18, Y+38	; 0x26
  810136:	66 28       	or	r6, r6
  810138:	d9 24       	eor	r13, r9
  81013a:	b2 76       	andi	r27, 0x62	; 98
  81013c:	5b a2       	std	Y+35, r5	; 0x23
  81013e:	49 6d       	ori	r20, 0xD9	; 217
  810140:	8b d1       	rcall	.+790    	;  0x810458
  810142:	25 72       	andi	r18, 0x25	; 37
  810144:	f8 f6       	brcc	.-66     	;  0x810104
  810146:	64 86       	std	Z+12, r6	; 0x0c
  810148:	68 98       	cbi	0x0d, 0	; 13
  81014a:	16 d4       	rcall	.+2092   	;  0x810978
  81014c:	a4 5c       	subi	r26, 0xC4	; 196
  81014e:	cc 5d       	subi	r28, 0xDC	; 220
  810150:	65 b6       	in	r6, 0x35	; 53
  810152:	92 6c       	ori	r25, 0xC2	; 194
  810154:	70 48       	sbci	r23, 0x80	; 128
  810156:	50 fd       	sbrc	r21, 0
  810158:	ed b9       	out	0x0d, r30	; 13
  81015a:	da 5e       	subi	r29, 0xEA	; 234
  81015c:	15 46       	sbci	r17, 0x65	; 101
  81015e:	57 a7       	std	Z+47, r21	; 0x2f
  810160:	8d 9d       	mul	r24, r13
  810162:	84 90       	lpm	r8, Z
  810164:	d8 ab       	std	Y+48, r29	; 0x30
  810166:	00 8c       	ldd	r0, Z+24	; 0x18
  810168:	bc d3       	rcall	.+1912   	;  0x8108e2
  81016a:	0a f7       	brpl	.-62     	;  0x81012e
  81016c:	e4 58       	subi	r30, 0x84	; 132
  81016e:	05 b8       	out	0x05, r0	; 5
  810170:	b3 45       	sbci	r27, 0x53	; 83
  810172:	06 d0       	rcall	.+12     	;  0x810180
  810174:	2c 1e       	adc	r2, r28
  810176:	8f ca       	rjmp	.-2786   	;  0x80f696
  810178:	3f 0f       	add	r19, r31
  81017a:	02 c1       	rjmp	.+516    	;  0x810380
  81017c:	af bd       	out	0x2f, r26	; 47
  81017e:	03 01       	movw	r0, r6
  810180:	13 8a       	std	Z+19, r1	; 0x13
  810182:	6b 3a       	cpi	r22, 0xAB	; 171
  810184:	91 11       	cpse	r25, r1
  810186:	41 4f       	sbci	r20, 0xF1	; 241
  810188:	67 dc       	rcall	.-1842   	;  0x80fa58
  81018a:	ea 97       	sbiw	r28, 0x3a	; 58
  81018c:	f2 cf       	rjmp	.-28     	;  0x810172
  81018e:	ce f0       	brts	.+50     	;  0x8101c2
  810190:	b4 e6       	ldi	r27, 0x64	; 100
  810192:	73 96       	adiw	r30, 0x13	; 19
  810194:	ac 74       	andi	r26, 0x4C	; 76
  810196:	22 e7       	ldi	r18, 0x72	; 114
  810198:	ad 35       	cpi	r26, 0x5D	; 93
  81019a:	85 e2       	ldi	r24, 0x25	; 37
  81019c:	f9 37       	cpi	r31, 0x79	; 121
  81019e:	e8 1c       	adc	r14, r8
  8101a0:	75 df       	rcall	.-278    	;  0x81008c
  8101a2:	6e 47       	sbci	r22, 0x7E	; 126
  8101a4:	f1 1a       	sub	r15, r17
  8101a6:	71 1d       	adc	r23, r1
  8101a8:	29 c5       	rjmp	.+2642   	;  0x810bfc
  8101aa:	89 6f       	ori	r24, 0xF9	; 249
  8101ac:	b7 62       	ori	r27, 0x27	; 39
  8101ae:	0e aa       	std	Y+54, r0	; 0x36
  8101b0:	18 be       	out	0x38, r1	; 56
  8101b2:	1b fc       	.word	0xfc1b	; ????
  8101b4:	56 3e       	cpi	r21, 0xE6	; 230
  8101b6:	4b c6       	rjmp	.+3222   	;  0x810e4e
  8101b8:	d2 79       	andi	r29, 0x92	; 146
  8101ba:	20 9a       	sbi	0x04, 0	; 4
  8101bc:	db c0       	rjmp	.+438    	;  0x810374
  8101be:	fe 78       	andi	r31, 0x8E	; 142
  8101c0:	cd 5a       	subi	r28, 0xAD	; 173
  8101c2:	f4 1f       	adc	r31, r20
  8101c4:	dd a8       	ldd	r13, Y+53	; 0x35
  8101c6:	33 88       	ldd	r3, Z+19	; 0x13
  8101c8:	07 c7       	rjmp	.+3598   	;  0x810fd8
  8101ca:	31 b1       	in	r19, 0x01	; 1
  8101cc:	12 10       	cpse	r1, r2
  8101ce:	59 27       	eor	r21, r25
  8101d0:	80 ec       	ldi	r24, 0xC0	; 192
  8101d2:	5f 60       	ori	r21, 0x0F	; 15
  8101d4:	51 7f       	andi	r21, 0xF1	; 241
  8101d6:	a9 19       	sub	r26, r9
  8101d8:	b5 4a       	sbci	r27, 0xA5	; 165
  8101da:	0d 2d       	mov	r16, r13
  8101dc:	e5 7a       	andi	r30, 0xA5	; 165
  8101de:	9f 93       	push	r25
  8101e0:	c9 9c       	mul	r12, r9
  8101e2:	ef a0       	ldd	r14, Y+39	; 0x27
  8101e4:	e0 3b       	cpi	r30, 0xB0	; 176
  8101e6:	4d ae       	std	Y+61, r4	; 0x3d
  8101e8:	2a f5       	brpl	.+74     	;  0x810234
  8101ea:	b0 c8       	rjmp	.-3744   	;  0x80f34c
  8101ec:	eb bb       	out	0x1b, r30	; 27
  8101ee:	3c 83       	std	Y+4, r19	; 0x04
  8101f0:	53 99       	sbic	0x0a, 3	; 10
  8101f2:	61 17       	cp	r22, r17
  8101f4:	2b 04       	cpc	r2, r11
  8101f6:	7e ba       	out	0x1e, r7	; 30
  8101f8:	77 d6       	rcall	.+3310   	;  0x810ee8
  8101fa:	26 e1       	ldi	r18, 0x16	; 22
  8101fc:	69 14       	cp	r6, r9
  8101fe:	63 55       	subi	r22, 0x53	; 83
  810200:	21 0c       	add	r2, r1
  810202:	7d 63       	ori	r23, 0x3D	; 61
  810204:	7c 77       	andi	r23, 0x7C	; 124
  810206:	7b f2       	brvs	.-98     	;  0x8101a6
  810208:	6b 6f       	ori	r22, 0xFB	; 251
  81020a:	c5 30       	cpi	r28, 0x05	; 5
  81020c:	01 67       	ori	r16, 0x71	; 113
  81020e:	2b fe       	.word	0xfe2b	; ????
  810210:	d7 ab       	std	Z+55, r29	; 0x37
  810212:	76 ca       	rjmp	.-2836   	;  0x80f700
  810214:	82 c9       	rjmp	.-3324   	;  0x80f51a
  810216:	7d fa       	.word	0xfa7d	; ????
  810218:	59 47       	sbci	r21, 0x79	; 121
  81021a:	f0 ad       	ldd	r31, Z+56	; 0x38
  81021c:	d4 a2       	std	Z+36, r13	; 0x24
  81021e:	af 9c       	mul	r10, r15
  810220:	a4 72       	andi	r26, 0x24	; 36
  810222:	c0 b7       	in	r28, 0x30	; 48
  810224:	fd 93       	st	X+, r31
  810226:	26 36       	cpi	r18, 0x66	; 102
  810228:	3f f7       	brid	.-50     	;  0x8101f8
  81022a:	cc 34       	cpi	r28, 0x4C	; 76
  81022c:	a5 e5       	ldi	r26, 0x55	; 85
  81022e:	f1 71       	andi	r31, 0x11	; 17
  810230:	d8 31       	cpi	r29, 0x18	; 24
  810232:	15 04       	cpc	r1, r5
  810234:	c7 23       	and	r28, r23
  810236:	c3 18       	sub	r12, r3
  810238:	96 05       	cpc	r25, r6
  81023a:	9a 07       	cpc	r25, r26
  81023c:	12 80       	ldd	r1, Z+2	; 0x02
  81023e:	e2 eb       	ldi	r30, 0xB2	; 178
  810240:	27 b2       	in	r2, 0x17	; 23
  810242:	75 09       	sbc	r23, r5
  810244:	83 2c       	mov	r8, r3
  810246:	1a 1b       	sub	r17, r26
  810248:	6e 5a       	subi	r22, 0xAE	; 174
  81024a:	a0 52       	subi	r26, 0x20	; 32
  81024c:	3b d6       	rcall	.+3190   	;  0x810ec4
  81024e:	b3 29       	or	r27, r3
  810250:	e3 2f       	mov	r30, r19
  810252:	84 53       	subi	r24, 0x34	; 52
  810254:	d1 00       	.word	0x00d1	; ????
  810256:	ed 20       	and	r14, r13
  810258:	fc b1       	in	r31, 0x0c	; 12
  81025a:	5b 6a       	ori	r21, 0xAB	; 171
  81025c:	cb be       	out	0x3b, r12	; 59
  81025e:	39 4a       	sbci	r19, 0xA9	; 169
  810260:	4c 58       	subi	r20, 0x8C	; 140
  810262:	cf d0       	rcall	.+414    	;  0x810402
  810264:	ef aa       	std	Y+55, r14	; 0x37
  810266:	fb 43       	sbci	r31, 0x3B	; 59
  810268:	4d 33       	cpi	r20, 0x3D	; 61
  81026a:	85 45       	sbci	r24, 0x55	; 85
  81026c:	f9 02       	muls	r31, r25
  81026e:	7f 50       	subi	r23, 0x0F	; 15
  810270:	3c 9f       	mul	r19, r28
  810272:	a8 51       	subi	r26, 0x18	; 24
  810274:	a3 40       	sbci	r26, 0x03	; 3
  810276:	8f 92       	push	r8
  810278:	9d 38       	cpi	r25, 0x8D	; 141
  81027a:	f5 bc       	out	0x25, r15	; 37
  81027c:	b6 da       	rcall	.-2708   	;  0x80f7ea
  81027e:	21 10       	cpse	r2, r1
  810280:	ff f3       	brie	.-2      	;  0x810280
  810282:	d2 cd       	rjmp	.-1116   	;  0x80fe28
  810284:	0c 13       	cpse	r16, r28
  810286:	ec 5f       	subi	r30, 0xFC	; 252
  810288:	97 44       	sbci	r25, 0x47	; 71
  81028a:	17 c4       	rjmp	.+2094   	;  0x810aba
  81028c:	a7 7e       	andi	r26, 0xE7	; 231
  81028e:	3d 64       	ori	r19, 0x4D	; 77
  810290:	5d 19       	sub	r21, r13
  810292:	73 60       	ori	r23, 0x03	; 3
  810294:	81 4f       	sbci	r24, 0xF1	; 241
  810296:	dc 22       	and	r13, r28
  810298:	2a 90       	ld	r2, -Y
  81029a:	88 46       	sbci	r24, 0x68	; 104
  81029c:	ee b8       	out	0x0e, r14	; 14
  81029e:	14 de       	rcall	.-984    	;  0x80fec8
  8102a0:	5e 0b       	sbc	r21, r30
  8102a2:	db e0       	ldi	r29, 0x0B	; 11
  8102a4:	32 3a       	cpi	r19, 0xA2	; 162
  8102a6:	0a 49       	sbci	r16, 0x9A	; 154
  8102a8:	06 24       	eor	r0, r6
  8102aa:	5c c2       	rjmp	.+1208   	;  0x810764
  8102ac:	d3 ac       	ldd	r13, Z+59	; 0x3b
  8102ae:	62 91       	ld	r22, -Z
  8102b0:	95 e4       	ldi	r25, 0x45	; 69
  8102b2:	79 e7       	ldi	r23, 0x79	; 121
  8102b4:	c8 37       	cpi	r28, 0x78	; 120
  8102b6:	6d 8d       	ldd	r22, Y+29	; 0x1d
  8102b8:	d5 4e       	sbci	r29, 0xE5	; 229
  8102ba:	a9 6c       	ori	r26, 0xC9	; 201
  8102bc:	56 f4       	brtc	.+20     	;  0x8102d2
  8102be:	ea 65       	ori	r30, 0x5A	; 90
  8102c0:	7a ae       	std	Y+58, r7	; 0x3a
  8102c2:	08 ba       	out	0x18, r0	; 24
  8102c4:	78 25       	eor	r23, r8
  8102c6:	2e 1c       	adc	r2, r14
  8102c8:	a6 b4       	in	r10, 0x26	; 38
  8102ca:	c6 e8       	ldi	r28, 0x86	; 134
  8102cc:	dd 74       	andi	r29, 0x4D	; 77
  8102ce:	1f 4b       	sbci	r17, 0xBF	; 191
  8102d0:	bd 8b       	std	Y+21, r27	; 0x15
  8102d2:	8a 70       	andi	r24, 0x0A	; 10
  8102d4:	3e b5       	in	r19, 0x2e	; 46
  8102d6:	66 48       	sbci	r22, 0x86	; 134
  8102d8:	03 f6       	brvc	.-128    	;  0x81025a
  8102da:	0e 61       	ori	r16, 0x1E	; 30
  8102dc:	35 57       	subi	r19, 0x75	; 117
  8102de:	b9 86       	std	Y+9, r11	; 0x09
  8102e0:	c1 1d       	adc	r28, r1
  8102e2:	9e e1       	ldi	r25, 0x1E	; 30
  8102e4:	f8 98       	cbi	0x1f, 0	; 31
  8102e6:	11 69       	ori	r17, 0x91	; 145
  8102e8:	d9 8e       	std	Y+25, r13	; 0x19
  8102ea:	94 9b       	sbis	0x12, 4	; 18
  8102ec:	1e 87       	std	Y+14, r17	; 0x0e
  8102ee:	e9 ce       	rjmp	.-558    	;  0x8100c2
  8102f0:	55 28       	or	r5, r5
  8102f2:	df 8c       	ldd	r13, Y+31	; 0x1f
  8102f4:	a1 89       	ldd	r26, Z+17	; 0x11
  8102f6:	0d bf       	out	0x3d, r16	; 61
  8102f8:	e6 42       	sbci	r30, 0x26	; 38
  8102fa:	68 41       	sbci	r22, 0x18	; 24
  8102fc:	99 2d       	mov	r25, r9
  8102fe:	0f b0       	in	r0, 0x0f	; 15
  810300:	54 bb       	out	0x14, r21	; 20
  810302:	16 00       	Address 0x0000000000810302 is out of bounds.
.word	0xffff	; ????

Disassembly of section .comment:

00000000 <.comment>:
   0:	47 43       	sbci	r20, 0x37	; 55
   2:	43 3a       	cpi	r20, 0xA3	; 163
   4:	20 28       	or	r2, r0
   6:	47 4e       	sbci	r20, 0xE7	; 231
   8:	55 29       	or	r21, r5
   a:	20 34       	cpi	r18, 0x40	; 64
   c:	2e 39       	cpi	r18, 0x9E	; 158
   e:	2e 32       	cpi	r18, 0x2E	; 46
	...
