../bootloader/bootloader_dbg.elf
architecture: avr:51, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x0001e000

Program Header:
    LOAD off    0x000000b4 vaddr 0x0001e000 paddr 0x0001e000 align 2**1
         filesz 0x00000b24 memsz 0x00000b24 flags r-x
    LOAD off    0x00000bd8 vaddr 0x00800100 paddr 0x0001eb24 align 2**0
         filesz 0x00000000 memsz 0x00000000 flags rw-
    LOAD off    0x00000bd8 vaddr 0x00800100 paddr 0x00800100 align 2**0
         filesz 0x00000000 memsz 0x000003b3 flags rw-
    LOAD off    0x00000bd8 vaddr 0x00810000 paddr 0x00810000 align 2**0
         filesz 0x00000303 memsz 0x00000303 flags rw-
Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .data         00000000  00800100  0001eb24  00000bd8  2**0
                  CONTENTS, ALLOC, LOAD, DATA
  1 .text         00000b24  0001e000  0001e000  000000b4  2**1
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  2 .bss          000003b3  00800100  00800100  00000bd8  2**0
                  ALLOC
  3 .eeprom       00000303  00810000  00810000  00000bd8  2**0
                  CONTENTS, ALLOC, LOAD, DATA
  4 .stab         0000267c  00000000  00000000  00000edc  2**2
                  CONTENTS, READONLY, DEBUGGING
  5 .stabstr      000013bf  00000000  00000000  00003558  2**0
                  CONTENTS, READONLY, DEBUGGING
  6 .comment      00000011  00000000  00000000  00004917  2**0
                  CONTENTS, READONLY
SYMBOL TABLE:
00800100 l    d  .data	00000000 .data
0001e000 l    d  .text	00000000 .text
00800100 l    d  .bss	00000000 .bss
00810000 l    d  .eeprom	00000000 .eeprom
00000000 l    d  .stab	00000000 .stab
00000000 l    d  .stabstr	00000000 .stabstr
00000000 l    d  .comment	00000000 .comment
00000000 l    df *ABS*	00000000 uart.c
0000003e l       *ABS*	00000000 __SP_H__
0000003d l       *ABS*	00000000 __SP_L__
0000003f l       *ABS*	00000000 __SREG__
0000003b l       *ABS*	00000000 __RAMPZ__
00000000 l       *ABS*	00000000 __tmp_reg__
00000001 l       *ABS*	00000000 __zero_reg__
00000000 l    df *ABS*	00000000 sys_startup.c
0000003e l       *ABS*	00000000 __SP_H__
0000003d l       *ABS*	00000000 __SP_L__
0000003f l       *ABS*	00000000 __SREG__
0000003b l       *ABS*	00000000 __RAMPZ__
00000000 l       *ABS*	00000000 __tmp_reg__
00000001 l       *ABS*	00000000 __zero_reg__
00000000 l    df *ABS*	00000000 bootloader.c
0000003e l       *ABS*	00000000 __SP_H__
0000003d l       *ABS*	00000000 __SP_L__
0000003f l       *ABS*	00000000 __SREG__
0000003b l       *ABS*	00000000 __RAMPZ__
00000000 l       *ABS*	00000000 __tmp_reg__
00000001 l       *ABS*	00000000 __zero_reg__
00000000 l    df *ABS*	00000000 aes.c
0000003e l       *ABS*	00000000 __SP_H__
0000003d l       *ABS*	00000000 __SP_L__
0000003f l       *ABS*	00000000 __SREG__
0000003b l       *ABS*	00000000 __RAMPZ__
00000000 l       *ABS*	00000000 __tmp_reg__
00000001 l       *ABS*	00000000 __zero_reg__
0001e3ea l     F .text	00000052 AddRoundKey
008001b2 l     O .bss	00000002 state
00800102 l     O .bss	000000b0 RoundKey
0001e43c l     F .text	0000003a ShiftRows
0001e476 l     F .text	00000016 xtime
0001e48c l     F .text	0000002e InvSubBytes
0001e4ba l     F .text	0000003a InvShiftRows
0001e4f4 l     F .text	0000002e SubBytes
0001e522 l     F .text	00000172 KeyExpansion
00800100 l     O .bss	00000002 Key
00810203 l     O .eeprom	00000100 Sbox
00810103 l     O .eeprom	00000100 Rsbox
00810004 l     O .eeprom	000000ff rcon
00000000 l    df *ABS*	00000000 _clear_bss.o
0001e018 l       .text	00000000 .do_clear_bss_start
0001e016 l       .text	00000000 .do_clear_bss_loop
0001e07a g     F .text	0000001c UART1_putstring
0001ea82 g       .text	00000036 .hidden __epilogue_restores__
0001e0e0 g     F .text	00000010 UART0_flush
0001e00e g       .text	00000000 __trampolines_start
0001eb24 g       .text	00000000 _etext
0001e694 g     F .text	00000194 AES128_ECB_encrypt
008001b4 g     O .bss	00000100 sbox
0001e10c g     F .text	0000007c boot_firmware
0001e0c6 g     F .text	0000000c UART0_data_available
0001eb24 g       *ABS*	00000000 __data_load_end
0001e05c g     F .text	0000000e UART1_getchar
0001e00e g       .text	00000000 __trampolines_end
0001eb24 g       *ABS*	00000000 __data_load_start
0001e00e g       .text	00000000 __dtors_end
0001e096 g     F .text	00000022 UART0_init
008004b3 g       .bss	00000000 __bss_end
0001e000 g     F .text	0000000e __Init
0001e272 g     F .text	000000ac program_flash
0001e0d2 g     F .text	0000000e UART0_getchar
0001eb02 g       .text	00000000 eeprom_update_r18
0001e01e g     F .text	00000002 __jumpMain
0001e00e g       .text	00000010 .hidden __do_clear_bss
00810303 g       .eeprom	00000000 __eeprom_end
0001eab8 g     F .text	00000010 eeprom_read_byte
0001e0f0 g     F .text	0000001c UART0_putstring
00810000 g     O .eeprom	00000002 fw_version
0001eb00 g     F .text	00000024 eeprom_update_byte
0001ead4 g     F .text	0000000c eeprom_update_word
0001e042 g     F .text	0000000e UART1_putchar
0001e00e g       .text	00000000 __ctors_start
0001e31e g     F .text	000000cc load_firmware
0001eae0 g     F .text	00000020 eeprom_read_block
0001e00e g     F .text	00000000 __do_copy_data
00800100 g       .bss	00000000 __bss_start
0001ea08 g     F .text	00000042 main
0001e828 g     F .text	000001e0 AES128_ECB_decrypt
008002b4 g     O .bss	000000ff Rcon
0001e00e g       .text	00000000 __dtors_start
0001e00e g       .text	00000000 __ctors_end
00810002 g     O .eeprom	00000002 fw_size
0001e21e g     F .text	00000054 read_frame
00800100 g       .data	00000000 _edata
008004b3 g       .bss	00000000 _end
0001eae4 g       .text	00000000 eeprom_read_blraw
0001e050 g     F .text	0000000c UART1_data_available
0001e0b8 g     F .text	0000000e UART0_putchar
0001e188 g     F .text	00000096 readback
0001e06a g     F .text	00000010 UART1_flush
0001e020 g     F .text	00000022 UART1_init
008003b3 g     O .bss	00000100 rsbox
0001eac8 g     F .text	0000000c eeprom_read_word
0001ea4a g       .text	00000038 .hidden __prologue_saves__



Disassembly of section .text:

0001e000 <__Init>:
   1e000:	14 be       	out	0x34, r1	; 52
   1e002:	88 e1       	ldi	r24, 0x18	; 24
   1e004:	80 93 60 00 	sts	0x0060, r24
   1e008:	10 92 60 00 	sts	0x0060, r1
   1e00c:	00 c0       	rjmp	.+0      	; 0x1e00e <__do_copy_data>

0001e00e <__do_copy_data>:
   1e00e:	24 e0       	ldi	r18, 0x04	; 4
   1e010:	a0 e0       	ldi	r26, 0x00	; 0
   1e012:	b1 e0       	ldi	r27, 0x01	; 1
   1e014:	01 c0       	rjmp	.+2      	; 0x1e018 <.do_clear_bss_start>

0001e016 <.do_clear_bss_loop>:
   1e016:	1d 92       	st	X+, r1

0001e018 <.do_clear_bss_start>:
   1e018:	a3 3b       	cpi	r26, 0xB3	; 179
   1e01a:	b2 07       	cpc	r27, r18
   1e01c:	e1 f7       	brne	.-8      	; 0x1e016 <.do_clear_bss_loop>

0001e01e <__jumpMain>:
   1e01e:	f4 c4       	rjmp	.+2536   	; 0x1ea08 <main>

0001e020 <UART1_init>:
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

0001e042 <UART1_putchar>:
   1e042:	90 91 c8 00 	lds	r25, 0x00C8
   1e046:	95 ff       	sbrs	r25, 5
   1e048:	fc cf       	rjmp	.-8      	; 0x1e042 <UART1_putchar>
   1e04a:	80 93 ce 00 	sts	0x00CE, r24
   1e04e:	08 95       	ret

0001e050 <UART1_data_available>:
   1e050:	80 91 c8 00 	lds	r24, 0x00C8
   1e054:	88 1f       	adc	r24, r24
   1e056:	88 27       	eor	r24, r24
   1e058:	88 1f       	adc	r24, r24
   1e05a:	08 95       	ret

0001e05c <UART1_getchar>:
   1e05c:	80 91 c8 00 	lds	r24, 0x00C8
   1e060:	87 ff       	sbrs	r24, 7
   1e062:	fc cf       	rjmp	.-8      	; 0x1e05c <UART1_getchar>
   1e064:	80 91 ce 00 	lds	r24, 0x00CE
   1e068:	08 95       	ret

0001e06a <UART1_flush>:
   1e06a:	80 91 c8 00 	lds	r24, 0x00C8
   1e06e:	87 ff       	sbrs	r24, 7
   1e070:	03 c0       	rjmp	.+6      	; 0x1e078 <UART1_flush+0xe>
   1e072:	80 91 ce 00 	lds	r24, 0x00CE
   1e076:	f9 cf       	rjmp	.-14     	; 0x1e06a <UART1_flush>
   1e078:	08 95       	ret

0001e07a <UART1_putstring>:
   1e07a:	cf 93       	push	r28
   1e07c:	df 93       	push	r29
   1e07e:	ec 01       	movw	r28, r24
   1e080:	89 91       	ld	r24, Y+
   1e082:	88 23       	and	r24, r24
   1e084:	19 f0       	breq	.+6      	; 0x1e08c <UART1_putstring+0x12>
   1e086:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1e08a:	fa cf       	rjmp	.-12     	; 0x1e080 <UART1_putstring+0x6>
   1e08c:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1e090:	df 91       	pop	r29
   1e092:	cf 91       	pop	r28
   1e094:	08 95       	ret

0001e096 <UART0_init>:
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

0001e0b8 <UART0_putchar>:
   1e0b8:	90 91 c0 00 	lds	r25, 0x00C0
   1e0bc:	95 ff       	sbrs	r25, 5
   1e0be:	fc cf       	rjmp	.-8      	; 0x1e0b8 <UART0_putchar>
   1e0c0:	80 93 c6 00 	sts	0x00C6, r24
   1e0c4:	08 95       	ret

0001e0c6 <UART0_data_available>:
   1e0c6:	80 91 c0 00 	lds	r24, 0x00C0
   1e0ca:	88 1f       	adc	r24, r24
   1e0cc:	88 27       	eor	r24, r24
   1e0ce:	88 1f       	adc	r24, r24
   1e0d0:	08 95       	ret

0001e0d2 <UART0_getchar>:
   1e0d2:	80 91 c0 00 	lds	r24, 0x00C0
   1e0d6:	87 ff       	sbrs	r24, 7
   1e0d8:	fc cf       	rjmp	.-8      	; 0x1e0d2 <UART0_getchar>
   1e0da:	80 91 c6 00 	lds	r24, 0x00C6
   1e0de:	08 95       	ret

0001e0e0 <UART0_flush>:
   1e0e0:	80 91 c0 00 	lds	r24, 0x00C0
   1e0e4:	87 ff       	sbrs	r24, 7
   1e0e6:	03 c0       	rjmp	.+6      	; 0x1e0ee <UART0_flush+0xe>
   1e0e8:	80 91 c6 00 	lds	r24, 0x00C6
   1e0ec:	f9 cf       	rjmp	.-14     	; 0x1e0e0 <UART0_flush>
   1e0ee:	08 95       	ret

0001e0f0 <UART0_putstring>:
   1e0f0:	cf 93       	push	r28
   1e0f2:	df 93       	push	r29
   1e0f4:	ec 01       	movw	r28, r24
   1e0f6:	89 91       	ld	r24, Y+
   1e0f8:	88 23       	and	r24, r24
   1e0fa:	19 f0       	breq	.+6      	; 0x1e102 <UART0_putstring+0x12>
   1e0fc:	0e 94 5c f0 	call	0x1e0b8	; 0x1e0b8 <UART0_putchar>
   1e100:	fa cf       	rjmp	.-12     	; 0x1e0f6 <UART0_putstring+0x6>
   1e102:	0e 94 5c f0 	call	0x1e0b8	; 0x1e0b8 <UART0_putchar>
   1e106:	df 91       	pop	r29
   1e108:	cf 91       	pop	r28
   1e10a:	08 95       	ret

0001e10c <boot_firmware>:
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
   1e12e:	0e 94 64 f5 	call	0x1eac8	; 0x1eac8 <eeprom_read_word>
   1e132:	6c 01       	movw	r12, r24
   1e134:	e1 2c       	mov	r14, r1
   1e136:	f1 2c       	mov	r15, r1
   1e138:	c1 14       	cp	r12, r1
   1e13a:	d1 04       	cpc	r13, r1
   1e13c:	e1 04       	cpc	r14, r1
   1e13e:	f1 04       	cpc	r15, r1
   1e140:	09 f4       	brne	.+2      	; 0x1e144 <boot_firmware+0x38>
   1e142:	ff cf       	rjmp	.-2      	; 0x1e142 <boot_firmware+0x36>
   1e144:	a8 95       	wdr
   1e146:	eb be       	out	0x3b, r14	; 59
   1e148:	f6 01       	movw	r30, r12
   1e14a:	c7 91       	elpm	r28, Z+
   1e14c:	8c 2f       	mov	r24, r28
   1e14e:	0e 94 5c f0 	call	0x1e0b8	; 0x1e0b8 <UART0_putchar>
   1e152:	8f ef       	ldi	r24, 0xFF	; 255
   1e154:	c8 1a       	sub	r12, r24
   1e156:	d8 0a       	sbc	r13, r24
   1e158:	e8 0a       	sbc	r14, r24
   1e15a:	f8 0a       	sbc	r15, r24
   1e15c:	c1 11       	cpse	r28, r1
   1e15e:	f3 cf       	rjmp	.-26     	; 0x1e146 <boot_firmware+0x3a>
   1e160:	a8 95       	wdr
   1e162:	0f b6       	in	r0, 0x3f	; 63
   1e164:	f8 94       	cli
   1e166:	a8 95       	wdr
   1e168:	80 91 60 00 	lds	r24, 0x0060
   1e16c:	88 61       	ori	r24, 0x18	; 24
   1e16e:	80 93 60 00 	sts	0x0060, r24
   1e172:	10 92 60 00 	sts	0x0060, r1
   1e176:	0f be       	out	0x3f, r0	; 63
   1e178:	0c 94 00 00 	jmp	0	; 0x0 <__tmp_reg__>
   1e17c:	cf 91       	pop	r28
   1e17e:	ff 90       	pop	r15
   1e180:	ef 90       	pop	r14
   1e182:	df 90       	pop	r13
   1e184:	cf 90       	pop	r12
   1e186:	08 95       	ret

0001e188 <readback>:
   1e188:	9f e0       	ldi	r25, 0x0F	; 15
   1e18a:	88 e1       	ldi	r24, 0x18	; 24
   1e18c:	0f b6       	in	r0, 0x3f	; 63
   1e18e:	f8 94       	cli
   1e190:	a8 95       	wdr
   1e192:	80 93 60 00 	sts	0x0060, r24
   1e196:	0f be       	out	0x3f, r0	; 63
   1e198:	90 93 60 00 	sts	0x0060, r25
   1e19c:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1a0:	c8 2e       	mov	r12, r24
   1e1a2:	d1 2c       	mov	r13, r1
   1e1a4:	e1 2c       	mov	r14, r1
   1e1a6:	f1 2c       	mov	r15, r1
   1e1a8:	fc 2c       	mov	r15, r12
   1e1aa:	ee 24       	eor	r14, r14
   1e1ac:	dd 24       	eor	r13, r13
   1e1ae:	cc 24       	eor	r12, r12
   1e1b0:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1b4:	e8 2a       	or	r14, r24
   1e1b6:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1ba:	c8 2f       	mov	r28, r24
   1e1bc:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1c0:	c8 2a       	or	r12, r24
   1e1c2:	dc 2a       	or	r13, r28
   1e1c4:	a8 95       	wdr
   1e1c6:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1ca:	88 2e       	mov	r8, r24
   1e1cc:	91 2c       	mov	r9, r1
   1e1ce:	a1 2c       	mov	r10, r1
   1e1d0:	b1 2c       	mov	r11, r1
   1e1d2:	b8 2c       	mov	r11, r8
   1e1d4:	aa 24       	eor	r10, r10
   1e1d6:	99 24       	eor	r9, r9
   1e1d8:	88 24       	eor	r8, r8
   1e1da:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1de:	a8 2a       	or	r10, r24
   1e1e0:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e1e4:	c8 2f       	mov	r28, r24
   1e1e6:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
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
   1e200:	68 f4       	brcc	.+26     	; 0x1e21c <readback+0x94>
   1e202:	eb be       	out	0x3b, r14	; 59
   1e204:	f6 01       	movw	r30, r12
   1e206:	87 91       	elpm	r24, Z+
   1e208:	a8 95       	wdr
   1e20a:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1e20e:	a8 95       	wdr
   1e210:	8f ef       	ldi	r24, 0xFF	; 255
   1e212:	c8 1a       	sub	r12, r24
   1e214:	d8 0a       	sbc	r13, r24
   1e216:	e8 0a       	sbc	r14, r24
   1e218:	f8 0a       	sbc	r15, r24
   1e21a:	ee cf       	rjmp	.-36     	; 0x1e1f8 <readback+0x70>
   1e21c:	ff cf       	rjmp	.-2      	; 0x1e21c <readback+0x94>

0001e21e <read_frame>:
; r14:r15 has array indicies (or start index)
; r16:r17 has the other
; r24 is first return reg
   1e21e:	a0 e0       	ldi	r26, 0x00	    ; r26 = 0
   1e220:	b0 e0       	ldi	r27, 0x00	    ; r27 = 0
   1e222:	e5 e1       	ldi	r30, 0x15	    ; r30 = 21
   1e224:	f1 ef       	ldi	r31, 0xF1	    ; r31 = 241
   1e226:	0c 94 2f f5 	jmp	0x1ea5e	; 0x1ea5e <__prologue_saves__+0x14>
   1e22a:	8c 01       	movw	r16, r24    ; r16 has 2B r24
   1e22c:	7b 01       	movw	r14, r22    ; r14 has 2B r22
   1e22e:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e232:	c8 2f       	mov	r28, r24        ; r28 = r24
   1e234:	d0 e0       	ldi	r29, 0x00	    ; r29 = 0 
   1e236:	dc 2f       	mov	r29, r28        ; r29 = r28
   1e238:	cc 27       	eor	r28, r28        ; r28 = 0
   1e23a:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e23e:	c8 0f       	add	r28, r24 
   1e240:	d1 1d       	adc	r29, r1         ; carry with 0 reg?
   1e242:	c1 2c       	mov	r12, r1         ; r12 = 0
   1e244:	d1 2c       	mov	r13, r1         ; r13 = 0
;for (int i = 0; i < frame_length; i++) {
; r12:r13 has data index
   1e246:	a8 95       	wdr                 ; <---------------------.
   1e248:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>   |
   1e24c:	f6 01       	movw	r30, r12    ; move index to address |
   1e24e:	ee 0d       	add	r30, r14        ; add array inedex      |
   1e250:	ff 1d       	adc	r31, r15        ; ^                     |
   1e252:	e0 0f       	add	r30, r16        ; add start offset      |
   1e254:	f1 1f       	adc	r31, r17        ; ^                     |
   1e256:	80 83       	st	Z, r24          ; store value in array  |
   1e258:	8f ef       	ldi	r24, 0xFF	    ; r24 = 255             |
   1e25a:	c8 1a       	sub	r12, r24        ; increment index       |
   1e25c:	d8 0a       	sbc	r13, r24        ; ^                     |
   1e25e:	80 e1       	ldi	r24, 0x10	    ; r24 = 16              |
   1e260:	c8 16       	cp	r12, r24        ; compare index to 16   |
   1e262:	d1 04       	cpc	r13, r1         ; ^                     |
   1e264:	81 f7       	brne	.-32    ; 0x1e246 <read_frame+0x28>-`
;}                                          
   1e266:	ce 01       	movw	r24, r28    ; put return value in return reg
   1e268:	cd b7       	in	r28, 0x3d	; 61
   1e26a:	de b7       	in	r29, 0x3e	; 62
   1e26c:	e8 e0       	ldi	r30, 0x08	; 8
   1e26e:	0c 94 4b f5 	jmp	0x1ea96	; 0x1ea96 <__epilogue_restores__+0x14>

0001e272 <program_flash>:
   1e272:	8f 92       	push	r8
   1e274:	9f 92       	push	r9
   1e276:	af 92       	push	r10
   1e278:	bf 92       	push	r11
   1e27a:	ef 92       	push	r14
   1e27c:	ff 92       	push	r15
   1e27e:	07 b6       	in	r0, 0x37	; 55
   1e280:	00 fc       	sbrc	r0, 0
   1e282:	fd cf       	rjmp	.-6      	; 0x1e27e <program_flash+0xc>
   1e284:	f9 99       	sbic	0x1f, 1	; 31
   1e286:	fe cf       	rjmp	.-4      	; 0x1e284 <program_flash+0x12>
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
   1e2ba:	fd cf       	rjmp	.-6      	; 0x1e2b6 <program_flash+0x44>
   1e2bc:	f9 99       	sbic	0x1f, 1	; 31
   1e2be:	fe cf       	rjmp	.-4      	; 0x1e2bc <program_flash+0x4a>
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
   1e2e4:	e9 f6       	brne	.-70     	; 0x1e2a0 <program_flash+0x2e>
   1e2e6:	07 b6       	in	r0, 0x37	; 55
   1e2e8:	00 fc       	sbrc	r0, 0
   1e2ea:	fd cf       	rjmp	.-6      	; 0x1e2e6 <program_flash+0x74>
   1e2ec:	f9 99       	sbic	0x1f, 1	; 31
   1e2ee:	fe cf       	rjmp	.-4      	; 0x1e2ec <program_flash+0x7a>
   1e2f0:	25 e0       	ldi	r18, 0x05	; 5
   1e2f2:	fb 01       	movw	r30, r22
   1e2f4:	80 93 5b 00 	sts	0x005B, r24
   1e2f8:	20 93 57 00 	sts	0x0057, r18
   1e2fc:	e8 95       	spm
   1e2fe:	07 b6       	in	r0, 0x37	; 55
   1e300:	00 fc       	sbrc	r0, 0
   1e302:	fd cf       	rjmp	.-6      	; 0x1e2fe <program_flash+0x8c>
   1e304:	f9 99       	sbic	0x1f, 1	; 31
   1e306:	fe cf       	rjmp	.-4      	; 0x1e304 <program_flash+0x92>
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

0001e31e <load_firmware>:
   1e31e:	a0 e0       	ldi	r26, 0x00	; 0
   1e320:	b1 e0       	ldi	r27, 0x01	; 1
   1e322:	e5 e9       	ldi	r30, 0x95	; 149
   1e324:	f1 ef       	ldi	r31, 0xF1	; 241
   1e326:	0c 94 31 f5 	jmp	0x1ea62	; 0x1ea62 <__prologue_saves__+0x18>
   1e32a:	9f e0       	ldi	r25, 0x0F	; 15
   1e32c:	88 e1       	ldi	r24, 0x18	; 24
   1e32e:	0f b6       	in	r0, 0x3f	; 63
   1e330:	f8 94       	cli
   1e332:	a8 95       	wdr
   1e334:	80 93 60 00 	sts	0x0060, r24
   1e338:	0f be       	out	0x3f, r0	; 63
   1e33a:	90 93 60 00 	sts	0x0060, r25
   1e33e:	0e 94 28 f0 	call	0x1e050	; 0x1e050 <UART1_data_available>
   1e342:	81 11       	cpse	r24, r1
   1e344:	01 c0       	rjmp	.+2      	; 0x1e348 <load_firmware+0x2a>
   1e346:	fb cf       	rjmp	.-10     	; 0x1e33e <load_firmware+0x20>
   1e348:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e34c:	08 2f       	mov	r16, r24
   1e34e:	10 e0       	ldi	r17, 0x00	; 0
   1e350:	10 2f       	mov	r17, r16
   1e352:	00 27       	eor	r16, r16
   1e354:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e358:	08 2b       	or	r16, r24
   1e35a:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e35e:	e8 2e       	mov	r14, r24
   1e360:	f1 2c       	mov	r15, r1
   1e362:	fe 2c       	mov	r15, r14
   1e364:	ee 24       	eor	r14, r14
   1e366:	0e 94 2e f0 	call	0x1e05c	; 0x1e05c <UART1_getchar>
   1e36a:	e8 2a       	or	r14, r24
   1e36c:	01 15       	cp	r16, r1
   1e36e:	11 05       	cpc	r17, r1
   1e370:	89 f0       	breq	.+34     	; 0x1e394 <load_firmware+0x76>
   1e372:	80 e0       	ldi	r24, 0x00	; 0
   1e374:	90 e0       	ldi	r25, 0x00	; 0
   1e376:	0e 94 64 f5 	call	0x1eac8	; 0x1eac8 <eeprom_read_word>
   1e37a:	08 17       	cp	r16, r24
   1e37c:	19 07       	cpc	r17, r25
   1e37e:	20 f4       	brcc	.+8      	; 0x1e388 <load_firmware+0x6a>
   1e380:	81 e0       	ldi	r24, 0x01	; 1
   1e382:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1e386:	ff cf       	rjmp	.-2      	; 0x1e386 <load_firmware+0x68>
   1e388:	a8 95       	wdr
   1e38a:	b8 01       	movw	r22, r16
   1e38c:	80 e0       	ldi	r24, 0x00	; 0
   1e38e:	90 e0       	ldi	r25, 0x00	; 0
   1e390:	0e 94 6a f5 	call	0x1ead4	; 0x1ead4 <eeprom_update_word>
   1e394:	a8 95       	wdr
   1e396:	b7 01       	movw	r22, r14
   1e398:	82 e0       	ldi	r24, 0x02	; 2
   1e39a:	90 e0       	ldi	r25, 0x00	; 0
   1e39c:	0e 94 6a f5 	call	0x1ead4	; 0x1ead4 <eeprom_update_word>
   1e3a0:	a8 95       	wdr
   1e3a2:	80 e0       	ldi	r24, 0x00	; 0
   1e3a4:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1e3a8:	00 e0       	ldi	r16, 0x00	; 0
   1e3aa:	10 e0       	ldi	r17, 0x00	; 0
; JUMP START
   1e3ac:	a8 95       	wdr
   1e3ae:	60 e0       	ldi	r22, 0x00	; 0
   1e3b0:	70 e0       	ldi	r23, 0x00	; 0
   1e3b2:	ce 01       	movw	r24, r28
   1e3b4:	01 96       	adiw	r24, 0x01	; 1
   1e3b6:	0e 94 0f f1 	call	0x1e21e	; 0x1e21e <read_frame>
   1e3ba:	a8 95       	wdr
   1e3bc:	b8 01       	movw	r22, r16
   1e3be:	80 e0       	ldi	r24, 0x00	; 0
   1e3c0:	90 e0       	ldi	r25, 0x00	; 0
   1e3c2:	ae 01       	movw	r20, r28
   1e3c4:	4f 5f       	subi	r20, 0xFF	; 255
   1e3c6:	5f 4f       	sbci	r21, 0xFF	; 255
   1e3c8:	0e 94 39 f1 	call	0x1e272	; 0x1e272 <program_flash>
   1e3cc:	13 95       	inc	r17
   1e3ce:	80 e5       	ldi	r24, 0x50	; 80
   1e3d0:	0e 94 5c f0 	call	0x1e0b8	; 0x1e0b8 <UART0_putchar>
   1e3d4:	81 2f       	mov	r24, r17
   1e3d6:	0e 94 5c f0 	call	0x1e0b8	; 0x1e0b8 <UART0_putchar>
   1e3da:	80 e0       	ldi	r24, 0x00	; 0
   1e3dc:	0e 94 5c f0 	call	0x1e0b8	; 0x1e0b8 <UART0_putchar>
   1e3e0:	a8 95       	wdr
   1e3e2:	80 e0       	ldi	r24, 0x00	; 0
   1e3e4:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1e3e8:	e1 cf       	rjmp	.-62     	; 0x1e3ac <load_firmware+0x8e>

0001e3ea <AddRoundKey>:
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
   1e426:	a1 f7       	brne	.-24     	; 0x1e410 <AddRoundKey+0x26>
   1e428:	4c 5f       	subi	r20, 0xFC	; 252
   1e42a:	5f 4f       	sbci	r21, 0xFF	; 255
   1e42c:	6c 5f       	subi	r22, 0xFC	; 252
   1e42e:	7f 4f       	sbci	r23, 0xFF	; 255
   1e430:	40 31       	cpi	r20, 0x10	; 16
   1e432:	51 05       	cpc	r21, r1
   1e434:	31 f7       	brne	.-52     	; 0x1e402 <AddRoundKey+0x18>
   1e436:	df 91       	pop	r29
   1e438:	cf 91       	pop	r28
   1e43a:	08 95       	ret

0001e43c <ShiftRows>:
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

0001e476 <xtime>:
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

0001e48c <InvSubBytes>:
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
   1e4ac:	b1 f7       	brne	.-20     	; 0x1e49a <InvSubBytes+0xe>
   1e4ae:	91 50       	subi	r25, 0x01	; 1
   1e4b0:	2f 5f       	subi	r18, 0xFF	; 255
   1e4b2:	3f 4f       	sbci	r19, 0xFF	; 255
   1e4b4:	91 11       	cpse	r25, r1
   1e4b6:	ef cf       	rjmp	.-34     	; 0x1e496 <InvSubBytes+0xa>
   1e4b8:	08 95       	ret

0001e4ba <InvShiftRows>:
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

0001e4f4 <SubBytes>:
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
   1e514:	b1 f7       	brne	.-20     	; 0x1e502 <SubBytes+0xe>
   1e516:	91 50       	subi	r25, 0x01	; 1
   1e518:	2f 5f       	subi	r18, 0xFF	; 255
   1e51a:	3f 4f       	sbci	r19, 0xFF	; 255
   1e51c:	91 11       	cpse	r25, r1
   1e51e:	ef cf       	rjmp	.-34     	; 0x1e4fe <SubBytes+0xa>
   1e520:	08 95       	ret

0001e522 <KeyExpansion>:
   1e522:	a4 e0       	ldi	r26, 0x04	; 4
   1e524:	b0 e0       	ldi	r27, 0x00	; 0
   1e526:	e7 e9       	ldi	r30, 0x97	; 151
   1e528:	f2 ef       	ldi	r31, 0xF2	; 242
   1e52a:	0c 94 2f f5 	jmp	0x1ea5e	; 0x1ea5e <__prologue_saves__+0x14>
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
   1e57c:	f9 f6       	brne	.-66     	; 0x1e53c <KeyExpansion+0x1a>
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
   1e5b4:	99 f7       	brne	.-26     	; 0x1e59c <KeyExpansion+0x7a>
   1e5b6:	b7 01       	movw	r22, r14
   1e5b8:	a6 01       	movw	r20, r12
   1e5ba:	43 70       	andi	r20, 0x03	; 3
   1e5bc:	55 27       	eor	r21, r21
   1e5be:	66 27       	eor	r22, r22
   1e5c0:	77 27       	eor	r23, r23
   1e5c2:	45 2b       	or	r20, r21
   1e5c4:	46 2b       	or	r20, r22
   1e5c6:	47 2b       	or	r20, r23
   1e5c8:	51 f5       	brne	.+84     	; 0x1e61e <KeyExpansion+0xfc>
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
   1e610:	d1 f7       	brne	.-12     	; 0x1e606 <KeyExpansion+0xe4>
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
   1e688:	09 f0       	breq	.+2      	; 0x1e68c <KeyExpansion+0x16a>
   1e68a:	80 cf       	rjmp	.-256    	; 0x1e58c <KeyExpansion+0x6a>
   1e68c:	24 96       	adiw	r28, 0x04	; 4
   1e68e:	e8 e0       	ldi	r30, 0x08	; 8
   1e690:	0c 94 4b f5 	jmp	0x1ea96	; 0x1ea96 <__epilogue_restores__+0x14>

0001e694 <AES128_ECB_encrypt>:
   1e694:	a6 e0       	ldi	r26, 0x06	; 6
   1e696:	b0 e0       	ldi	r27, 0x00	; 0
   1e698:	e0 e5       	ldi	r30, 0x50	; 80
   1e69a:	f3 ef       	ldi	r31, 0xF3	; 243
   1e69c:	0c 94 25 f5 	jmp	0x1ea4a	; 0x1ea4a <__prologue_saves__>
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
   1e6ba:	c9 f7       	brne	.-14     	; 0x1e6ae <AES128_ECB_encrypt+0x1a>
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
   1e6e2:	0e 94 5c f5 	call	0x1eab8	; 0x1eab8 <eeprom_read_byte>
   1e6e6:	d6 01       	movw	r26, r12
   1e6e8:	8d 93       	st	X+, r24
   1e6ea:	6d 01       	movw	r12, r26
   1e6ec:	c8 01       	movw	r24, r16
   1e6ee:	8d 5f       	subi	r24, 0xFD	; 253
   1e6f0:	9e 4f       	sbci	r25, 0xFE	; 254
   1e6f2:	0e 94 5c f5 	call	0x1eab8	; 0x1eab8 <eeprom_read_byte>
   1e6f6:	f7 01       	movw	r30, r14
   1e6f8:	81 93       	st	Z+, r24
   1e6fa:	7f 01       	movw	r14, r30
   1e6fc:	0f 3f       	cpi	r16, 0xFF	; 255
   1e6fe:	11 05       	cpc	r17, r1
   1e700:	49 f0       	breq	.+18     	; 0x1e714 <AES128_ECB_encrypt+0x80>
   1e702:	c8 01       	movw	r24, r16
   1e704:	8c 5f       	subi	r24, 0xFC	; 252
   1e706:	9f 4f       	sbci	r25, 0xFF	; 255
   1e708:	0e 94 5c f5 	call	0x1eab8	; 0x1eab8 <eeprom_read_byte>
   1e70c:	f8 01       	movw	r30, r16
   1e70e:	ec 54       	subi	r30, 0x4C	; 76
   1e710:	fd 4f       	sbci	r31, 0xFD	; 253
   1e712:	80 83       	st	Z, r24
   1e714:	0f 5f       	subi	r16, 0xFF	; 255
   1e716:	1f 4f       	sbci	r17, 0xFF	; 255
   1e718:	01 15       	cp	r16, r1
   1e71a:	f1 e0       	ldi	r31, 0x01	; 1
   1e71c:	1f 07       	cpc	r17, r31
   1e71e:	f1 f6       	brne	.-68     	; 0x1e6dc <AES128_ECB_encrypt+0x48>
   1e720:	b0 92 01 01 	sts	0x0101, r11
   1e724:	a0 92 00 01 	sts	0x0100, r10
   1e728:	0e 94 91 f2 	call	0x1e522	; 0x1e522 <KeyExpansion>
   1e72c:	80 e0       	ldi	r24, 0x00	; 0
   1e72e:	0e 94 f5 f1 	call	0x1e3ea	; 0x1e3ea <AddRoundKey>
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
   1e75e:	0e 94 7a f2 	call	0x1e4f4	; 0x1e4f4 <SubBytes>
   1e762:	0e 94 1e f2 	call	0x1e43c	; 0x1e43c <ShiftRows>
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
   1e788:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
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
   1e7a0:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
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
   1e7ba:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
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
   1e7d4:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
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
   1e7fc:	09 f0       	breq	.+2      	; 0x1e800 <AES128_ECB_encrypt+0x16c>
   1e7fe:	b9 cf       	rjmp	.-142    	; 0x1e772 <AES128_ECB_encrypt+0xde>
   1e800:	89 81       	ldd	r24, Y+1	; 0x01
   1e802:	0e 94 f5 f1 	call	0x1e3ea	; 0x1e3ea <AddRoundKey>
   1e806:	99 81       	ldd	r25, Y+1	; 0x01
   1e808:	9f 5f       	subi	r25, 0xFF	; 255
   1e80a:	99 83       	std	Y+1, r25	; 0x01
   1e80c:	9a 30       	cpi	r25, 0x0A	; 10
   1e80e:	09 f0       	breq	.+2      	; 0x1e812 <AES128_ECB_encrypt+0x17e>
   1e810:	a6 cf       	rjmp	.-180    	; 0x1e75e <AES128_ECB_encrypt+0xca>
   1e812:	0e 94 7a f2 	call	0x1e4f4	; 0x1e4f4 <SubBytes>
   1e816:	0e 94 1e f2 	call	0x1e43c	; 0x1e43c <ShiftRows>
   1e81a:	8a e0       	ldi	r24, 0x0A	; 10
   1e81c:	0e 94 f5 f1 	call	0x1e3ea	; 0x1e3ea <AddRoundKey>
   1e820:	26 96       	adiw	r28, 0x06	; 6
   1e822:	e2 e1       	ldi	r30, 0x12	; 18
   1e824:	0c 94 41 f5 	jmp	0x1ea82	; 0x1ea82 <__epilogue_restores__>

0001e828 <AES128_ECB_decrypt>:
   1e828:	ae e0       	ldi	r26, 0x0E	; 14
   1e82a:	b0 e0       	ldi	r27, 0x00	; 0
   1e82c:	ea e1       	ldi	r30, 0x1A	; 26
   1e82e:	f4 ef       	ldi	r31, 0xF4	; 244
   1e830:	0c 94 25 f5 	jmp	0x1ea4a	; 0x1ea4a <__prologue_saves__>
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
   1e84c:	c9 f7       	brne	.-14     	; 0x1e840 <AES128_ECB_decrypt+0x18>
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
   1e86c:	0e 94 5c f5 	call	0x1eab8	; 0x1eab8 <eeprom_read_byte>
   1e870:	f7 01       	movw	r30, r14
   1e872:	81 93       	st	Z+, r24
   1e874:	7f 01       	movw	r14, r30
   1e876:	c4 01       	movw	r24, r8
   1e878:	8d 5f       	subi	r24, 0xFD	; 253
   1e87a:	9e 4f       	sbci	r25, 0xFE	; 254
   1e87c:	0e 94 5c f5 	call	0x1eab8	; 0x1eab8 <eeprom_read_byte>
   1e880:	d8 01       	movw	r26, r16
   1e882:	8d 93       	st	X+, r24
   1e884:	8d 01       	movw	r16, r26
   1e886:	bf ef       	ldi	r27, 0xFF	; 255
   1e888:	8b 16       	cp	r8, r27
   1e88a:	91 04       	cpc	r9, r1
   1e88c:	49 f0       	breq	.+18     	; 0x1e8a0 <AES128_ECB_decrypt+0x78>
   1e88e:	c4 01       	movw	r24, r8
   1e890:	8c 5f       	subi	r24, 0xFC	; 252
   1e892:	9f 4f       	sbci	r25, 0xFF	; 255
   1e894:	0e 94 5c f5 	call	0x1eab8	; 0x1eab8 <eeprom_read_byte>
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
   1e8ac:	e1 f6       	brne	.-72     	; 0x1e866 <AES128_ECB_decrypt+0x3e>
   1e8ae:	d0 92 01 01 	sts	0x0101, r13
   1e8b2:	c0 92 00 01 	sts	0x0100, r12
   1e8b6:	0e 94 91 f2 	call	0x1e522	; 0x1e522 <KeyExpansion>
   1e8ba:	8a e0       	ldi	r24, 0x0A	; 10
   1e8bc:	0e 94 f5 f1 	call	0x1e3ea	; 0x1e3ea <AddRoundKey>
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
   1e8d4:	0e 94 5d f2 	call	0x1e4ba	; 0x1e4ba <InvShiftRows>
   1e8d8:	0e 94 46 f2 	call	0x1e48c	; 0x1e48c <InvSubBytes>
   1e8dc:	82 2d       	mov	r24, r2
   1e8de:	0e 94 f5 f1 	call	0x1e3ea	; 0x1e3ea <AddRoundKey>
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
   1e906:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e90a:	38 2f       	mov	r19, r24
   1e90c:	3b 87       	std	Y+11, r19	; 0x0b
   1e90e:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e912:	f8 2e       	mov	r15, r24
   1e914:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e918:	58 2f       	mov	r21, r24
   1e91a:	6c 85       	ldd	r22, Y+12	; 0x0c
   1e91c:	86 2f       	mov	r24, r22
   1e91e:	5a 87       	std	Y+10, r21	; 0x0a
   1e920:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e924:	8d 87       	std	Y+13, r24	; 0x0d
   1e926:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e92a:	28 2f       	mov	r18, r24
   1e92c:	29 87       	std	Y+9, r18	; 0x09
   1e92e:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e932:	68 2e       	mov	r6, r24
   1e934:	8e 2d       	mov	r24, r14
   1e936:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e93a:	48 2f       	mov	r20, r24
   1e93c:	48 87       	std	Y+8, r20	; 0x08
   1e93e:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e942:	8e 87       	std	Y+14, r24	; 0x0e
   1e944:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e948:	78 2e       	mov	r7, r24
   1e94a:	80 2f       	mov	r24, r16
   1e94c:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e950:	98 2f       	mov	r25, r24
   1e952:	9f 83       	std	Y+7, r25	; 0x07
   1e954:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
   1e958:	38 2e       	mov	r3, r24
   1e95a:	0e 94 3b f2 	call	0x1e476	; 0x1e476 <xtime>
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
   1e9e8:	09 f0       	breq	.+2      	; 0x1e9ec <AES128_ECB_decrypt+0x1c4>
   1e9ea:	7e cf       	rjmp	.-260    	; 0x1e8e8 <AES128_ECB_decrypt+0xc0>
   1e9ec:	2a 94       	dec	r2
   1e9ee:	21 10       	cpse	r2, r1
   1e9f0:	71 cf       	rjmp	.-286    	; 0x1e8d4 <AES128_ECB_decrypt+0xac>
   1e9f2:	0e 94 5d f2 	call	0x1e4ba	; 0x1e4ba <InvShiftRows>
   1e9f6:	0e 94 46 f2 	call	0x1e48c	; 0x1e48c <InvSubBytes>
   1e9fa:	80 e0       	ldi	r24, 0x00	; 0
   1e9fc:	0e 94 f5 f1 	call	0x1e3ea	; 0x1e3ea <AddRoundKey>
   1ea00:	2e 96       	adiw	r28, 0x0e	; 14
   1ea02:	e2 e1       	ldi	r30, 0x12	; 18
   1ea04:	0c 94 41 f5 	jmp	0x1ea82	; 0x1ea82 <__epilogue_restores__>

0001ea08 <main>:
   1ea08:	0e 94 10 f0 	call	0x1e020	; 0x1e020 <UART1_init>
   1ea0c:	0e 94 4b f0 	call	0x1e096	; 0x1e096 <UART0_init>
   1ea10:	a8 95       	wdr
   1ea12:	84 b1       	in	r24, 0x04	; 4
   1ea14:	83 7f       	andi	r24, 0xF3	; 243
   1ea16:	84 b9       	out	0x04, r24	; 4
   1ea18:	85 b1       	in	r24, 0x05	; 5
   1ea1a:	8c 60       	ori	r24, 0x0C	; 12
   1ea1c:	85 b9       	out	0x05, r24	; 5
   1ea1e:	1a 99       	sbic	0x03, 2	; 3
   1ea20:	05 c0       	rjmp	.+10     	; 0x1ea2c <main+0x24>
   1ea22:	85 e5       	ldi	r24, 0x55	; 85
   1ea24:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1ea28:	0e 94 8f f1 	call	0x1e31e	; 0x1e31e <load_firmware>
   1ea2c:	1b 99       	sbic	0x03, 3	; 3
   1ea2e:	05 c0       	rjmp	.+10     	; 0x1ea3a <main+0x32>
   1ea30:	82 e5       	ldi	r24, 0x52	; 82
   1ea32:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1ea36:	0e 94 c4 f0 	call	0x1e188	; 0x1e188 <readback>
   1ea3a:	82 e4       	ldi	r24, 0x42	; 66
   1ea3c:	0e 94 21 f0 	call	0x1e042	; 0x1e042 <UART1_putchar>
   1ea40:	0e 94 86 f0 	call	0x1e10c	; 0x1e10c <boot_firmware>
   1ea44:	80 e0       	ldi	r24, 0x00	; 0
   1ea46:	90 e0       	ldi	r25, 0x00	; 0
   1ea48:	08 95       	ret

0001ea4a <__prologue_saves__>:
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

0001ea82 <__epilogue_restores__>:
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

0001eab8 <eeprom_read_byte>:
   1eab8:	f9 99       	sbic	0x1f, 1	; 31
   1eaba:	fe cf       	rjmp	.-4      	; 0x1eab8 <eeprom_read_byte>
   1eabc:	92 bd       	out	0x22, r25	; 34
   1eabe:	81 bd       	out	0x21, r24	; 33
   1eac0:	f8 9a       	sbi	0x1f, 0	; 31
   1eac2:	99 27       	eor	r25, r25
   1eac4:	80 b5       	in	r24, 0x20	; 32
   1eac6:	08 95       	ret

0001eac8 <eeprom_read_word>:
   1eac8:	a8 e1       	ldi	r26, 0x18	; 24
   1eaca:	b0 e0       	ldi	r27, 0x00	; 0
   1eacc:	42 e0       	ldi	r20, 0x02	; 2
   1eace:	50 e0       	ldi	r21, 0x00	; 0
   1ead0:	0c 94 72 f5 	jmp	0x1eae4	; 0x1eae4 <eeprom_read_blraw>

0001ead4 <eeprom_update_word>:
   1ead4:	01 96       	adiw	r24, 0x01	; 1
   1ead6:	27 2f       	mov	r18, r23
   1ead8:	0e 94 81 f5 	call	0x1eb02	; 0x1eb02 <eeprom_update_r18>
   1eadc:	0c 94 80 f5 	jmp	0x1eb00	; 0x1eb00 <eeprom_update_byte>

0001eae0 <eeprom_read_block>:
   1eae0:	dc 01       	movw	r26, r24
   1eae2:	cb 01       	movw	r24, r22

0001eae4 <eeprom_read_blraw>:
   1eae4:	fc 01       	movw	r30, r24
   1eae6:	f9 99       	sbic	0x1f, 1	; 31
   1eae8:	fe cf       	rjmp	.-4      	; 0x1eae6 <eeprom_read_blraw+0x2>
   1eaea:	06 c0       	rjmp	.+12     	; 0x1eaf8 <eeprom_read_blraw+0x14>
   1eaec:	f2 bd       	out	0x22, r31	; 34
   1eaee:	e1 bd       	out	0x21, r30	; 33
   1eaf0:	f8 9a       	sbi	0x1f, 0	; 31
   1eaf2:	31 96       	adiw	r30, 0x01	; 1
   1eaf4:	00 b4       	in	r0, 0x20	; 32
   1eaf6:	0d 92       	st	X+, r0
   1eaf8:	41 50       	subi	r20, 0x01	; 1
   1eafa:	50 40       	sbci	r21, 0x00	; 0
   1eafc:	b8 f7       	brcc	.-18     	; 0x1eaec <eeprom_read_blraw+0x8>
   1eafe:	08 95       	ret

0001eb00 <eeprom_update_byte>:
   1eb00:	26 2f       	mov	r18, r22

0001eb02 <eeprom_update_r18>:
   1eb02:	f9 99       	sbic	0x1f, 1	; 31
   1eb04:	fe cf       	rjmp	.-4      	; 0x1eb02 <eeprom_update_r18>
   1eb06:	92 bd       	out	0x22, r25	; 34
   1eb08:	81 bd       	out	0x21, r24	; 33
   1eb0a:	f8 9a       	sbi	0x1f, 0	; 31
   1eb0c:	01 97       	sbiw	r24, 0x01	; 1
   1eb0e:	00 b4       	in	r0, 0x20	; 32
   1eb10:	02 16       	cp	r0, r18
   1eb12:	39 f0       	breq	.+14     	; 0x1eb22 <eeprom_update_r18+0x20>
   1eb14:	1f ba       	out	0x1f, r1	; 31
   1eb16:	20 bd       	out	0x20, r18	; 32
   1eb18:	0f b6       	in	r0, 0x3f	; 63
   1eb1a:	f8 94       	cli
   1eb1c:	fa 9a       	sbi	0x1f, 2	; 31
   1eb1e:	f9 9a       	sbi	0x1f, 1	; 31
   1eb20:	0f be       	out	0x3f, r0	; 63
   1eb22:	08 95       	ret

Disassembly of section .bss:

00800100 <__bss_start>:
	...

00800102 <RoundKey>:
	...

008001b2 <state>:
	...

008001b4 <sbox>:
	...

008002b4 <Rcon>:
	...

008003b3 <rsbox>:
	...

Disassembly of section .eeprom:

00810000 <fw_version>:
	...

00810002 <fw_size>:
	...

00810004 <rcon>:
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
  810020:	ef c5       	rjmp	.+3038   	; 0x810c00 <__eeprom_end+0x8fd>
  810022:	91 39       	cpi	r25, 0x91	; 145
  810024:	72 e4       	ldi	r23, 0x42	; 66
  810026:	d3 bd       	out	0x23, r29	; 35
  810028:	61 c2       	rjmp	.+1218   	; 0x8104ec <__eeprom_end+0x1e9>
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
  810042:	6c d8       	rcall	.-3880   	; 0x80f11c <__bss_end+0xec69>
  810044:	ab 4d       	sbci	r26, 0xDB	; 219
  810046:	9a 2f       	mov	r25, r26
  810048:	5e bc       	out	0x2e, r5	; 46
  81004a:	63 c6       	rjmp	.+3270   	; 0x810d12 <__eeprom_end+0xa0f>
  81004c:	97 35       	cpi	r25, 0x57	; 87
  81004e:	6a d4       	rcall	.+2260   	; 0x810924 <__eeprom_end+0x621>
  810050:	b3 7d       	andi	r27, 0xD3	; 211
  810052:	fa ef       	ldi	r31, 0xFA	; 250
  810054:	c5 91       	lpm	r28, Z+
  810056:	39 72       	andi	r19, 0x29	; 41
  810058:	e4 d3       	rcall	.+1992   	; 0x810822 <__eeprom_end+0x51f>
  81005a:	bd 61       	ori	r27, 0x1D	; 29
  81005c:	c2 9f       	mul	r28, r18
  81005e:	25 4a       	sbci	r18, 0xA5	; 165
  810060:	94 33       	cpi	r25, 0x34	; 52
  810062:	66 cc       	rjmp	.-1844   	; 0x80f930 <__bss_end+0xf47d>
  810064:	83 1d       	adc	r24, r3
  810066:	3a 74       	andi	r19, 0x4A	; 74
  810068:	e8 cb       	rjmp	.-2096   	; 0x80f83a <__bss_end+0xf387>
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
  810086:	ef c5       	rjmp	.+3038   	; 0x810c66 <__eeprom_end+0x963>
  810088:	91 39       	cpi	r25, 0x91	; 145
  81008a:	72 e4       	ldi	r23, 0x42	; 66
  81008c:	d3 bd       	out	0x23, r29	; 35
  81008e:	61 c2       	rjmp	.+1218   	; 0x810552 <__eeprom_end+0x24f>
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
  8100a8:	6c d8       	rcall	.-3880   	; 0x80f182 <__bss_end+0xeccf>
  8100aa:	ab 4d       	sbci	r26, 0xDB	; 219
  8100ac:	9a 2f       	mov	r25, r26
  8100ae:	5e bc       	out	0x2e, r5	; 46
  8100b0:	63 c6       	rjmp	.+3270   	; 0x810d78 <__eeprom_end+0xa75>
  8100b2:	97 35       	cpi	r25, 0x57	; 87
  8100b4:	6a d4       	rcall	.+2260   	; 0x81098a <__eeprom_end+0x687>
  8100b6:	b3 7d       	andi	r27, 0xD3	; 211
  8100b8:	fa ef       	ldi	r31, 0xFA	; 250
  8100ba:	c5 91       	lpm	r28, Z+
  8100bc:	39 72       	andi	r19, 0x29	; 41
  8100be:	e4 d3       	rcall	.+1992   	; 0x810888 <__eeprom_end+0x585>
  8100c0:	bd 61       	ori	r27, 0x1D	; 29
  8100c2:	c2 9f       	mul	r28, r18
  8100c4:	25 4a       	sbci	r18, 0xA5	; 165
  8100c6:	94 33       	cpi	r25, 0x34	; 52
  8100c8:	66 cc       	rjmp	.-1844   	; 0x80f996 <__bss_end+0xf4e3>
  8100ca:	83 1d       	adc	r24, r3
  8100cc:	3a 74       	andi	r19, 0x4A	; 74
  8100ce:	e8 cb       	rjmp	.-2096   	; 0x80f8a0 <__bss_end+0xf3ed>
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
  8100ec:	ef c5       	rjmp	.+3038   	; 0x810ccc <__eeprom_end+0x9c9>
  8100ee:	91 39       	cpi	r25, 0x91	; 145
  8100f0:	72 e4       	ldi	r23, 0x42	; 66
  8100f2:	d3 bd       	out	0x23, r29	; 35
  8100f4:	61 c2       	rjmp	.+1218   	; 0x8105b8 <__eeprom_end+0x2b5>
  8100f6:	9f 25       	eor	r25, r15
  8100f8:	4a 94       	dec	r4
  8100fa:	33 66       	ori	r19, 0x63	; 99
  8100fc:	cc 83       	std	Y+4, r28	; 0x04
  8100fe:	1d 3a       	cpi	r17, 0xAD	; 173
  810100:	74 e8       	ldi	r23, 0x84	; 132
  810102:	cb 52       	subi	r28, 0x2B	; 43

00810103 <Rsbox>:
  810103:	52 09       	sbc	r21, r2
  810105:	6a d5       	rcall	.+2772   	; 0x810bdb <__eeprom_end+0x8d8>
  810107:	30 36       	cpi	r19, 0x60	; 96
  810109:	a5 38       	cpi	r26, 0x85	; 133
  81010b:	bf 40       	sbci	r27, 0x0F	; 15
  81010d:	a3 9e       	mul	r10, r19
  81010f:	81 f3       	breq	.-32     	; 0x8100f1 <rcon+0xed>
  810111:	d7 fb       	bst	r29, 7
  810113:	7c e3       	ldi	r23, 0x3C	; 60
  810115:	39 82       	std	Y+1, r3	; 0x01
  810117:	9b 2f       	mov	r25, r27
  810119:	ff 87       	std	Y+15, r31	; 0x0f
  81011b:	34 8e       	std	Z+28, r3	; 0x1c
  81011d:	43 44       	sbci	r20, 0x43	; 67
  81011f:	c4 de       	rcall	.-632    	; 0x80fea9 <__bss_end+0xf9f6>
  810121:	e9 cb       	rjmp	.-2094   	; 0x80f8f5 <__bss_end+0xf442>
  810123:	54 7b       	andi	r21, 0xB4	; 180
  810125:	94 32       	cpi	r25, 0x24	; 36
  810127:	a6 c2       	rjmp	.+1356   	; 0x810675 <__eeprom_end+0x372>
  810129:	23 3d       	cpi	r18, 0xD3	; 211
  81012b:	ee 4c       	sbci	r30, 0xCE	; 206
  81012d:	95 0b       	sbc	r25, r21
  81012f:	42 fa       	bst	r4, 2
  810131:	c3 4e       	sbci	r28, 0xE3	; 227
  810133:	08 2e       	mov	r0, r24
  810135:	a1 66       	ori	r26, 0x61	; 97
  810137:	28 d9       	rcall	.-3504   	; 0x80f389 <__bss_end+0xeed6>
  810139:	24 b2       	in	r2, 0x14	; 20
  81013b:	76 5b       	subi	r23, 0xB6	; 182
  81013d:	a2 49       	sbci	r26, 0x92	; 146
  81013f:	6d 8b       	std	Y+21, r22	; 0x15
  810141:	d1 25       	eor	r29, r1
  810143:	72 f8       	bld	r7, 2
  810145:	f6 64       	ori	r31, 0x46	; 70
  810147:	86 68       	ori	r24, 0x86	; 134
  810149:	98 16       	cp	r9, r24
  81014b:	d4 a4       	ldd	r13, Z+44	; 0x2c
  81014d:	5c cc       	rjmp	.-1864   	; 0x80fa07 <__bss_end+0xf554>
  81014f:	5d 65       	ori	r21, 0x5D	; 93
  810151:	b6 92       	lac	Z, r11
  810153:	6c 70       	andi	r22, 0x0C	; 12
  810155:	48 50       	subi	r20, 0x08	; 8
  810157:	fd ed       	ldi	r31, 0xDD	; 221
  810159:	b9 da       	rcall	.-2702   	; 0x80f6cd <__bss_end+0xf21a>
  81015b:	5e 15       	cp	r21, r14
  81015d:	46 57       	subi	r20, 0x76	; 118
  81015f:	a7 8d       	ldd	r26, Z+31	; 0x1f
  810161:	9d 84       	ldd	r9, Y+13	; 0x0d
  810163:	90 d8       	rcall	.-3808   	; 0x80f285 <__bss_end+0xedd2>
  810165:	ab 00       	.word	0x00ab	; ????
  810167:	8c bc       	out	0x2c, r8	; 44
  810169:	d3 0a       	sbc	r13, r19
  81016b:	f7 e4       	ldi	r31, 0x47	; 71
  81016d:	58 05       	cpc	r21, r8
  81016f:	b8 b3       	in	r27, 0x18	; 24
  810171:	45 06       	cpc	r4, r21
  810173:	d0 2c       	mov	r13, r0
  810175:	1e 8f       	std	Y+30, r17	; 0x1e
  810177:	ca 3f       	cpi	r28, 0xFA	; 250
  810179:	0f 02       	muls	r16, r31
  81017b:	c1 af       	std	Z+57, r28	; 0x39
  81017d:	bd 03       	fmulsu	r19, r21
  81017f:	01 13       	cpse	r16, r17
  810181:	8a 6b       	ori	r24, 0xBA	; 186
  810183:	3a 91       	ld	r19, -Y
  810185:	11 41       	sbci	r17, 0x11	; 17
  810187:	4f 67       	ori	r20, 0x7F	; 127
  810189:	dc ea       	ldi	r29, 0xAC	; 172
  81018b:	97 f2       	brie	.-92     	; 0x810131 <Rsbox+0x2e>
  81018d:	cf ce       	rjmp	.-610    	; 0x80ff2d <__bss_end+0xfa7a>
  81018f:	f0 b4       	in	r15, 0x20	; 32
  810191:	e6 73       	andi	r30, 0x36	; 54
  810193:	96 ac       	ldd	r9, Z+62	; 0x3e
  810195:	74 22       	and	r7, r20
  810197:	e7 ad       	ldd	r30, Z+63	; 0x3f
  810199:	35 85       	ldd	r19, Z+13	; 0x0d
  81019b:	e2 f9       	bld	r30, 2
  81019d:	37 e8       	ldi	r19, 0x87	; 135
  81019f:	1c 75       	andi	r17, 0x5C	; 92
  8101a1:	df 6e       	ori	r29, 0xEF	; 239
  8101a3:	47 f1       	brie	.+80     	; 0x8101f5 <Rsbox+0xf2>
  8101a5:	1a 71       	andi	r17, 0x1A	; 26
  8101a7:	1d 29       	or	r17, r13
  8101a9:	c5 89       	ldd	r28, Z+21	; 0x15
  8101ab:	6f b7       	in	r22, 0x3f	; 63
  8101ad:	62 0e       	add	r6, r18
  8101af:	aa 18       	sub	r10, r10
  8101b1:	be 1b       	sub	r27, r30
  8101b3:	fc 56       	subi	r31, 0x6C	; 108
  8101b5:	3e 4b       	sbci	r19, 0xBE	; 190
  8101b7:	c6 d2       	rcall	.+1420   	; 0x810745 <__eeprom_end+0x442>
  8101b9:	79 20       	and	r7, r9
  8101bb:	9a db       	rcall	.-2252   	; 0x80f8f1 <__bss_end+0xf43e>
  8101bd:	c0 fe       	sbrs	r12, 0
  8101bf:	78 cd       	rjmp	.-1296   	; 0x80fcb1 <__bss_end+0xf7fe>
  8101c1:	5a f4       	brpl	.+22     	; 0x8101d9 <Rsbox+0xd6>
  8101c3:	1f dd       	rcall	.-1474   	; 0x80fc03 <__bss_end+0xf750>
  8101c5:	a8 33       	cpi	r26, 0x38	; 56
  8101c7:	88 07       	cpc	r24, r24
  8101c9:	c7 31       	cpi	r28, 0x17	; 23
  8101cb:	b1 12       	cpse	r11, r17
  8101cd:	10 59       	subi	r17, 0x90	; 144
  8101cf:	27 80       	ldd	r2, Z+7	; 0x07
  8101d1:	ec 5f       	subi	r30, 0xFC	; 252
  8101d3:	60 51       	subi	r22, 0x10	; 16
  8101d5:	7f a9       	ldd	r23, Y+55	; 0x37
  8101d7:	19 b5       	in	r17, 0x29	; 41
  8101d9:	4a 0d       	add	r20, r10
  8101db:	2d e5       	ldi	r18, 0x5D	; 93
  8101dd:	7a 9f       	mul	r23, r26
  8101df:	93 c9       	rjmp	.-3290   	; 0x80f507 <__bss_end+0xf054>
  8101e1:	9c ef       	ldi	r25, 0xFC	; 252
  8101e3:	a0 e0       	ldi	r26, 0x00	; 0
  8101e5:	3b 4d       	sbci	r19, 0xDB	; 219
  8101e7:	ae 2a       	or	r10, r30
  8101e9:	f5 b0       	in	r15, 0x05	; 5
  8101eb:	c8 eb       	ldi	r28, 0xB8	; 184
  8101ed:	bb 3c       	cpi	r27, 0xCB	; 203
  8101ef:	83 53       	subi	r24, 0x33	; 51
  8101f1:	99 61       	ori	r25, 0x19	; 25
  8101f3:	17 2b       	or	r17, r23
  8101f5:	04 7e       	andi	r16, 0xE4	; 228
  8101f7:	ba 77       	andi	r27, 0x7A	; 122
  8101f9:	d6 26       	eor	r13, r22
  8101fb:	e1 69       	ori	r30, 0x91	; 145
  8101fd:	14 63       	ori	r17, 0x34	; 52
  8101ff:	55 21       	and	r21, r5
  810201:	0c 7d       	andi	r16, 0xDC	; 220

00810203 <Sbox>:
  810203:	63 7c       	andi	r22, 0xC3	; 195
  810205:	77 7b       	andi	r23, 0xB7	; 183
  810207:	f2 6b       	ori	r31, 0xB2	; 178
  810209:	6f c5       	rjmp	.+2782   	; 0x810ce9 <__eeprom_end+0x9e6>
  81020b:	30 01       	movw	r6, r0
  81020d:	67 2b       	or	r22, r23
  81020f:	fe d7       	rcall	.+4092   	; 0x81120d <__eeprom_end+0xf0a>
  810211:	ab 76       	andi	r26, 0x6B	; 107
  810213:	ca 82       	std	Y+2, r12	; 0x02
  810215:	c9 7d       	andi	r28, 0xD9	; 217
  810217:	fa 59       	subi	r31, 0x9A	; 154
  810219:	47 f0       	brie	.+16     	; 0x81022b <Sbox+0x28>
  81021b:	ad d4       	rcall	.+2394   	; 0x810b77 <__eeprom_end+0x874>
  81021d:	a2 af       	std	Z+58, r26	; 0x3a
  81021f:	9c a4       	ldd	r9, Y+44	; 0x2c
  810221:	72 c0       	rjmp	.+228    	; 0x810307 <__eeprom_end+0x4>
  810223:	b7 fd       	sbrc	r27, 7
  810225:	93 26       	eor	r9, r19
  810227:	36 3f       	cpi	r19, 0xF6	; 246
  810229:	f7 cc       	rjmp	.-1554   	; 0x80fc19 <__bss_end+0xf766>
  81022b:	34 a5       	ldd	r19, Z+44	; 0x2c
  81022d:	e5 f1       	brhs	.+120    	; 0x8102a7 <Sbox+0xa4>
  81022f:	71 d8       	rcall	.-3870   	; 0x80f313 <__bss_end+0xee60>
  810231:	31 15       	cp	r19, r1
  810233:	04 c7       	rjmp	.+3592   	; 0x81103d <__eeprom_end+0xd3a>
  810235:	23 c3       	rjmp	.+1606   	; 0x81087d <__eeprom_end+0x57a>
  810237:	18 96       	adiw	r26, 0x08	; 8
  810239:	05 9a       	sbi	0x00, 5	; 0
  81023b:	07 12       	cpse	r0, r23
  81023d:	80 e2       	ldi	r24, 0x20	; 32
  81023f:	eb 27       	eor	r30, r27
  810241:	b2 75       	andi	r27, 0x52	; 82
  810243:	09 83       	std	Y+1, r16	; 0x01
  810245:	2c 1a       	sub	r2, r28
  810247:	1b 6e       	ori	r17, 0xEB	; 235
  810249:	5a a0       	ldd	r5, Y+34	; 0x22
  81024b:	52 3b       	cpi	r21, 0xB2	; 178
  81024d:	d6 b3       	in	r29, 0x16	; 22
  81024f:	29 e3       	ldi	r18, 0x39	; 57
  810251:	2f 84       	ldd	r2, Y+15	; 0x0f
  810253:	53 d1       	rcall	.+678    	; 0x8104fb <__eeprom_end+0x1f8>
  810255:	00 ed       	ldi	r16, 0xD0	; 208
  810257:	20 fc       	sbrc	r2, 0
  810259:	b1 5b       	subi	r27, 0xB1	; 177
  81025b:	6a cb       	rjmp	.-2348   	; 0x80f931 <__bss_end+0xf47e>
  81025d:	be 39       	cpi	r27, 0x9E	; 158
  81025f:	4a 4c       	sbci	r20, 0xCA	; 202
  810261:	58 cf       	rjmp	.-336    	; 0x810113 <Rsbox+0x10>
  810263:	d0 ef       	ldi	r29, 0xF0	; 240
  810265:	aa fb       	.word	0xfbaa	; ????
  810267:	43 4d       	sbci	r20, 0xD3	; 211
  810269:	33 85       	ldd	r19, Z+11	; 0x0b
  81026b:	45 f9       	bld	r20, 5
  81026d:	02 7f       	andi	r16, 0xF2	; 242
  81026f:	50 3c       	cpi	r21, 0xC0	; 192
  810271:	9f a8       	ldd	r9, Y+55	; 0x37
  810273:	51 a3       	std	Z+33, r21	; 0x21
  810275:	40 8f       	std	Z+24, r20	; 0x18
  810277:	92 9d       	mul	r25, r2
  810279:	38 f5       	brcc	.+78     	; 0x8102c9 <Sbox+0xc6>
  81027b:	bc b6       	in	r11, 0x3c	; 60
  81027d:	da 21       	and	r29, r10
  81027f:	10 ff       	sbrs	r17, 0
  810281:	f3 d2       	rcall	.+1510   	; 0x810869 <__eeprom_end+0x566>
  810283:	cd 0c       	add	r12, r13
  810285:	13 ec       	ldi	r17, 0xC3	; 195
  810287:	5f 97       	sbiw	r26, 0x1f	; 31
  810289:	44 17       	cp	r20, r20
  81028b:	c4 a7       	std	Z+44, r28	; 0x2c
  81028d:	7e 3d       	cpi	r23, 0xDE	; 222
  81028f:	64 5d       	subi	r22, 0xD4	; 212
  810291:	19 73       	andi	r17, 0x39	; 57
  810293:	60 81       	ld	r22, Z
  810295:	4f dc       	rcall	.-1890   	; 0x80fb35 <__bss_end+0xf682>
  810297:	22 2a       	or	r2, r18
  810299:	90 88       	ldd	r9, Z+16	; 0x10
  81029b:	46 ee       	ldi	r20, 0xE6	; 230
  81029d:	b8 14       	cp	r11, r8
  81029f:	de 5e       	subi	r29, 0xEE	; 238
  8102a1:	0b db       	rcall	.-2538   	; 0x80f8b9 <__bss_end+0xf406>
  8102a3:	e0 32       	cpi	r30, 0x20	; 32
  8102a5:	3a 0a       	sbc	r3, r26
  8102a7:	49 06       	cpc	r4, r25
  8102a9:	24 5c       	subi	r18, 0xC4	; 196
  8102ab:	c2 d3       	rcall	.+1924   	; 0x810a31 <__eeprom_end+0x72e>
  8102ad:	ac 62       	ori	r26, 0x2C	; 44
  8102af:	91 95       	neg	r25
  8102b1:	e4 79       	andi	r30, 0x94	; 148
  8102b3:	e7 c8       	rjmp	.-3634   	; 0x80f483 <__bss_end+0xefd0>
  8102b5:	37 6d       	ori	r19, 0xD7	; 215
  8102b7:	8d d5       	rcall	.+2842   	; 0x810dd3 <__eeprom_end+0xad0>
  8102b9:	4e a9       	ldd	r20, Y+54	; 0x36
  8102bb:	6c 56       	subi	r22, 0x6C	; 108
  8102bd:	f4 ea       	ldi	r31, 0xA4	; 164
  8102bf:	65 7a       	andi	r22, 0xA5	; 165
  8102c1:	ae 08       	sbc	r10, r14
  8102c3:	ba 78       	andi	r27, 0x8A	; 138
  8102c5:	25 2e       	mov	r2, r21
  8102c7:	1c a6       	std	Y+44, r1	; 0x2c
  8102c9:	b4 c6       	rjmp	.+3432   	; 0x811033 <__eeprom_end+0xd30>
  8102cb:	e8 dd       	rcall	.-1072   	; 0x80fe9d <__bss_end+0xf9ea>
  8102cd:	74 1f       	adc	r23, r20
  8102cf:	4b bd       	out	0x2b, r20	; 43
  8102d1:	8b 8a       	std	Y+19, r8	; 0x13
  8102d3:	70 3e       	cpi	r23, 0xE0	; 224
  8102d5:	b5 66       	ori	r27, 0x65	; 101
  8102d7:	48 03       	fmul	r20, r16
  8102d9:	f6 0e       	add	r15, r22
  8102db:	61 35       	cpi	r22, 0x51	; 81
  8102dd:	57 b9       	out	0x07, r21	; 7
  8102df:	86 c1       	rjmp	.+780    	; 0x8105ed <__eeprom_end+0x2ea>
  8102e1:	1d 9e       	mul	r1, r29
  8102e3:	e1 f8       	bld	r14, 1
  8102e5:	98 11       	cpse	r25, r8
  8102e7:	69 d9       	rcall	.-3374   	; 0x80f5bb <__bss_end+0xf108>
  8102e9:	8e 94 9b 1e 	call	0x203d36	; 0x203d36 <__data_load_end+0x1e5212>
  8102ed:	87 e9       	ldi	r24, 0x97	; 151
  8102ef:	ce 55       	subi	r28, 0x5E	; 94
  8102f1:	28 df       	rcall	.-432    	; 0x810143 <Rsbox+0x40>
  8102f3:	8c a1       	ldd	r24, Y+36	; 0x24
  8102f5:	89 0d       	add	r24, r9
  8102f7:	bf e6       	ldi	r27, 0x6F	; 111
  8102f9:	42 68       	ori	r20, 0x82	; 130
  8102fb:	41 99       	sbic	0x08, 1	; 8
  8102fd:	2d 0f       	add	r18, r29
  8102ff:	b0 54       	subi	r27, 0x40	; 64
  810301:	bb 16       	cp	r11, r27

Disassembly of section .stab:

00000000 <.stab>:
       0:	01 00       	.word	0x0001	; ????
       2:	00 00       	nop
       4:	00 00       	nop
       6:	34 03       	mulsu	r19, r20
       8:	bf 13       	cpse	r27, r31
       a:	00 00       	nop
       c:	08 00       	.word	0x0008	; ????
       e:	00 00       	nop
      10:	64 00       	.word	0x0064	; ????
      12:	02 00       	.word	0x0002	; ????
      14:	20 e0       	ldi	r18, 0x00	; 0
      16:	01 00       	.word	0x0001	; ????
      18:	28 00       	.word	0x0028	; ????
      1a:	00 00       	nop
      1c:	64 00       	.word	0x0064	; ????
      1e:	02 00       	.word	0x0002	; ????
      20:	20 e0       	ldi	r18, 0x00	; 0
      22:	01 00       	.word	0x0001	; ????
      24:	33 00       	.word	0x0033	; ????
      26:	00 00       	nop
      28:	3c 00       	.word	0x003c	; ????
      2a:	00 00       	nop
      2c:	00 00       	nop
      2e:	00 00       	nop
      30:	42 00       	.word	0x0042	; ????
      32:	00 00       	nop
      34:	80 00       	.word	0x0080	; ????
      36:	00 00       	nop
      38:	00 00       	nop
      3a:	00 00       	nop
      3c:	62 00       	.word	0x0062	; ????
      3e:	00 00       	nop
      40:	80 00       	.word	0x0080	; ????
      42:	00 00       	nop
      44:	00 00       	nop
      46:	00 00       	nop
      48:	7c 00       	.word	0x007c	; ????
      4a:	00 00       	nop
      4c:	80 00       	.word	0x0080	; ????
      4e:	00 00       	nop
      50:	00 00       	nop
      52:	00 00       	nop
      54:	b3 00       	.word	0x00b3	; ????
      56:	00 00       	nop
      58:	80 00       	.word	0x0080	; ????
      5a:	00 00       	nop
      5c:	00 00       	nop
      5e:	00 00       	nop
      60:	d9 00       	.word	0x00d9	; ????
      62:	00 00       	nop
      64:	80 00       	.word	0x0080	; ????
      66:	00 00       	nop
      68:	00 00       	nop
      6a:	00 00       	nop
      6c:	0e 01       	movw	r0, r28
      6e:	00 00       	nop
      70:	80 00       	.word	0x0080	; ????
      72:	00 00       	nop
      74:	00 00       	nop
      76:	00 00       	nop
      78:	5f 01       	movw	r10, r30
      7a:	00 00       	nop
      7c:	80 00       	.word	0x0080	; ????
      7e:	00 00       	nop
      80:	00 00       	nop
      82:	00 00       	nop
      84:	a4 01       	movw	r20, r8
      86:	00 00       	nop
      88:	80 00       	.word	0x0080	; ????
      8a:	00 00       	nop
      8c:	00 00       	nop
      8e:	00 00       	nop
      90:	ca 01       	movw	r24, r20
      92:	00 00       	nop
      94:	80 00       	.word	0x0080	; ????
      96:	00 00       	nop
      98:	00 00       	nop
      9a:	00 00       	nop
      9c:	f6 01       	movw	r30, r12
      9e:	00 00       	nop
      a0:	80 00       	.word	0x0080	; ????
      a2:	00 00       	nop
      a4:	00 00       	nop
      a6:	00 00       	nop
      a8:	20 02       	muls	r18, r16
      aa:	00 00       	nop
      ac:	80 00       	.word	0x0080	; ????
      ae:	00 00       	nop
      b0:	00 00       	nop
      b2:	00 00       	nop
      b4:	49 02       	muls	r20, r25
      b6:	00 00       	nop
      b8:	80 00       	.word	0x0080	; ????
      ba:	00 00       	nop
      bc:	00 00       	nop
      be:	00 00       	nop
      c0:	63 02       	muls	r22, r19
      c2:	00 00       	nop
      c4:	80 00       	.word	0x0080	; ????
      c6:	00 00       	nop
      c8:	00 00       	nop
      ca:	00 00       	nop
      cc:	7e 02       	muls	r23, r30
      ce:	00 00       	nop
      d0:	80 00       	.word	0x0080	; ????
      d2:	00 00       	nop
      d4:	00 00       	nop
      d6:	00 00       	nop
      d8:	9e 02       	muls	r25, r30
      da:	00 00       	nop
      dc:	80 00       	.word	0x0080	; ????
      de:	00 00       	nop
      e0:	00 00       	nop
      e2:	00 00       	nop
      e4:	bf 02       	muls	r27, r31
      e6:	00 00       	nop
      e8:	80 00       	.word	0x0080	; ????
      ea:	00 00       	nop
      ec:	00 00       	nop
      ee:	00 00       	nop
      f0:	da 02       	muls	r29, r26
      f2:	00 00       	nop
      f4:	80 00       	.word	0x0080	; ????
      f6:	00 00       	nop
      f8:	00 00       	nop
      fa:	00 00       	nop
      fc:	fa 02       	muls	r31, r26
      fe:	00 00       	nop
     100:	80 00       	.word	0x0080	; ????
     102:	00 00       	nop
     104:	00 00       	nop
     106:	00 00       	nop
     108:	1f 03       	fmul	r17, r23
     10a:	00 00       	nop
     10c:	80 00       	.word	0x0080	; ????
     10e:	00 00       	nop
     110:	00 00       	nop
     112:	00 00       	nop
     114:	49 03       	fmul	r20, r17
     116:	00 00       	nop
     118:	80 00       	.word	0x0080	; ????
     11a:	00 00       	nop
     11c:	00 00       	nop
     11e:	00 00       	nop
     120:	6d 03       	fmul	r22, r21
     122:	00 00       	nop
     124:	80 00       	.word	0x0080	; ????
     126:	00 00       	nop
     128:	00 00       	nop
     12a:	00 00       	nop
     12c:	96 03       	fmuls	r17, r22
     12e:	00 00       	nop
     130:	80 00       	.word	0x0080	; ????
     132:	00 00       	nop
     134:	00 00       	nop
     136:	00 00       	nop
     138:	c4 03       	fmuls	r20, r20
     13a:	00 00       	nop
     13c:	80 00       	.word	0x0080	; ????
     13e:	00 00       	nop
     140:	00 00       	nop
     142:	00 00       	nop
     144:	ea 03       	fmulsu	r22, r18
     146:	00 00       	nop
     148:	80 00       	.word	0x0080	; ????
     14a:	00 00       	nop
     14c:	00 00       	nop
     14e:	00 00       	nop
     150:	0a 04       	cpc	r0, r10
     152:	00 00       	nop
     154:	80 00       	.word	0x0080	; ????
     156:	00 00       	nop
     158:	00 00       	nop
     15a:	00 00       	nop
     15c:	2f 04       	cpc	r2, r15
     15e:	00 00       	nop
     160:	80 00       	.word	0x0080	; ????
     162:	00 00       	nop
     164:	00 00       	nop
     166:	00 00       	nop
     168:	59 04       	cpc	r5, r9
     16a:	00 00       	nop
     16c:	80 00       	.word	0x0080	; ????
     16e:	00 00       	nop
     170:	00 00       	nop
     172:	00 00       	nop
     174:	88 04       	cpc	r8, r8
     176:	00 00       	nop
     178:	80 00       	.word	0x0080	; ????
     17a:	00 00       	nop
     17c:	00 00       	nop
     17e:	00 00       	nop
     180:	b1 04       	cpc	r11, r1
     182:	00 00       	nop
     184:	80 00       	.word	0x0080	; ????
     186:	00 00       	nop
     188:	00 00       	nop
     18a:	00 00       	nop
     18c:	df 04       	cpc	r13, r15
     18e:	00 00       	nop
     190:	80 00       	.word	0x0080	; ????
     192:	00 00       	nop
     194:	00 00       	nop
     196:	00 00       	nop
     198:	12 05       	cpc	r17, r2
     19a:	00 00       	nop
     19c:	80 00       	.word	0x0080	; ????
     19e:	00 00       	nop
     1a0:	00 00       	nop
     1a2:	00 00       	nop
     1a4:	33 05       	cpc	r19, r3
     1a6:	00 00       	nop
     1a8:	80 00       	.word	0x0080	; ????
     1aa:	00 00       	nop
     1ac:	00 00       	nop
     1ae:	00 00       	nop
     1b0:	4e 05       	cpc	r20, r14
     1b2:	00 00       	nop
     1b4:	80 00       	.word	0x0080	; ????
     1b6:	00 00       	nop
     1b8:	00 00       	nop
     1ba:	00 00       	nop
     1bc:	6e 05       	cpc	r22, r14
     1be:	00 00       	nop
     1c0:	80 00       	.word	0x0080	; ????
     1c2:	00 00       	nop
     1c4:	00 00       	nop
     1c6:	00 00       	nop
     1c8:	93 05       	cpc	r25, r3
     1ca:	00 00       	nop
     1cc:	80 00       	.word	0x0080	; ????
     1ce:	00 00       	nop
     1d0:	00 00       	nop
     1d2:	00 00       	nop
     1d4:	bd 05       	cpc	r27, r13
     1d6:	00 00       	nop
     1d8:	80 00       	.word	0x0080	; ????
     1da:	00 00       	nop
     1dc:	00 00       	nop
     1de:	00 00       	nop
     1e0:	e1 05       	cpc	r30, r1
     1e2:	00 00       	nop
     1e4:	80 00       	.word	0x0080	; ????
     1e6:	00 00       	nop
     1e8:	00 00       	nop
     1ea:	00 00       	nop
     1ec:	0a 06       	cpc	r0, r26
     1ee:	00 00       	nop
     1f0:	80 00       	.word	0x0080	; ????
     1f2:	00 00       	nop
     1f4:	00 00       	nop
     1f6:	00 00       	nop
     1f8:	38 06       	cpc	r3, r24
     1fa:	00 00       	nop
     1fc:	80 00       	.word	0x0080	; ????
     1fe:	00 00       	nop
     200:	00 00       	nop
     202:	00 00       	nop
     204:	5e 06       	cpc	r5, r30
     206:	00 00       	nop
     208:	80 00       	.word	0x0080	; ????
     20a:	00 00       	nop
     20c:	00 00       	nop
     20e:	00 00       	nop
     210:	7e 06       	cpc	r7, r30
     212:	00 00       	nop
     214:	80 00       	.word	0x0080	; ????
     216:	00 00       	nop
     218:	00 00       	nop
     21a:	00 00       	nop
     21c:	a3 06       	cpc	r10, r19
     21e:	00 00       	nop
     220:	80 00       	.word	0x0080	; ????
     222:	00 00       	nop
     224:	00 00       	nop
     226:	00 00       	nop
     228:	cd 06       	cpc	r12, r29
     22a:	00 00       	nop
     22c:	80 00       	.word	0x0080	; ????
     22e:	00 00       	nop
     230:	00 00       	nop
     232:	00 00       	nop
     234:	fc 06       	cpc	r15, r28
     236:	00 00       	nop
     238:	80 00       	.word	0x0080	; ????
     23a:	00 00       	nop
     23c:	00 00       	nop
     23e:	00 00       	nop
     240:	25 07       	cpc	r18, r21
     242:	00 00       	nop
     244:	80 00       	.word	0x0080	; ????
     246:	00 00       	nop
     248:	00 00       	nop
     24a:	00 00       	nop
     24c:	53 07       	cpc	r21, r19
     24e:	00 00       	nop
     250:	80 00       	.word	0x0080	; ????
     252:	00 00       	nop
     254:	00 00       	nop
     256:	00 00       	nop
     258:	86 07       	cpc	r24, r22
     25a:	00 00       	nop
     25c:	80 00       	.word	0x0080	; ????
     25e:	00 00       	nop
     260:	00 00       	nop
     262:	00 00       	nop
     264:	9a 07       	cpc	r25, r26
     266:	00 00       	nop
     268:	82 00       	.word	0x0082	; ????
     26a:	00 00       	nop
     26c:	00 00       	nop
     26e:	00 00       	nop
     270:	b8 07       	cpc	r27, r24
     272:	00 00       	nop
     274:	82 00       	.word	0x0082	; ????
     276:	00 00       	nop
     278:	00 00       	nop
     27a:	00 00       	nop
     27c:	dc 07       	cpc	r29, r28
     27e:	00 00       	nop
     280:	82 00       	.word	0x0082	; ????
     282:	00 00       	nop
     284:	25 0f       	add	r18, r21
     286:	00 00       	nop
     288:	fc 07       	cpc	r31, r28
     28a:	00 00       	nop
     28c:	82 00       	.word	0x0082	; ????
     28e:	00 00       	nop
     290:	00 00       	nop
     292:	00 00       	nop
     294:	24 08       	sbc	r2, r4
     296:	00 00       	nop
     298:	82 00       	.word	0x0082	; ????
     29a:	00 00       	nop
     29c:	33 b8       	out	0x03, r3	; 3
     29e:	00 00       	nop
     2a0:	42 08       	sbc	r4, r2
     2a2:	00 00       	nop
     2a4:	80 00       	.word	0x0080	; ????
     2a6:	79 00       	.word	0x0079	; ????
     2a8:	00 00       	nop
     2aa:	00 00       	nop
     2ac:	57 08       	sbc	r5, r7
     2ae:	00 00       	nop
     2b0:	80 00       	.word	0x0080	; ????
     2b2:	7a 00       	.word	0x007a	; ????
     2b4:	00 00       	nop
     2b6:	00 00       	nop
     2b8:	6d 08       	sbc	r6, r13
     2ba:	00 00       	nop
     2bc:	80 00       	.word	0x0080	; ????
     2be:	7b 00       	.word	0x007b	; ????
     2c0:	00 00       	nop
     2c2:	00 00       	nop
     2c4:	82 08       	sbc	r8, r2
     2c6:	00 00       	nop
     2c8:	80 00       	.word	0x0080	; ????
     2ca:	7c 00       	.word	0x007c	; ????
     2cc:	00 00       	nop
     2ce:	00 00       	nop
     2d0:	98 08       	sbc	r9, r8
     2d2:	00 00       	nop
     2d4:	80 00       	.word	0x0080	; ????
     2d6:	7d 00       	.word	0x007d	; ????
     2d8:	00 00       	nop
     2da:	00 00       	nop
     2dc:	ad 08       	sbc	r10, r13
     2de:	00 00       	nop
     2e0:	80 00       	.word	0x0080	; ????
     2e2:	7e 00       	.word	0x007e	; ????
     2e4:	00 00       	nop
     2e6:	00 00       	nop
     2e8:	c3 08       	sbc	r12, r3
     2ea:	00 00       	nop
     2ec:	80 00       	.word	0x0080	; ????
     2ee:	80 00       	.word	0x0080	; ????
     2f0:	00 00       	nop
     2f2:	00 00       	nop
     2f4:	d8 08       	sbc	r13, r8
     2f6:	00 00       	nop
     2f8:	80 00       	.word	0x0080	; ????
     2fa:	81 00       	.word	0x0081	; ????
     2fc:	00 00       	nop
     2fe:	00 00       	nop
     300:	ee 08       	sbc	r14, r14
     302:	00 00       	nop
     304:	80 00       	.word	0x0080	; ????
     306:	8e 00       	.word	0x008e	; ????
     308:	00 00       	nop
     30a:	00 00       	nop
     30c:	04 09       	sbc	r16, r4
     30e:	00 00       	nop
     310:	80 00       	.word	0x0080	; ????
     312:	93 00       	.word	0x0093	; ????
     314:	00 00       	nop
     316:	00 00       	nop
     318:	1c 09       	sbc	r17, r12
     31a:	00 00       	nop
     31c:	80 00       	.word	0x0080	; ????
     31e:	9f 00       	.word	0x009f	; ????
     320:	00 00       	nop
     322:	00 00       	nop
     324:	37 09       	sbc	r19, r7
     326:	00 00       	nop
     328:	80 00       	.word	0x0080	; ????
     32a:	a4 00       	.word	0x00a4	; ????
     32c:	00 00       	nop
     32e:	00 00       	nop
     330:	53 09       	sbc	r21, r3
     332:	00 00       	nop
     334:	80 00       	.word	0x0080	; ????
     336:	a9 00       	.word	0x00a9	; ????
     338:	00 00       	nop
     33a:	00 00       	nop
     33c:	6f 09       	sbc	r22, r15
     33e:	00 00       	nop
     340:	80 00       	.word	0x0080	; ????
     342:	ae 00       	.word	0x00ae	; ????
     344:	00 00       	nop
     346:	00 00       	nop
     348:	8c 09       	sbc	r24, r12
     34a:	00 00       	nop
     34c:	80 00       	.word	0x0080	; ????
     34e:	b3 00       	.word	0x00b3	; ????
     350:	00 00       	nop
     352:	00 00       	nop
     354:	a8 09       	sbc	r26, r8
     356:	00 00       	nop
     358:	80 00       	.word	0x0080	; ????
     35a:	b8 00       	.word	0x00b8	; ????
     35c:	00 00       	nop
     35e:	00 00       	nop
     360:	c5 09       	sbc	r28, r5
     362:	00 00       	nop
     364:	80 00       	.word	0x0080	; ????
     366:	c0 00       	.word	0x00c0	; ????
     368:	00 00       	nop
     36a:	00 00       	nop
     36c:	e1 09       	sbc	r30, r1
     36e:	00 00       	nop
     370:	80 00       	.word	0x0080	; ????
     372:	c7 00       	.word	0x00c7	; ????
     374:	00 00       	nop
     376:	00 00       	nop
     378:	fe 09       	sbc	r31, r14
     37a:	00 00       	nop
     37c:	80 00       	.word	0x0080	; ????
     37e:	d5 00       	.word	0x00d5	; ????
     380:	00 00       	nop
     382:	00 00       	nop
     384:	18 0a       	sbc	r1, r24
     386:	00 00       	nop
     388:	80 00       	.word	0x0080	; ????
     38a:	da 00       	.word	0x00da	; ????
     38c:	00 00       	nop
     38e:	00 00       	nop
     390:	33 0a       	sbc	r3, r19
     392:	00 00       	nop
     394:	80 00       	.word	0x0080	; ????
     396:	df 00       	.word	0x00df	; ????
     398:	00 00       	nop
     39a:	00 00       	nop
     39c:	4e 0a       	sbc	r4, r30
     39e:	00 00       	nop
     3a0:	80 00       	.word	0x0080	; ????
     3a2:	e4 00       	.word	0x00e4	; ????
     3a4:	00 00       	nop
     3a6:	00 00       	nop
     3a8:	6a 0a       	sbc	r6, r26
     3aa:	00 00       	nop
     3ac:	80 00       	.word	0x0080	; ????
     3ae:	e9 00       	.word	0x00e9	; ????
     3b0:	00 00       	nop
     3b2:	00 00       	nop
     3b4:	85 0a       	sbc	r8, r21
     3b6:	00 00       	nop
     3b8:	80 00       	.word	0x0080	; ????
     3ba:	ee 00       	.word	0x00ee	; ????
     3bc:	00 00       	nop
     3be:	00 00       	nop
     3c0:	a1 0a       	sbc	r10, r17
     3c2:	00 00       	nop
     3c4:	80 00       	.word	0x0080	; ????
     3c6:	f6 00       	.word	0x00f6	; ????
     3c8:	00 00       	nop
     3ca:	00 00       	nop
     3cc:	bc 0a       	sbc	r11, r28
     3ce:	00 00       	nop
     3d0:	80 00       	.word	0x0080	; ????
     3d2:	fd 00       	.word	0x00fd	; ????
     3d4:	00 00       	nop
     3d6:	00 00       	nop
     3d8:	d8 0a       	sbc	r13, r24
     3da:	00 00       	nop
     3dc:	80 00       	.word	0x0080	; ????
     3de:	11 01       	movw	r2, r2
     3e0:	00 00       	nop
     3e2:	00 00       	nop
     3e4:	ef 0a       	sbc	r14, r31
     3e6:	00 00       	nop
     3e8:	80 00       	.word	0x0080	; ????
     3ea:	16 01       	movw	r2, r12
	...
     3f4:	a2 00       	.word	0x00a2	; ????
	...
     3fe:	00 00       	nop
     400:	a2 00       	.word	0x00a2	; ????
     402:	00 00       	nop
     404:	00 00       	nop
     406:	00 00       	nop
     408:	07 0b       	sbc	r16, r23
     40a:	00 00       	nop
     40c:	80 00       	.word	0x0080	; ????
     40e:	4d 00       	.word	0x004d	; ????
     410:	00 00       	nop
     412:	00 00       	nop
     414:	21 0b       	sbc	r18, r17
     416:	00 00       	nop
     418:	80 00       	.word	0x0080	; ????
     41a:	51 00       	.word	0x0051	; ????
	...
     424:	a2 00       	.word	0x00a2	; ????
	...
     42e:	00 00       	nop
     430:	a2 00       	.word	0x00a2	; ????
     432:	00 00       	nop
     434:	00 00       	nop
     436:	00 00       	nop
     438:	3c 0b       	sbc	r19, r28
     43a:	00 00       	nop
     43c:	82 00       	.word	0x0082	; ????
     43e:	00 00       	nop
     440:	68 13       	cpse	r22, r24
     442:	00 00       	nop
     444:	5c 0b       	sbc	r21, r28
     446:	00 00       	nop
     448:	80 00       	.word	0x0080	; ????
     44a:	f4 00       	.word	0x00f4	; ????
	...
     454:	a2 00       	.word	0x00a2	; ????
	...
     45e:	00 00       	nop
     460:	a2 00       	.word	0x00a2	; ????
     462:	00 00       	nop
     464:	00 00       	nop
     466:	00 00       	nop
     468:	aa 0b       	sbc	r26, r26
     46a:	00 00       	nop
     46c:	24 00       	.word	0x0024	; ????
     46e:	0c 00       	.word	0x000c	; ????
     470:	20 e0       	ldi	r18, 0x00	; 0
     472:	01 00       	.word	0x0001	; ????
     474:	00 00       	nop
     476:	00 00       	nop
     478:	2e 00       	.word	0x002e	; ????
     47a:	00 00       	nop
     47c:	20 e0       	ldi	r18, 0x00	; 0
     47e:	01 00       	.word	0x0001	; ????
     480:	00 00       	nop
     482:	00 00       	nop
     484:	44 00       	.word	0x0044	; ????
     486:	0d 00       	.word	0x000d	; ????
	...
     490:	44 00       	.word	0x0044	; ????
     492:	0f 00       	.word	0x000f	; ????
	...
     49c:	44 00       	.word	0x0044	; ????
     49e:	10 00       	.word	0x0010	; ????
     4a0:	04 00       	.word	0x0004	; ????
     4a2:	00 00       	nop
     4a4:	00 00       	nop
     4a6:	00 00       	nop
     4a8:	44 00       	.word	0x0044	; ????
     4aa:	15 00       	.word	0x0015	; ????
     4ac:	0a 00       	.word	0x000a	; ????
     4ae:	00 00       	nop
     4b0:	00 00       	nop
     4b2:	00 00       	nop
     4b4:	44 00       	.word	0x0044	; ????
     4b6:	18 00       	.word	0x0018	; ????
     4b8:	14 00       	.word	0x0014	; ????
     4ba:	00 00       	nop
     4bc:	00 00       	nop
     4be:	00 00       	nop
     4c0:	44 00       	.word	0x0044	; ????
     4c2:	1b 00       	.word	0x001b	; ????
     4c4:	1a 00       	.word	0x001a	; ????
     4c6:	00 00       	nop
     4c8:	00 00       	nop
     4ca:	00 00       	nop
     4cc:	24 00       	.word	0x0024	; ????
     4ce:	00 00       	nop
     4d0:	22 00       	.word	0x0022	; ????
     4d2:	00 00       	nop
     4d4:	00 00       	nop
     4d6:	00 00       	nop
     4d8:	4e 00       	.word	0x004e	; ????
     4da:	00 00       	nop
     4dc:	42 e0       	ldi	r20, 0x02	; 2
     4de:	01 00       	.word	0x0001	; ????
     4e0:	bd 0b       	sbc	r27, r29
     4e2:	00 00       	nop
     4e4:	24 00       	.word	0x0024	; ????
     4e6:	1e 00       	.word	0x001e	; ????
     4e8:	42 e0       	ldi	r20, 0x02	; 2
     4ea:	01 00       	.word	0x0001	; ????
     4ec:	d3 0b       	sbc	r29, r19
     4ee:	00 00       	nop
     4f0:	40 00       	.word	0x0040	; ????
     4f2:	1e 00       	.word	0x001e	; ????
     4f4:	18 00       	.word	0x0018	; ????
     4f6:	00 00       	nop
     4f8:	00 00       	nop
     4fa:	00 00       	nop
     4fc:	2e 00       	.word	0x002e	; ????
     4fe:	00 00       	nop
     500:	42 e0       	ldi	r20, 0x02	; 2
     502:	01 00       	.word	0x0001	; ????
     504:	00 00       	nop
     506:	00 00       	nop
     508:	44 00       	.word	0x0044	; ????
     50a:	1f 00       	.word	0x001f	; ????
	...
     514:	44 00       	.word	0x0044	; ????
     516:	20 00       	.word	0x0020	; ????
	...
     520:	44 00       	.word	0x0044	; ????
     522:	24 00       	.word	0x0024	; ????
     524:	08 00       	.word	0x0008	; ????
     526:	00 00       	nop
     528:	00 00       	nop
     52a:	00 00       	nop
     52c:	24 00       	.word	0x0024	; ????
     52e:	00 00       	nop
     530:	0e 00       	.word	0x000e	; ????
     532:	00 00       	nop
     534:	00 00       	nop
     536:	00 00       	nop
     538:	4e 00       	.word	0x004e	; ????
     53a:	00 00       	nop
     53c:	50 e0       	ldi	r21, 0x00	; 0
     53e:	01 00       	.word	0x0001	; ????
     540:	e0 0b       	sbc	r30, r16
     542:	00 00       	nop
     544:	24 00       	.word	0x0024	; ????
     546:	27 00       	.word	0x0027	; ????
     548:	50 e0       	ldi	r21, 0x00	; 0
     54a:	01 00       	.word	0x0001	; ????
     54c:	00 00       	nop
     54e:	00 00       	nop
     550:	2e 00       	.word	0x002e	; ????
     552:	00 00       	nop
     554:	50 e0       	ldi	r21, 0x00	; 0
     556:	01 00       	.word	0x0001	; ????
     558:	00 00       	nop
     55a:	00 00       	nop
     55c:	44 00       	.word	0x0044	; ????
     55e:	28 00       	.word	0x0028	; ????
	...
     568:	44 00       	.word	0x0044	; ????
     56a:	29 00       	.word	0x0029	; ????
	...
     574:	44 00       	.word	0x0044	; ????
     576:	2a 00       	.word	0x002a	; ????
     578:	04 00       	.word	0x0004	; ????
     57a:	00 00       	nop
     57c:	00 00       	nop
     57e:	00 00       	nop
     580:	24 00       	.word	0x0024	; ????
     582:	00 00       	nop
     584:	0c 00       	.word	0x000c	; ????
     586:	00 00       	nop
     588:	00 00       	nop
     58a:	00 00       	nop
     58c:	4e 00       	.word	0x004e	; ????
     58e:	00 00       	nop
     590:	5c e0       	ldi	r21, 0x0C	; 12
     592:	01 00       	.word	0x0001	; ????
     594:	06 0c       	add	r0, r6
     596:	00 00       	nop
     598:	24 00       	.word	0x0024	; ????
     59a:	2c 00       	.word	0x002c	; ????
     59c:	5c e0       	ldi	r21, 0x0C	; 12
     59e:	01 00       	.word	0x0001	; ????
     5a0:	00 00       	nop
     5a2:	00 00       	nop
     5a4:	2e 00       	.word	0x002e	; ????
     5a6:	00 00       	nop
     5a8:	5c e0       	ldi	r21, 0x0C	; 12
     5aa:	01 00       	.word	0x0001	; ????
     5ac:	00 00       	nop
     5ae:	00 00       	nop
     5b0:	44 00       	.word	0x0044	; ????
     5b2:	2d 00       	.word	0x002d	; ????
	...
     5bc:	44 00       	.word	0x0044	; ????
     5be:	29 00       	.word	0x0029	; ????
	...
     5c8:	44 00       	.word	0x0044	; ????
     5ca:	2e 00       	.word	0x002e	; ????
     5cc:	04 00       	.word	0x0004	; ????
     5ce:	00 00       	nop
     5d0:	00 00       	nop
     5d2:	00 00       	nop
     5d4:	44 00       	.word	0x0044	; ????
     5d6:	33 00       	.word	0x0033	; ????
     5d8:	08 00       	.word	0x0008	; ????
     5da:	00 00       	nop
     5dc:	00 00       	nop
     5de:	00 00       	nop
     5e0:	44 00       	.word	0x0044	; ????
     5e2:	34 00       	.word	0x0034	; ????
     5e4:	0c 00       	.word	0x000c	; ????
     5e6:	00 00       	nop
     5e8:	00 00       	nop
     5ea:	00 00       	nop
     5ec:	24 00       	.word	0x0024	; ????
     5ee:	00 00       	nop
     5f0:	0e 00       	.word	0x000e	; ????
     5f2:	00 00       	nop
     5f4:	00 00       	nop
     5f6:	00 00       	nop
     5f8:	4e 00       	.word	0x004e	; ????
     5fa:	00 00       	nop
     5fc:	6a e0       	ldi	r22, 0x0A	; 10
     5fe:	01 00       	.word	0x0001	; ????
     600:	1c 0c       	add	r1, r12
     602:	00 00       	nop
     604:	24 00       	.word	0x0024	; ????
     606:	36 00       	.word	0x0036	; ????
     608:	6a e0       	ldi	r22, 0x0A	; 10
     60a:	01 00       	.word	0x0001	; ????
     60c:	00 00       	nop
     60e:	00 00       	nop
     610:	2e 00       	.word	0x002e	; ????
     612:	00 00       	nop
     614:	6a e0       	ldi	r22, 0x0A	; 10
     616:	01 00       	.word	0x0001	; ????
     618:	00 00       	nop
     61a:	00 00       	nop
     61c:	44 00       	.word	0x0044	; ????
     61e:	37 00       	.word	0x0037	; ????
	...
     628:	44 00       	.word	0x0044	; ????
     62a:	29 00       	.word	0x0029	; ????
	...
     634:	44 00       	.word	0x0044	; ????
     636:	3a 00       	.word	0x003a	; ????
     638:	04 00       	.word	0x0004	; ????
     63a:	00 00       	nop
     63c:	00 00       	nop
     63e:	00 00       	nop
     640:	44 00       	.word	0x0044	; ????
     642:	3a 00       	.word	0x003a	; ????
     644:	08 00       	.word	0x0008	; ????
     646:	00 00       	nop
     648:	00 00       	nop
     64a:	00 00       	nop
     64c:	44 00       	.word	0x0044	; ????
     64e:	3b 00       	.word	0x003b	; ????
     650:	0e 00       	.word	0x000e	; ????
     652:	00 00       	nop
     654:	30 0c       	add	r3, r0
     656:	00 00       	nop
     658:	40 00       	.word	0x0040	; ????
     65a:	39 00       	.word	0x0039	; ????
     65c:	18 00       	.word	0x0018	; ????
     65e:	00 00       	nop
     660:	00 00       	nop
     662:	00 00       	nop
     664:	c0 00       	.word	0x00c0	; ????
	...
     66e:	00 00       	nop
     670:	e0 00       	.word	0x00e0	; ????
     672:	00 00       	nop
     674:	10 00       	.word	0x0010	; ????
     676:	00 00       	nop
     678:	00 00       	nop
     67a:	00 00       	nop
     67c:	24 00       	.word	0x0024	; ????
     67e:	00 00       	nop
     680:	10 00       	.word	0x0010	; ????
     682:	00 00       	nop
     684:	00 00       	nop
     686:	00 00       	nop
     688:	4e 00       	.word	0x004e	; ????
     68a:	00 00       	nop
     68c:	7a e0       	ldi	r23, 0x0A	; 10
     68e:	01 00       	.word	0x0001	; ????
     690:	3e 0c       	add	r3, r14
     692:	00 00       	nop
     694:	24 00       	.word	0x0024	; ????
     696:	3d 00       	.word	0x003d	; ????
     698:	7a e0       	ldi	r23, 0x0A	; 10
     69a:	01 00       	.word	0x0001	; ????
     69c:	56 0c       	add	r5, r6
     69e:	00 00       	nop
     6a0:	40 00       	.word	0x0040	; ????
     6a2:	3d 00       	.word	0x003d	; ????
     6a4:	18 00       	.word	0x0018	; ????
     6a6:	00 00       	nop
     6a8:	00 00       	nop
     6aa:	00 00       	nop
     6ac:	2e 00       	.word	0x002e	; ????
     6ae:	00 00       	nop
     6b0:	7a e0       	ldi	r23, 0x0A	; 10
     6b2:	01 00       	.word	0x0001	; ????
     6b4:	00 00       	nop
     6b6:	00 00       	nop
     6b8:	44 00       	.word	0x0044	; ????
     6ba:	3e 00       	.word	0x003e	; ????
	...
     6c4:	44 00       	.word	0x0044	; ????
     6c6:	40 00       	.word	0x0040	; ????
     6c8:	06 00       	.word	0x0006	; ????
     6ca:	00 00       	nop
     6cc:	00 00       	nop
     6ce:	00 00       	nop
     6d0:	44 00       	.word	0x0044	; ????
     6d2:	41 00       	.word	0x0041	; ????
     6d4:	0c 00       	.word	0x000c	; ????
     6d6:	00 00       	nop
     6d8:	00 00       	nop
     6da:	00 00       	nop
     6dc:	44 00       	.word	0x0044	; ????
     6de:	44 00       	.word	0x0044	; ????
     6e0:	12 00       	.word	0x0012	; ????
     6e2:	00 00       	nop
     6e4:	00 00       	nop
     6e6:	00 00       	nop
     6e8:	44 00       	.word	0x0044	; ????
     6ea:	45 00       	.word	0x0045	; ????
     6ec:	16 00       	.word	0x0016	; ????
     6ee:	00 00       	nop
     6f0:	00 00       	nop
     6f2:	00 00       	nop
     6f4:	24 00       	.word	0x0024	; ????
     6f6:	00 00       	nop
     6f8:	1c 00       	.word	0x001c	; ????
     6fa:	00 00       	nop
     6fc:	00 00       	nop
     6fe:	00 00       	nop
     700:	4e 00       	.word	0x004e	; ????
     702:	00 00       	nop
     704:	96 e0       	ldi	r25, 0x06	; 6
     706:	01 00       	.word	0x0001	; ????
     708:	69 0c       	add	r6, r9
     70a:	00 00       	nop
     70c:	24 00       	.word	0x0024	; ????
     70e:	4b 00       	.word	0x004b	; ????
     710:	96 e0       	ldi	r25, 0x06	; 6
     712:	01 00       	.word	0x0001	; ????
     714:	00 00       	nop
     716:	00 00       	nop
     718:	2e 00       	.word	0x002e	; ????
     71a:	00 00       	nop
     71c:	96 e0       	ldi	r25, 0x06	; 6
     71e:	01 00       	.word	0x0001	; ????
     720:	00 00       	nop
     722:	00 00       	nop
     724:	44 00       	.word	0x0044	; ????
     726:	4c 00       	.word	0x004c	; ????
	...
     730:	44 00       	.word	0x0044	; ????
     732:	4e 00       	.word	0x004e	; ????
	...
     73c:	44 00       	.word	0x0044	; ????
     73e:	4f 00       	.word	0x004f	; ????
     740:	04 00       	.word	0x0004	; ????
     742:	00 00       	nop
     744:	00 00       	nop
     746:	00 00       	nop
     748:	44 00       	.word	0x0044	; ????
     74a:	54 00       	.word	0x0054	; ????
     74c:	0a 00       	.word	0x000a	; ????
     74e:	00 00       	nop
     750:	00 00       	nop
     752:	00 00       	nop
     754:	44 00       	.word	0x0044	; ????
     756:	57 00       	.word	0x0057	; ????
     758:	14 00       	.word	0x0014	; ????
     75a:	00 00       	nop
     75c:	00 00       	nop
     75e:	00 00       	nop
     760:	44 00       	.word	0x0044	; ????
     762:	5a 00       	.word	0x005a	; ????
     764:	1a 00       	.word	0x001a	; ????
     766:	00 00       	nop
     768:	00 00       	nop
     76a:	00 00       	nop
     76c:	24 00       	.word	0x0024	; ????
     76e:	00 00       	nop
     770:	22 00       	.word	0x0022	; ????
     772:	00 00       	nop
     774:	00 00       	nop
     776:	00 00       	nop
     778:	4e 00       	.word	0x004e	; ????
     77a:	00 00       	nop
     77c:	b8 e0       	ldi	r27, 0x08	; 8
     77e:	01 00       	.word	0x0001	; ????
     780:	7c 0c       	add	r7, r12
     782:	00 00       	nop
     784:	24 00       	.word	0x0024	; ????
     786:	5d 00       	.word	0x005d	; ????
     788:	b8 e0       	ldi	r27, 0x08	; 8
     78a:	01 00       	.word	0x0001	; ????
     78c:	d3 0b       	sbc	r29, r19
     78e:	00 00       	nop
     790:	40 00       	.word	0x0040	; ????
     792:	5d 00       	.word	0x005d	; ????
     794:	18 00       	.word	0x0018	; ????
     796:	00 00       	nop
     798:	00 00       	nop
     79a:	00 00       	nop
     79c:	2e 00       	.word	0x002e	; ????
     79e:	00 00       	nop
     7a0:	b8 e0       	ldi	r27, 0x08	; 8
     7a2:	01 00       	.word	0x0001	; ????
     7a4:	00 00       	nop
     7a6:	00 00       	nop
     7a8:	44 00       	.word	0x0044	; ????
     7aa:	5e 00       	.word	0x005e	; ????
	...
     7b4:	44 00       	.word	0x0044	; ????
     7b6:	5f 00       	.word	0x005f	; ????
	...
     7c0:	44 00       	.word	0x0044	; ????
     7c2:	63 00       	.word	0x0063	; ????
     7c4:	08 00       	.word	0x0008	; ????
     7c6:	00 00       	nop
     7c8:	00 00       	nop
     7ca:	00 00       	nop
     7cc:	24 00       	.word	0x0024	; ????
     7ce:	00 00       	nop
     7d0:	0e 00       	.word	0x000e	; ????
     7d2:	00 00       	nop
     7d4:	00 00       	nop
     7d6:	00 00       	nop
     7d8:	4e 00       	.word	0x004e	; ????
     7da:	00 00       	nop
     7dc:	c6 e0       	ldi	r28, 0x06	; 6
     7de:	01 00       	.word	0x0001	; ????
     7e0:	92 0c       	add	r9, r2
     7e2:	00 00       	nop
     7e4:	24 00       	.word	0x0024	; ????
     7e6:	66 00       	.word	0x0066	; ????
     7e8:	c6 e0       	ldi	r28, 0x06	; 6
     7ea:	01 00       	.word	0x0001	; ????
     7ec:	00 00       	nop
     7ee:	00 00       	nop
     7f0:	2e 00       	.word	0x002e	; ????
     7f2:	00 00       	nop
     7f4:	c6 e0       	ldi	r28, 0x06	; 6
     7f6:	01 00       	.word	0x0001	; ????
     7f8:	00 00       	nop
     7fa:	00 00       	nop
     7fc:	44 00       	.word	0x0044	; ????
     7fe:	67 00       	.word	0x0067	; ????
	...
     808:	44 00       	.word	0x0044	; ????
     80a:	68 00       	.word	0x0068	; ????
	...
     814:	44 00       	.word	0x0044	; ????
     816:	69 00       	.word	0x0069	; ????
     818:	04 00       	.word	0x0004	; ????
     81a:	00 00       	nop
     81c:	00 00       	nop
     81e:	00 00       	nop
     820:	24 00       	.word	0x0024	; ????
     822:	00 00       	nop
     824:	0c 00       	.word	0x000c	; ????
     826:	00 00       	nop
     828:	00 00       	nop
     82a:	00 00       	nop
     82c:	4e 00       	.word	0x004e	; ????
     82e:	00 00       	nop
     830:	d2 e0       	ldi	r29, 0x02	; 2
     832:	01 00       	.word	0x0001	; ????
     834:	af 0c       	add	r10, r15
     836:	00 00       	nop
     838:	24 00       	.word	0x0024	; ????
     83a:	6b 00       	.word	0x006b	; ????
     83c:	d2 e0       	ldi	r29, 0x02	; 2
     83e:	01 00       	.word	0x0001	; ????
     840:	00 00       	nop
     842:	00 00       	nop
     844:	2e 00       	.word	0x002e	; ????
     846:	00 00       	nop
     848:	d2 e0       	ldi	r29, 0x02	; 2
     84a:	01 00       	.word	0x0001	; ????
     84c:	00 00       	nop
     84e:	00 00       	nop
     850:	44 00       	.word	0x0044	; ????
     852:	6c 00       	.word	0x006c	; ????
	...
     85c:	44 00       	.word	0x0044	; ????
     85e:	68 00       	.word	0x0068	; ????
	...
     868:	44 00       	.word	0x0044	; ????
     86a:	6d 00       	.word	0x006d	; ????
     86c:	04 00       	.word	0x0004	; ????
     86e:	00 00       	nop
     870:	00 00       	nop
     872:	00 00       	nop
     874:	44 00       	.word	0x0044	; ????
     876:	72 00       	.word	0x0072	; ????
     878:	08 00       	.word	0x0008	; ????
     87a:	00 00       	nop
     87c:	00 00       	nop
     87e:	00 00       	nop
     880:	44 00       	.word	0x0044	; ????
     882:	73 00       	.word	0x0073	; ????
     884:	0c 00       	.word	0x000c	; ????
     886:	00 00       	nop
     888:	00 00       	nop
     88a:	00 00       	nop
     88c:	24 00       	.word	0x0024	; ????
     88e:	00 00       	nop
     890:	0e 00       	.word	0x000e	; ????
     892:	00 00       	nop
     894:	00 00       	nop
     896:	00 00       	nop
     898:	4e 00       	.word	0x004e	; ????
     89a:	00 00       	nop
     89c:	e0 e0       	ldi	r30, 0x00	; 0
     89e:	01 00       	.word	0x0001	; ????
     8a0:	c5 0c       	add	r12, r5
     8a2:	00 00       	nop
     8a4:	24 00       	.word	0x0024	; ????
     8a6:	75 00       	.word	0x0075	; ????
     8a8:	e0 e0       	ldi	r30, 0x00	; 0
     8aa:	01 00       	.word	0x0001	; ????
     8ac:	00 00       	nop
     8ae:	00 00       	nop
     8b0:	2e 00       	.word	0x002e	; ????
     8b2:	00 00       	nop
     8b4:	e0 e0       	ldi	r30, 0x00	; 0
     8b6:	01 00       	.word	0x0001	; ????
     8b8:	00 00       	nop
     8ba:	00 00       	nop
     8bc:	44 00       	.word	0x0044	; ????
     8be:	76 00       	.word	0x0076	; ????
	...
     8c8:	44 00       	.word	0x0044	; ????
     8ca:	68 00       	.word	0x0068	; ????
	...
     8d4:	44 00       	.word	0x0044	; ????
     8d6:	79 00       	.word	0x0079	; ????
     8d8:	04 00       	.word	0x0004	; ????
     8da:	00 00       	nop
     8dc:	00 00       	nop
     8de:	00 00       	nop
     8e0:	44 00       	.word	0x0044	; ????
     8e2:	7b 00       	.word	0x007b	; ????
     8e4:	08 00       	.word	0x0008	; ????
     8e6:	00 00       	nop
     8e8:	00 00       	nop
     8ea:	00 00       	nop
     8ec:	44 00       	.word	0x0044	; ????
     8ee:	7d 00       	.word	0x007d	; ????
     8f0:	0e 00       	.word	0x000e	; ????
     8f2:	00 00       	nop
     8f4:	30 0c       	add	r3, r0
     8f6:	00 00       	nop
     8f8:	40 00       	.word	0x0040	; ????
     8fa:	78 00       	.word	0x0078	; ????
     8fc:	18 00       	.word	0x0018	; ????
     8fe:	00 00       	nop
     900:	00 00       	nop
     902:	00 00       	nop
     904:	c0 00       	.word	0x00c0	; ????
	...
     90e:	00 00       	nop
     910:	e0 00       	.word	0x00e0	; ????
     912:	00 00       	nop
     914:	10 00       	.word	0x0010	; ????
     916:	00 00       	nop
     918:	00 00       	nop
     91a:	00 00       	nop
     91c:	24 00       	.word	0x0024	; ????
     91e:	00 00       	nop
     920:	10 00       	.word	0x0010	; ????
     922:	00 00       	nop
     924:	00 00       	nop
     926:	00 00       	nop
     928:	4e 00       	.word	0x004e	; ????
     92a:	00 00       	nop
     92c:	f0 e0       	ldi	r31, 0x00	; 0
     92e:	01 00       	.word	0x0001	; ????
     930:	d9 0c       	add	r13, r9
     932:	00 00       	nop
     934:	24 00       	.word	0x0024	; ????
     936:	7f 00       	.word	0x007f	; ????
     938:	f0 e0       	ldi	r31, 0x00	; 0
     93a:	01 00       	.word	0x0001	; ????
     93c:	f1 0c       	add	r15, r1
     93e:	00 00       	nop
     940:	40 00       	.word	0x0040	; ????
     942:	7f 00       	.word	0x007f	; ????
     944:	18 00       	.word	0x0018	; ????
     946:	00 00       	nop
     948:	00 00       	nop
     94a:	00 00       	nop
     94c:	2e 00       	.word	0x002e	; ????
     94e:	00 00       	nop
     950:	f0 e0       	ldi	r31, 0x00	; 0
     952:	01 00       	.word	0x0001	; ????
     954:	00 00       	nop
     956:	00 00       	nop
     958:	44 00       	.word	0x0044	; ????
     95a:	80 00       	.word	0x0080	; ????
	...
     964:	44 00       	.word	0x0044	; ????
     966:	82 00       	.word	0x0082	; ????
     968:	06 00       	.word	0x0006	; ????
     96a:	00 00       	nop
     96c:	00 00       	nop
     96e:	00 00       	nop
     970:	44 00       	.word	0x0044	; ????
     972:	83 00       	.word	0x0083	; ????
     974:	0c 00       	.word	0x000c	; ????
     976:	00 00       	nop
     978:	00 00       	nop
     97a:	00 00       	nop
     97c:	44 00       	.word	0x0044	; ????
     97e:	86 00       	.word	0x0086	; ????
     980:	12 00       	.word	0x0012	; ????
     982:	00 00       	nop
     984:	00 00       	nop
     986:	00 00       	nop
     988:	44 00       	.word	0x0044	; ????
     98a:	87 00       	.word	0x0087	; ????
     98c:	16 00       	.word	0x0016	; ????
     98e:	00 00       	nop
     990:	00 00       	nop
     992:	00 00       	nop
     994:	24 00       	.word	0x0024	; ????
     996:	00 00       	nop
     998:	1c 00       	.word	0x001c	; ????
     99a:	00 00       	nop
     99c:	00 00       	nop
     99e:	00 00       	nop
     9a0:	4e 00       	.word	0x004e	; ????
     9a2:	00 00       	nop
     9a4:	0c e1       	ldi	r16, 0x1C	; 28
     9a6:	01 00       	.word	0x0001	; ????
     9a8:	00 00       	nop
     9aa:	00 00       	nop
     9ac:	64 00       	.word	0x0064	; ????
     9ae:	00 00       	nop
     9b0:	0c e1       	ldi	r16, 0x1C	; 28
     9b2:	01 00       	.word	0x0001	; ????
     9b4:	08 00       	.word	0x0008	; ????
     9b6:	00 00       	nop
     9b8:	64 00       	.word	0x0064	; ????
     9ba:	02 00       	.word	0x0002	; ????
     9bc:	0c e1       	ldi	r16, 0x1C	; 28
     9be:	01 00       	.word	0x0001	; ????
     9c0:	fd 0c       	add	r15, r13
     9c2:	00 00       	nop
     9c4:	64 00       	.word	0x0064	; ????
     9c6:	02 00       	.word	0x0002	; ????
     9c8:	0c e1       	ldi	r16, 0x1C	; 28
     9ca:	01 00       	.word	0x0001	; ????
     9cc:	33 00       	.word	0x0033	; ????
     9ce:	00 00       	nop
     9d0:	3c 00       	.word	0x003c	; ????
     9d2:	00 00       	nop
     9d4:	00 00       	nop
     9d6:	00 00       	nop
     9d8:	42 00       	.word	0x0042	; ????
     9da:	00 00       	nop
     9dc:	80 00       	.word	0x0080	; ????
     9de:	00 00       	nop
     9e0:	00 00       	nop
     9e2:	00 00       	nop
     9e4:	62 00       	.word	0x0062	; ????
     9e6:	00 00       	nop
     9e8:	80 00       	.word	0x0080	; ????
     9ea:	00 00       	nop
     9ec:	00 00       	nop
     9ee:	00 00       	nop
     9f0:	7c 00       	.word	0x007c	; ????
     9f2:	00 00       	nop
     9f4:	80 00       	.word	0x0080	; ????
     9f6:	00 00       	nop
     9f8:	00 00       	nop
     9fa:	00 00       	nop
     9fc:	b3 00       	.word	0x00b3	; ????
     9fe:	00 00       	nop
     a00:	80 00       	.word	0x0080	; ????
     a02:	00 00       	nop
     a04:	00 00       	nop
     a06:	00 00       	nop
     a08:	d9 00       	.word	0x00d9	; ????
     a0a:	00 00       	nop
     a0c:	80 00       	.word	0x0080	; ????
     a0e:	00 00       	nop
     a10:	00 00       	nop
     a12:	00 00       	nop
     a14:	0e 01       	movw	r0, r28
     a16:	00 00       	nop
     a18:	80 00       	.word	0x0080	; ????
     a1a:	00 00       	nop
     a1c:	00 00       	nop
     a1e:	00 00       	nop
     a20:	5f 01       	movw	r10, r30
     a22:	00 00       	nop
     a24:	80 00       	.word	0x0080	; ????
     a26:	00 00       	nop
     a28:	00 00       	nop
     a2a:	00 00       	nop
     a2c:	a4 01       	movw	r20, r8
     a2e:	00 00       	nop
     a30:	80 00       	.word	0x0080	; ????
     a32:	00 00       	nop
     a34:	00 00       	nop
     a36:	00 00       	nop
     a38:	ca 01       	movw	r24, r20
     a3a:	00 00       	nop
     a3c:	80 00       	.word	0x0080	; ????
     a3e:	00 00       	nop
     a40:	00 00       	nop
     a42:	00 00       	nop
     a44:	f6 01       	movw	r30, r12
     a46:	00 00       	nop
     a48:	80 00       	.word	0x0080	; ????
     a4a:	00 00       	nop
     a4c:	00 00       	nop
     a4e:	00 00       	nop
     a50:	20 02       	muls	r18, r16
     a52:	00 00       	nop
     a54:	80 00       	.word	0x0080	; ????
     a56:	00 00       	nop
     a58:	00 00       	nop
     a5a:	00 00       	nop
     a5c:	49 02       	muls	r20, r25
     a5e:	00 00       	nop
     a60:	80 00       	.word	0x0080	; ????
     a62:	00 00       	nop
     a64:	00 00       	nop
     a66:	00 00       	nop
     a68:	63 02       	muls	r22, r19
     a6a:	00 00       	nop
     a6c:	80 00       	.word	0x0080	; ????
     a6e:	00 00       	nop
     a70:	00 00       	nop
     a72:	00 00       	nop
     a74:	7e 02       	muls	r23, r30
     a76:	00 00       	nop
     a78:	80 00       	.word	0x0080	; ????
     a7a:	00 00       	nop
     a7c:	00 00       	nop
     a7e:	00 00       	nop
     a80:	9e 02       	muls	r25, r30
     a82:	00 00       	nop
     a84:	80 00       	.word	0x0080	; ????
     a86:	00 00       	nop
     a88:	00 00       	nop
     a8a:	00 00       	nop
     a8c:	bf 02       	muls	r27, r31
     a8e:	00 00       	nop
     a90:	80 00       	.word	0x0080	; ????
     a92:	00 00       	nop
     a94:	00 00       	nop
     a96:	00 00       	nop
     a98:	da 02       	muls	r29, r26
     a9a:	00 00       	nop
     a9c:	80 00       	.word	0x0080	; ????
     a9e:	00 00       	nop
     aa0:	00 00       	nop
     aa2:	00 00       	nop
     aa4:	fa 02       	muls	r31, r26
     aa6:	00 00       	nop
     aa8:	80 00       	.word	0x0080	; ????
     aaa:	00 00       	nop
     aac:	00 00       	nop
     aae:	00 00       	nop
     ab0:	1f 03       	fmul	r17, r23
     ab2:	00 00       	nop
     ab4:	80 00       	.word	0x0080	; ????
     ab6:	00 00       	nop
     ab8:	00 00       	nop
     aba:	00 00       	nop
     abc:	49 03       	fmul	r20, r17
     abe:	00 00       	nop
     ac0:	80 00       	.word	0x0080	; ????
     ac2:	00 00       	nop
     ac4:	00 00       	nop
     ac6:	00 00       	nop
     ac8:	6d 03       	fmul	r22, r21
     aca:	00 00       	nop
     acc:	80 00       	.word	0x0080	; ????
     ace:	00 00       	nop
     ad0:	00 00       	nop
     ad2:	00 00       	nop
     ad4:	96 03       	fmuls	r17, r22
     ad6:	00 00       	nop
     ad8:	80 00       	.word	0x0080	; ????
     ada:	00 00       	nop
     adc:	00 00       	nop
     ade:	00 00       	nop
     ae0:	c4 03       	fmuls	r20, r20
     ae2:	00 00       	nop
     ae4:	80 00       	.word	0x0080	; ????
     ae6:	00 00       	nop
     ae8:	00 00       	nop
     aea:	00 00       	nop
     aec:	ea 03       	fmulsu	r22, r18
     aee:	00 00       	nop
     af0:	80 00       	.word	0x0080	; ????
     af2:	00 00       	nop
     af4:	00 00       	nop
     af6:	00 00       	nop
     af8:	0a 04       	cpc	r0, r10
     afa:	00 00       	nop
     afc:	80 00       	.word	0x0080	; ????
     afe:	00 00       	nop
     b00:	00 00       	nop
     b02:	00 00       	nop
     b04:	2f 04       	cpc	r2, r15
     b06:	00 00       	nop
     b08:	80 00       	.word	0x0080	; ????
     b0a:	00 00       	nop
     b0c:	00 00       	nop
     b0e:	00 00       	nop
     b10:	59 04       	cpc	r5, r9
     b12:	00 00       	nop
     b14:	80 00       	.word	0x0080	; ????
     b16:	00 00       	nop
     b18:	00 00       	nop
     b1a:	00 00       	nop
     b1c:	88 04       	cpc	r8, r8
     b1e:	00 00       	nop
     b20:	80 00       	.word	0x0080	; ????
     b22:	00 00       	nop
     b24:	00 00       	nop
     b26:	00 00       	nop
     b28:	b1 04       	cpc	r11, r1
     b2a:	00 00       	nop
     b2c:	80 00       	.word	0x0080	; ????
     b2e:	00 00       	nop
     b30:	00 00       	nop
     b32:	00 00       	nop
     b34:	df 04       	cpc	r13, r15
     b36:	00 00       	nop
     b38:	80 00       	.word	0x0080	; ????
     b3a:	00 00       	nop
     b3c:	00 00       	nop
     b3e:	00 00       	nop
     b40:	12 05       	cpc	r17, r2
     b42:	00 00       	nop
     b44:	80 00       	.word	0x0080	; ????
     b46:	00 00       	nop
     b48:	00 00       	nop
     b4a:	00 00       	nop
     b4c:	33 05       	cpc	r19, r3
     b4e:	00 00       	nop
     b50:	80 00       	.word	0x0080	; ????
     b52:	00 00       	nop
     b54:	00 00       	nop
     b56:	00 00       	nop
     b58:	4e 05       	cpc	r20, r14
     b5a:	00 00       	nop
     b5c:	80 00       	.word	0x0080	; ????
     b5e:	00 00       	nop
     b60:	00 00       	nop
     b62:	00 00       	nop
     b64:	6e 05       	cpc	r22, r14
     b66:	00 00       	nop
     b68:	80 00       	.word	0x0080	; ????
     b6a:	00 00       	nop
     b6c:	00 00       	nop
     b6e:	00 00       	nop
     b70:	93 05       	cpc	r25, r3
     b72:	00 00       	nop
     b74:	80 00       	.word	0x0080	; ????
     b76:	00 00       	nop
     b78:	00 00       	nop
     b7a:	00 00       	nop
     b7c:	bd 05       	cpc	r27, r13
     b7e:	00 00       	nop
     b80:	80 00       	.word	0x0080	; ????
     b82:	00 00       	nop
     b84:	00 00       	nop
     b86:	00 00       	nop
     b88:	e1 05       	cpc	r30, r1
     b8a:	00 00       	nop
     b8c:	80 00       	.word	0x0080	; ????
     b8e:	00 00       	nop
     b90:	00 00       	nop
     b92:	00 00       	nop
     b94:	0a 06       	cpc	r0, r26
     b96:	00 00       	nop
     b98:	80 00       	.word	0x0080	; ????
     b9a:	00 00       	nop
     b9c:	00 00       	nop
     b9e:	00 00       	nop
     ba0:	38 06       	cpc	r3, r24
     ba2:	00 00       	nop
     ba4:	80 00       	.word	0x0080	; ????
     ba6:	00 00       	nop
     ba8:	00 00       	nop
     baa:	00 00       	nop
     bac:	5e 06       	cpc	r5, r30
     bae:	00 00       	nop
     bb0:	80 00       	.word	0x0080	; ????
     bb2:	00 00       	nop
     bb4:	00 00       	nop
     bb6:	00 00       	nop
     bb8:	7e 06       	cpc	r7, r30
     bba:	00 00       	nop
     bbc:	80 00       	.word	0x0080	; ????
     bbe:	00 00       	nop
     bc0:	00 00       	nop
     bc2:	00 00       	nop
     bc4:	a3 06       	cpc	r10, r19
     bc6:	00 00       	nop
     bc8:	80 00       	.word	0x0080	; ????
     bca:	00 00       	nop
     bcc:	00 00       	nop
     bce:	00 00       	nop
     bd0:	cd 06       	cpc	r12, r29
     bd2:	00 00       	nop
     bd4:	80 00       	.word	0x0080	; ????
     bd6:	00 00       	nop
     bd8:	00 00       	nop
     bda:	00 00       	nop
     bdc:	fc 06       	cpc	r15, r28
     bde:	00 00       	nop
     be0:	80 00       	.word	0x0080	; ????
     be2:	00 00       	nop
     be4:	00 00       	nop
     be6:	00 00       	nop
     be8:	25 07       	cpc	r18, r21
     bea:	00 00       	nop
     bec:	80 00       	.word	0x0080	; ????
     bee:	00 00       	nop
     bf0:	00 00       	nop
     bf2:	00 00       	nop
     bf4:	53 07       	cpc	r21, r19
     bf6:	00 00       	nop
     bf8:	80 00       	.word	0x0080	; ????
     bfa:	00 00       	nop
     bfc:	00 00       	nop
     bfe:	00 00       	nop
     c00:	86 07       	cpc	r24, r22
     c02:	00 00       	nop
     c04:	80 00       	.word	0x0080	; ????
     c06:	00 00       	nop
     c08:	00 00       	nop
     c0a:	00 00       	nop
     c0c:	9a 07       	cpc	r25, r26
     c0e:	00 00       	nop
     c10:	c2 00       	.word	0x00c2	; ????
     c12:	00 00       	nop
     c14:	00 00       	nop
     c16:	00 00       	nop
     c18:	b8 07       	cpc	r27, r24
     c1a:	00 00       	nop
     c1c:	c2 00       	.word	0x00c2	; ????
     c1e:	00 00       	nop
     c20:	00 00       	nop
     c22:	00 00       	nop
     c24:	dc 07       	cpc	r29, r28
     c26:	00 00       	nop
     c28:	c2 00       	.word	0x00c2	; ????
     c2a:	00 00       	nop
     c2c:	25 0f       	add	r18, r21
     c2e:	00 00       	nop
     c30:	fc 07       	cpc	r31, r28
     c32:	00 00       	nop
     c34:	c2 00       	.word	0x00c2	; ????
     c36:	00 00       	nop
     c38:	00 00       	nop
     c3a:	00 00       	nop
     c3c:	24 08       	sbc	r2, r4
     c3e:	00 00       	nop
     c40:	c2 00       	.word	0x00c2	; ????
     c42:	00 00       	nop
     c44:	33 b8       	out	0x03, r3	; 3
     c46:	00 00       	nop
     c48:	3c 0b       	sbc	r19, r28
     c4a:	00 00       	nop
     c4c:	c2 00       	.word	0x00c2	; ????
     c4e:	00 00       	nop
     c50:	68 13       	cpse	r22, r24
     c52:	00 00       	nop
     c54:	0f 0d       	add	r16, r15
     c56:	00 00       	nop
     c58:	24 00       	.word	0x0024	; ????
     c5a:	08 00       	.word	0x0008	; ????
     c5c:	00 e0       	ldi	r16, 0x00	; 0
     c5e:	01 00       	.word	0x0001	; ????
     c60:	00 00       	nop
     c62:	00 00       	nop
     c64:	2e 00       	.word	0x002e	; ????
     c66:	00 00       	nop
     c68:	00 e0       	ldi	r16, 0x00	; 0
     c6a:	01 00       	.word	0x0001	; ????
     c6c:	00 00       	nop
     c6e:	00 00       	nop
     c70:	44 00       	.word	0x0044	; ????
     c72:	09 00       	.word	0x0009	; ????
	...
     c7c:	44 00       	.word	0x0044	; ????
     c7e:	2b 00       	.word	0x002b	; ????
	...
     c88:	44 00       	.word	0x0044	; ????
     c8a:	2e 00       	.word	0x002e	; ????
     c8c:	02 00       	.word	0x0002	; ????
     c8e:	00 00       	nop
     c90:	00 00       	nop
     c92:	00 00       	nop
     c94:	44 00       	.word	0x0044	; ????
     c96:	39 00       	.word	0x0039	; ????
     c98:	0e 00       	.word	0x000e	; ????
     c9a:	00 00       	nop
     c9c:	00 00       	nop
     c9e:	00 00       	nop
     ca0:	24 00       	.word	0x0024	; ????
     ca2:	00 00       	nop
     ca4:	0e 00       	.word	0x000e	; ????
     ca6:	00 00       	nop
     ca8:	00 00       	nop
     caa:	00 00       	nop
     cac:	4e 00       	.word	0x004e	; ????
     cae:	00 00       	nop
     cb0:	0e e0       	ldi	r16, 0x0E	; 14
     cb2:	01 00       	.word	0x0001	; ????
     cb4:	1e 0d       	add	r17, r14
     cb6:	00 00       	nop
     cb8:	24 00       	.word	0x0024	; ????
     cba:	3c 00       	.word	0x003c	; ????
     cbc:	0e e0       	ldi	r16, 0x0E	; 14
     cbe:	01 00       	.word	0x0001	; ????
     cc0:	00 00       	nop
     cc2:	00 00       	nop
     cc4:	2e 00       	.word	0x002e	; ????
     cc6:	00 00       	nop
     cc8:	0e e0       	ldi	r16, 0x0E	; 14
     cca:	01 00       	.word	0x0001	; ????
     ccc:	00 00       	nop
     cce:	00 00       	nop
     cd0:	44 00       	.word	0x0044	; ????
     cd2:	3d 00       	.word	0x003d	; ????
	...
     cdc:	44 00       	.word	0x0044	; ????
     cde:	3e 00       	.word	0x003e	; ????
	...
     ce8:	24 00       	.word	0x0024	; ????
	...
     cf2:	00 00       	nop
     cf4:	4e 00       	.word	0x004e	; ????
     cf6:	00 00       	nop
     cf8:	0e e0       	ldi	r16, 0x0E	; 14
     cfa:	01 00       	.word	0x0001	; ????
     cfc:	35 0d       	add	r19, r5
     cfe:	00 00       	nop
     d00:	24 00       	.word	0x0024	; ????
     d02:	41 00       	.word	0x0041	; ????
     d04:	1e e0       	ldi	r17, 0x0E	; 14
     d06:	01 00       	.word	0x0001	; ????
     d08:	00 00       	nop
     d0a:	00 00       	nop
     d0c:	2e 00       	.word	0x002e	; ????
     d0e:	00 00       	nop
     d10:	1e e0       	ldi	r17, 0x0E	; 14
     d12:	01 00       	.word	0x0001	; ????
     d14:	00 00       	nop
     d16:	00 00       	nop
     d18:	44 00       	.word	0x0044	; ????
     d1a:	42 00       	.word	0x0042	; ????
	...
     d24:	44 00       	.word	0x0044	; ????
     d26:	44 00       	.word	0x0044	; ????
	...
     d30:	44 00       	.word	0x0044	; ????
     d32:	45 00       	.word	0x0045	; ????
     d34:	02 00       	.word	0x0002	; ????
     d36:	00 00       	nop
     d38:	00 00       	nop
     d3a:	00 00       	nop
     d3c:	24 00       	.word	0x0024	; ????
     d3e:	00 00       	nop
     d40:	02 00       	.word	0x0002	; ????
     d42:	00 00       	nop
     d44:	00 00       	nop
     d46:	00 00       	nop
     d48:	4e 00       	.word	0x004e	; ????
     d4a:	00 00       	nop
     d4c:	20 e0       	ldi	r18, 0x00	; 0
     d4e:	01 00       	.word	0x0001	; ????
     d50:	00 00       	nop
     d52:	00 00       	nop
     d54:	64 00       	.word	0x0064	; ????
     d56:	00 00       	nop
     d58:	0c e1       	ldi	r16, 0x1C	; 28
     d5a:	01 00       	.word	0x0001	; ????
     d5c:	08 00       	.word	0x0008	; ????
     d5e:	00 00       	nop
     d60:	64 00       	.word	0x0064	; ????
     d62:	02 00       	.word	0x0002	; ????
     d64:	0c e1       	ldi	r16, 0x1C	; 28
     d66:	01 00       	.word	0x0001	; ????
     d68:	48 0d       	add	r20, r8
     d6a:	00 00       	nop
     d6c:	64 00       	.word	0x0064	; ????
     d6e:	02 00       	.word	0x0002	; ????
     d70:	0c e1       	ldi	r16, 0x1C	; 28
     d72:	01 00       	.word	0x0001	; ????
     d74:	33 00       	.word	0x0033	; ????
     d76:	00 00       	nop
     d78:	3c 00       	.word	0x003c	; ????
     d7a:	00 00       	nop
     d7c:	00 00       	nop
     d7e:	00 00       	nop
     d80:	42 00       	.word	0x0042	; ????
     d82:	00 00       	nop
     d84:	80 00       	.word	0x0080	; ????
     d86:	00 00       	nop
     d88:	00 00       	nop
     d8a:	00 00       	nop
     d8c:	62 00       	.word	0x0062	; ????
     d8e:	00 00       	nop
     d90:	80 00       	.word	0x0080	; ????
     d92:	00 00       	nop
     d94:	00 00       	nop
     d96:	00 00       	nop
     d98:	7c 00       	.word	0x007c	; ????
     d9a:	00 00       	nop
     d9c:	80 00       	.word	0x0080	; ????
     d9e:	00 00       	nop
     da0:	00 00       	nop
     da2:	00 00       	nop
     da4:	b3 00       	.word	0x00b3	; ????
     da6:	00 00       	nop
     da8:	80 00       	.word	0x0080	; ????
     daa:	00 00       	nop
     dac:	00 00       	nop
     dae:	00 00       	nop
     db0:	d9 00       	.word	0x00d9	; ????
     db2:	00 00       	nop
     db4:	80 00       	.word	0x0080	; ????
     db6:	00 00       	nop
     db8:	00 00       	nop
     dba:	00 00       	nop
     dbc:	0e 01       	movw	r0, r28
     dbe:	00 00       	nop
     dc0:	80 00       	.word	0x0080	; ????
     dc2:	00 00       	nop
     dc4:	00 00       	nop
     dc6:	00 00       	nop
     dc8:	5f 01       	movw	r10, r30
     dca:	00 00       	nop
     dcc:	80 00       	.word	0x0080	; ????
     dce:	00 00       	nop
     dd0:	00 00       	nop
     dd2:	00 00       	nop
     dd4:	a4 01       	movw	r20, r8
     dd6:	00 00       	nop
     dd8:	80 00       	.word	0x0080	; ????
     dda:	00 00       	nop
     ddc:	00 00       	nop
     dde:	00 00       	nop
     de0:	ca 01       	movw	r24, r20
     de2:	00 00       	nop
     de4:	80 00       	.word	0x0080	; ????
     de6:	00 00       	nop
     de8:	00 00       	nop
     dea:	00 00       	nop
     dec:	f6 01       	movw	r30, r12
     dee:	00 00       	nop
     df0:	80 00       	.word	0x0080	; ????
     df2:	00 00       	nop
     df4:	00 00       	nop
     df6:	00 00       	nop
     df8:	20 02       	muls	r18, r16
     dfa:	00 00       	nop
     dfc:	80 00       	.word	0x0080	; ????
     dfe:	00 00       	nop
     e00:	00 00       	nop
     e02:	00 00       	nop
     e04:	49 02       	muls	r20, r25
     e06:	00 00       	nop
     e08:	80 00       	.word	0x0080	; ????
     e0a:	00 00       	nop
     e0c:	00 00       	nop
     e0e:	00 00       	nop
     e10:	63 02       	muls	r22, r19
     e12:	00 00       	nop
     e14:	80 00       	.word	0x0080	; ????
     e16:	00 00       	nop
     e18:	00 00       	nop
     e1a:	00 00       	nop
     e1c:	7e 02       	muls	r23, r30
     e1e:	00 00       	nop
     e20:	80 00       	.word	0x0080	; ????
     e22:	00 00       	nop
     e24:	00 00       	nop
     e26:	00 00       	nop
     e28:	9e 02       	muls	r25, r30
     e2a:	00 00       	nop
     e2c:	80 00       	.word	0x0080	; ????
     e2e:	00 00       	nop
     e30:	00 00       	nop
     e32:	00 00       	nop
     e34:	bf 02       	muls	r27, r31
     e36:	00 00       	nop
     e38:	80 00       	.word	0x0080	; ????
     e3a:	00 00       	nop
     e3c:	00 00       	nop
     e3e:	00 00       	nop
     e40:	da 02       	muls	r29, r26
     e42:	00 00       	nop
     e44:	80 00       	.word	0x0080	; ????
     e46:	00 00       	nop
     e48:	00 00       	nop
     e4a:	00 00       	nop
     e4c:	fa 02       	muls	r31, r26
     e4e:	00 00       	nop
     e50:	80 00       	.word	0x0080	; ????
     e52:	00 00       	nop
     e54:	00 00       	nop
     e56:	00 00       	nop
     e58:	1f 03       	fmul	r17, r23
     e5a:	00 00       	nop
     e5c:	80 00       	.word	0x0080	; ????
     e5e:	00 00       	nop
     e60:	00 00       	nop
     e62:	00 00       	nop
     e64:	49 03       	fmul	r20, r17
     e66:	00 00       	nop
     e68:	80 00       	.word	0x0080	; ????
     e6a:	00 00       	nop
     e6c:	00 00       	nop
     e6e:	00 00       	nop
     e70:	6d 03       	fmul	r22, r21
     e72:	00 00       	nop
     e74:	80 00       	.word	0x0080	; ????
     e76:	00 00       	nop
     e78:	00 00       	nop
     e7a:	00 00       	nop
     e7c:	96 03       	fmuls	r17, r22
     e7e:	00 00       	nop
     e80:	80 00       	.word	0x0080	; ????
     e82:	00 00       	nop
     e84:	00 00       	nop
     e86:	00 00       	nop
     e88:	c4 03       	fmuls	r20, r20
     e8a:	00 00       	nop
     e8c:	80 00       	.word	0x0080	; ????
     e8e:	00 00       	nop
     e90:	00 00       	nop
     e92:	00 00       	nop
     e94:	ea 03       	fmulsu	r22, r18
     e96:	00 00       	nop
     e98:	80 00       	.word	0x0080	; ????
     e9a:	00 00       	nop
     e9c:	00 00       	nop
     e9e:	00 00       	nop
     ea0:	0a 04       	cpc	r0, r10
     ea2:	00 00       	nop
     ea4:	80 00       	.word	0x0080	; ????
     ea6:	00 00       	nop
     ea8:	00 00       	nop
     eaa:	00 00       	nop
     eac:	2f 04       	cpc	r2, r15
     eae:	00 00       	nop
     eb0:	80 00       	.word	0x0080	; ????
     eb2:	00 00       	nop
     eb4:	00 00       	nop
     eb6:	00 00       	nop
     eb8:	59 04       	cpc	r5, r9
     eba:	00 00       	nop
     ebc:	80 00       	.word	0x0080	; ????
     ebe:	00 00       	nop
     ec0:	00 00       	nop
     ec2:	00 00       	nop
     ec4:	88 04       	cpc	r8, r8
     ec6:	00 00       	nop
     ec8:	80 00       	.word	0x0080	; ????
     eca:	00 00       	nop
     ecc:	00 00       	nop
     ece:	00 00       	nop
     ed0:	b1 04       	cpc	r11, r1
     ed2:	00 00       	nop
     ed4:	80 00       	.word	0x0080	; ????
     ed6:	00 00       	nop
     ed8:	00 00       	nop
     eda:	00 00       	nop
     edc:	df 04       	cpc	r13, r15
     ede:	00 00       	nop
     ee0:	80 00       	.word	0x0080	; ????
     ee2:	00 00       	nop
     ee4:	00 00       	nop
     ee6:	00 00       	nop
     ee8:	12 05       	cpc	r17, r2
     eea:	00 00       	nop
     eec:	80 00       	.word	0x0080	; ????
     eee:	00 00       	nop
     ef0:	00 00       	nop
     ef2:	00 00       	nop
     ef4:	33 05       	cpc	r19, r3
     ef6:	00 00       	nop
     ef8:	80 00       	.word	0x0080	; ????
     efa:	00 00       	nop
     efc:	00 00       	nop
     efe:	00 00       	nop
     f00:	4e 05       	cpc	r20, r14
     f02:	00 00       	nop
     f04:	80 00       	.word	0x0080	; ????
     f06:	00 00       	nop
     f08:	00 00       	nop
     f0a:	00 00       	nop
     f0c:	6e 05       	cpc	r22, r14
     f0e:	00 00       	nop
     f10:	80 00       	.word	0x0080	; ????
     f12:	00 00       	nop
     f14:	00 00       	nop
     f16:	00 00       	nop
     f18:	93 05       	cpc	r25, r3
     f1a:	00 00       	nop
     f1c:	80 00       	.word	0x0080	; ????
     f1e:	00 00       	nop
     f20:	00 00       	nop
     f22:	00 00       	nop
     f24:	bd 05       	cpc	r27, r13
     f26:	00 00       	nop
     f28:	80 00       	.word	0x0080	; ????
     f2a:	00 00       	nop
     f2c:	00 00       	nop
     f2e:	00 00       	nop
     f30:	e1 05       	cpc	r30, r1
     f32:	00 00       	nop
     f34:	80 00       	.word	0x0080	; ????
     f36:	00 00       	nop
     f38:	00 00       	nop
     f3a:	00 00       	nop
     f3c:	0a 06       	cpc	r0, r26
     f3e:	00 00       	nop
     f40:	80 00       	.word	0x0080	; ????
     f42:	00 00       	nop
     f44:	00 00       	nop
     f46:	00 00       	nop
     f48:	38 06       	cpc	r3, r24
     f4a:	00 00       	nop
     f4c:	80 00       	.word	0x0080	; ????
     f4e:	00 00       	nop
     f50:	00 00       	nop
     f52:	00 00       	nop
     f54:	5e 06       	cpc	r5, r30
     f56:	00 00       	nop
     f58:	80 00       	.word	0x0080	; ????
     f5a:	00 00       	nop
     f5c:	00 00       	nop
     f5e:	00 00       	nop
     f60:	7e 06       	cpc	r7, r30
     f62:	00 00       	nop
     f64:	80 00       	.word	0x0080	; ????
     f66:	00 00       	nop
     f68:	00 00       	nop
     f6a:	00 00       	nop
     f6c:	a3 06       	cpc	r10, r19
     f6e:	00 00       	nop
     f70:	80 00       	.word	0x0080	; ????
     f72:	00 00       	nop
     f74:	00 00       	nop
     f76:	00 00       	nop
     f78:	cd 06       	cpc	r12, r29
     f7a:	00 00       	nop
     f7c:	80 00       	.word	0x0080	; ????
     f7e:	00 00       	nop
     f80:	00 00       	nop
     f82:	00 00       	nop
     f84:	fc 06       	cpc	r15, r28
     f86:	00 00       	nop
     f88:	80 00       	.word	0x0080	; ????
     f8a:	00 00       	nop
     f8c:	00 00       	nop
     f8e:	00 00       	nop
     f90:	25 07       	cpc	r18, r21
     f92:	00 00       	nop
     f94:	80 00       	.word	0x0080	; ????
     f96:	00 00       	nop
     f98:	00 00       	nop
     f9a:	00 00       	nop
     f9c:	53 07       	cpc	r21, r19
     f9e:	00 00       	nop
     fa0:	80 00       	.word	0x0080	; ????
     fa2:	00 00       	nop
     fa4:	00 00       	nop
     fa6:	00 00       	nop
     fa8:	86 07       	cpc	r24, r22
     faa:	00 00       	nop
     fac:	80 00       	.word	0x0080	; ????
     fae:	00 00       	nop
     fb0:	00 00       	nop
     fb2:	00 00       	nop
     fb4:	9a 07       	cpc	r25, r26
     fb6:	00 00       	nop
     fb8:	c2 00       	.word	0x00c2	; ????
     fba:	00 00       	nop
     fbc:	00 00       	nop
     fbe:	00 00       	nop
     fc0:	b8 07       	cpc	r27, r24
     fc2:	00 00       	nop
     fc4:	c2 00       	.word	0x00c2	; ????
     fc6:	00 00       	nop
     fc8:	00 00       	nop
     fca:	00 00       	nop
     fcc:	dc 07       	cpc	r29, r28
     fce:	00 00       	nop
     fd0:	c2 00       	.word	0x00c2	; ????
     fd2:	00 00       	nop
     fd4:	25 0f       	add	r18, r21
     fd6:	00 00       	nop
     fd8:	fc 07       	cpc	r31, r28
     fda:	00 00       	nop
     fdc:	c2 00       	.word	0x00c2	; ????
     fde:	00 00       	nop
     fe0:	00 00       	nop
     fe2:	00 00       	nop
     fe4:	24 08       	sbc	r2, r4
     fe6:	00 00       	nop
     fe8:	c2 00       	.word	0x00c2	; ????
     fea:	00 00       	nop
     fec:	33 b8       	out	0x03, r3	; 3
     fee:	00 00       	nop
     ff0:	3c 0b       	sbc	r19, r28
     ff2:	00 00       	nop
     ff4:	c2 00       	.word	0x00c2	; ????
     ff6:	00 00       	nop
     ff8:	68 13       	cpse	r22, r24
     ffa:	00 00       	nop
     ffc:	59 0d       	add	r21, r9
     ffe:	00 00       	nop
    1000:	82 00       	.word	0x0082	; ????
    1002:	00 00       	nop
    1004:	32 2b       	or	r19, r18
    1006:	00 00       	nop
    1008:	76 0d       	add	r23, r6
    100a:	00 00       	nop
    100c:	82 00       	.word	0x0082	; ????
    100e:	00 00       	nop
    1010:	8e 0e       	add	r8, r30
    1012:	00 00       	nop
    1014:	9e 0d       	add	r25, r14
    1016:	00 00       	nop
    1018:	80 00       	.word	0x0080	; ????
    101a:	28 00       	.word	0x0028	; ????
    101c:	00 00       	nop
    101e:	00 00       	nop
    1020:	c2 0d       	add	r28, r2
    1022:	00 00       	nop
    1024:	80 00       	.word	0x0080	; ????
    1026:	62 00       	.word	0x0062	; ????
	...
    1030:	a2 00       	.word	0x00a2	; ????
    1032:	00 00       	nop
    1034:	00 00       	nop
    1036:	00 00       	nop
    1038:	d7 0d       	add	r29, r7
    103a:	00 00       	nop
    103c:	82 00       	.word	0x0082	; ????
    103e:	00 00       	nop
    1040:	d8 04       	cpc	r13, r8
    1042:	00 00       	nop
    1044:	ff 0d       	add	r31, r15
    1046:	00 00       	nop
    1048:	80 00       	.word	0x0080	; ????
    104a:	d4 00       	.word	0x00d4	; ????
	...
    1054:	a2 00       	.word	0x00a2	; ????
    1056:	00 00       	nop
    1058:	00 00       	nop
    105a:	00 00       	nop
    105c:	13 0e       	add	r1, r19
    105e:	00 00       	nop
    1060:	80 00       	.word	0x0080	; ????
	...
    106a:	00 00       	nop
    106c:	a2 00       	.word	0x00a2	; ????
    106e:	00 00       	nop
    1070:	00 00       	nop
    1072:	00 00       	nop
    1074:	d6 0e       	add	r13, r22
    1076:	00 00       	nop
    1078:	82 00       	.word	0x0082	; ????
    107a:	00 00       	nop
    107c:	00 00       	nop
    107e:	00 00       	nop
    1080:	f6 0e       	add	r15, r22
    1082:	00 00       	nop
    1084:	82 00       	.word	0x0082	; ????
    1086:	00 00       	nop
    1088:	00 00       	nop
    108a:	00 00       	nop
    108c:	d7 0d       	add	r29, r7
    108e:	00 00       	nop
    1090:	82 00       	.word	0x0082	; ????
    1092:	00 00       	nop
    1094:	39 0b       	sbc	r19, r25
    1096:	00 00       	nop
    1098:	18 0f       	add	r17, r24
    109a:	00 00       	nop
    109c:	80 00       	.word	0x0080	; ????
    109e:	93 00       	.word	0x0093	; ????
    10a0:	00 00       	nop
    10a2:	00 00       	nop
    10a4:	30 0f       	add	r19, r16
    10a6:	00 00       	nop
    10a8:	80 00       	.word	0x0080	; ????
    10aa:	44 01       	movw	r8, r8
	...
    10b4:	a2 00       	.word	0x00a2	; ????
	...
    10be:	00 00       	nop
    10c0:	a2 00       	.word	0x00a2	; ????
	...
    10ca:	00 00       	nop
    10cc:	a2 00       	.word	0x00a2	; ????
    10ce:	00 00       	nop
    10d0:	00 00       	nop
    10d2:	00 00       	nop
    10d4:	46 0f       	add	r20, r22
    10d6:	00 00       	nop
    10d8:	24 00       	.word	0x0024	; ????
    10da:	59 00       	.word	0x0059	; ????
    10dc:	0c e1       	ldi	r16, 0x1C	; 28
    10de:	01 00       	.word	0x0001	; ????
    10e0:	00 00       	nop
    10e2:	00 00       	nop
    10e4:	2e 00       	.word	0x002e	; ????
    10e6:	00 00       	nop
    10e8:	0c e1       	ldi	r16, 0x1C	; 28
    10ea:	01 00       	.word	0x0001	; ????
    10ec:	00 00       	nop
    10ee:	00 00       	nop
    10f0:	44 00       	.word	0x0044	; ????
    10f2:	5a 00       	.word	0x005a	; ????
    10f4:	00 00       	nop
    10f6:	00 00       	nop
    10f8:	5c 0f       	add	r21, r28
    10fa:	00 00       	nop
    10fc:	84 00       	.word	0x0084	; ????
    10fe:	00 00       	nop
    1100:	16 e1       	ldi	r17, 0x16	; 22
    1102:	01 00       	.word	0x0001	; ????
    1104:	00 00       	nop
    1106:	00 00       	nop
    1108:	44 00       	.word	0x0044	; ????
    110a:	a9 01       	movw	r20, r18
    110c:	0a 00       	.word	0x000a	; ????
    110e:	00 00       	nop
    1110:	48 0d       	add	r20, r8
    1112:	00 00       	nop
    1114:	84 00       	.word	0x0084	; ????
    1116:	00 00       	nop
    1118:	2a e1       	ldi	r18, 0x1A	; 26
    111a:	01 00       	.word	0x0001	; ????
    111c:	00 00       	nop
    111e:	00 00       	nop
    1120:	44 00       	.word	0x0044	; ????
    1122:	60 00       	.word	0x0060	; ????
    1124:	1e 00       	.word	0x001e	; ????
    1126:	00 00       	nop
    1128:	00 00       	nop
    112a:	00 00       	nop
    112c:	44 00       	.word	0x0044	; ????
    112e:	63 00       	.word	0x0063	; ????
    1130:	2c 00       	.word	0x002c	; ????
    1132:	00 00       	nop
    1134:	00 00       	nop
    1136:	00 00       	nop
    1138:	44 00       	.word	0x0044	; ????
    113a:	66 00       	.word	0x0066	; ????
    113c:	36 00       	.word	0x0036	; ????
    113e:	00 00       	nop
    1140:	00 00       	nop
    1142:	00 00       	nop
    1144:	44 00       	.word	0x0044	; ????
    1146:	69 00       	.word	0x0069	; ????
    1148:	38 00       	.word	0x0038	; ????
    114a:	00 00       	nop
    114c:	00 00       	nop
    114e:	00 00       	nop
    1150:	44 00       	.word	0x0044	; ????
    1152:	6e 00       	.word	0x006e	; ????
    1154:	3a 00       	.word	0x003a	; ????
    1156:	00 00       	nop
    1158:	00 00       	nop
    115a:	00 00       	nop
    115c:	44 00       	.word	0x0044	; ????
    115e:	6f 00       	.word	0x006f	; ????
    1160:	40 00       	.word	0x0040	; ????
    1162:	00 00       	nop
    1164:	00 00       	nop
    1166:	00 00       	nop
    1168:	44 00       	.word	0x0044	; ????
    116a:	70 00       	.word	0x0070	; ????
    116c:	46 00       	.word	0x0046	; ????
    116e:	00 00       	nop
    1170:	00 00       	nop
    1172:	00 00       	nop
    1174:	44 00       	.word	0x0044	; ????
    1176:	71 00       	.word	0x0071	; ????
    1178:	50 00       	.word	0x0050	; ????
    117a:	00 00       	nop
    117c:	00 00       	nop
    117e:	00 00       	nop
    1180:	44 00       	.word	0x0044	; ????
    1182:	74 00       	.word	0x0074	; ????
    1184:	54 00       	.word	0x0054	; ????
    1186:	00 00       	nop
    1188:	5c 0f       	add	r21, r28
    118a:	00 00       	nop
    118c:	84 00       	.word	0x0084	; ????
    118e:	00 00       	nop
    1190:	62 e1       	ldi	r22, 0x12	; 18
    1192:	01 00       	.word	0x0001	; ????
    1194:	00 00       	nop
    1196:	00 00       	nop
    1198:	44 00       	.word	0x0044	; ????
    119a:	d3 01       	movw	r26, r6
    119c:	56 00       	.word	0x0056	; ????
    119e:	00 00       	nop
    11a0:	48 0d       	add	r20, r8
    11a2:	00 00       	nop
    11a4:	84 00       	.word	0x0084	; ????
    11a6:	00 00       	nop
    11a8:	78 e1       	ldi	r23, 0x18	; 24
    11aa:	01 00       	.word	0x0001	; ????
    11ac:	00 00       	nop
    11ae:	00 00       	nop
    11b0:	44 00       	.word	0x0044	; ????
    11b2:	78 00       	.word	0x0078	; ????
    11b4:	6c 00       	.word	0x006c	; ????
    11b6:	00 00       	nop
    11b8:	00 00       	nop
    11ba:	00 00       	nop
    11bc:	44 00       	.word	0x0044	; ????
    11be:	79 00       	.word	0x0079	; ????
    11c0:	70 00       	.word	0x0070	; ????
    11c2:	00 00       	nop
    11c4:	7b 0f       	add	r23, r27
    11c6:	00 00       	nop
    11c8:	40 00       	.word	0x0040	; ????
    11ca:	6e 00       	.word	0x006e	; ????
    11cc:	0c 00       	.word	0x000c	; ????
    11ce:	00 00       	nop
    11d0:	00 00       	nop
    11d2:	00 00       	nop
    11d4:	c0 00       	.word	0x00c0	; ????
    11d6:	00 00       	nop
    11d8:	3a 00       	.word	0x003a	; ????
    11da:	00 00       	nop
    11dc:	00 00       	nop
    11de:	00 00       	nop
    11e0:	e0 00       	.word	0x00e0	; ????
    11e2:	00 00       	nop
    11e4:	40 00       	.word	0x0040	; ????
    11e6:	00 00       	nop
    11e8:	00 00       	nop
    11ea:	00 00       	nop
    11ec:	24 00       	.word	0x0024	; ????
    11ee:	00 00       	nop
    11f0:	7c 00       	.word	0x007c	; ????
    11f2:	00 00       	nop
    11f4:	00 00       	nop
    11f6:	00 00       	nop
    11f8:	4e 00       	.word	0x004e	; ????
    11fa:	00 00       	nop
    11fc:	88 e1       	ldi	r24, 0x18	; 24
    11fe:	01 00       	.word	0x0001	; ????
    1200:	8b 0f       	add	r24, r27
    1202:	00 00       	nop
    1204:	24 00       	.word	0x0024	; ????
    1206:	7f 00       	.word	0x007f	; ????
    1208:	88 e1       	ldi	r24, 0x18	; 24
    120a:	01 00       	.word	0x0001	; ????
    120c:	00 00       	nop
    120e:	00 00       	nop
    1210:	2e 00       	.word	0x002e	; ????
    1212:	00 00       	nop
    1214:	88 e1       	ldi	r24, 0x18	; 24
    1216:	01 00       	.word	0x0001	; ????
    1218:	00 00       	nop
    121a:	00 00       	nop
    121c:	44 00       	.word	0x0044	; ????
    121e:	80 00       	.word	0x0080	; ????
    1220:	00 00       	nop
    1222:	00 00       	nop
    1224:	5c 0f       	add	r21, r28
    1226:	00 00       	nop
    1228:	84 00       	.word	0x0084	; ????
    122a:	00 00       	nop
    122c:	88 e1       	ldi	r24, 0x18	; 24
    122e:	01 00       	.word	0x0001	; ????
    1230:	00 00       	nop
    1232:	00 00       	nop
    1234:	44 00       	.word	0x0044	; ????
    1236:	a9 01       	movw	r20, r18
    1238:	00 00       	nop
    123a:	00 00       	nop
    123c:	48 0d       	add	r20, r8
    123e:	00 00       	nop
    1240:	84 00       	.word	0x0084	; ????
    1242:	00 00       	nop
    1244:	9c e1       	ldi	r25, 0x1C	; 28
    1246:	01 00       	.word	0x0001	; ????
    1248:	00 00       	nop
    124a:	00 00       	nop
    124c:	44 00       	.word	0x0044	; ????
    124e:	85 00       	.word	0x0085	; ????
    1250:	14 00       	.word	0x0014	; ????
    1252:	00 00       	nop
    1254:	00 00       	nop
    1256:	00 00       	nop
    1258:	44 00       	.word	0x0044	; ????
    125a:	86 00       	.word	0x0086	; ????
    125c:	28 00       	.word	0x0028	; ????
    125e:	00 00       	nop
    1260:	00 00       	nop
    1262:	00 00       	nop
    1264:	44 00       	.word	0x0044	; ????
    1266:	87 00       	.word	0x0087	; ????
    1268:	2e 00       	.word	0x002e	; ????
    126a:	00 00       	nop
    126c:	00 00       	nop
    126e:	00 00       	nop
    1270:	44 00       	.word	0x0044	; ????
    1272:	88 00       	.word	0x0088	; ????
    1274:	34 00       	.word	0x0034	; ????
    1276:	00 00       	nop
    1278:	00 00       	nop
    127a:	00 00       	nop
    127c:	44 00       	.word	0x0044	; ????
    127e:	8a 00       	.word	0x008a	; ????
    1280:	3c 00       	.word	0x003c	; ????
    1282:	00 00       	nop
    1284:	00 00       	nop
    1286:	00 00       	nop
    1288:	44 00       	.word	0x0044	; ????
    128a:	8d 00       	.word	0x008d	; ????
    128c:	3e 00       	.word	0x003e	; ????
    128e:	00 00       	nop
    1290:	00 00       	nop
    1292:	00 00       	nop
    1294:	44 00       	.word	0x0044	; ????
    1296:	8e 00       	.word	0x008e	; ????
    1298:	52 00       	.word	0x0052	; ????
    129a:	00 00       	nop
    129c:	00 00       	nop
    129e:	00 00       	nop
    12a0:	44 00       	.word	0x0044	; ????
    12a2:	8f 00       	.word	0x008f	; ????
    12a4:	58 00       	.word	0x0058	; ????
    12a6:	00 00       	nop
    12a8:	00 00       	nop
    12aa:	00 00       	nop
    12ac:	44 00       	.word	0x0044	; ????
    12ae:	90 00       	.word	0x0090	; ????
    12b0:	5e 00       	.word	0x005e	; ????
    12b2:	00 00       	nop
    12b4:	00 00       	nop
    12b6:	00 00       	nop
    12b8:	44 00       	.word	0x0044	; ????
    12ba:	92 00       	.word	0x0092	; ????
    12bc:	66 00       	.word	0x0066	; ????
    12be:	00 00       	nop
    12c0:	00 00       	nop
    12c2:	00 00       	nop
    12c4:	44 00       	.word	0x0044	; ????
    12c6:	95 00       	.word	0x0095	; ????
    12c8:	68 00       	.word	0x0068	; ????
    12ca:	00 00       	nop
    12cc:	00 00       	nop
    12ce:	00 00       	nop
    12d0:	44 00       	.word	0x0044	; ????
    12d2:	95 00       	.word	0x0095	; ????
    12d4:	70 00       	.word	0x0070	; ????
    12d6:	00 00       	nop
    12d8:	00 00       	nop
    12da:	00 00       	nop
    12dc:	44 00       	.word	0x0044	; ????
    12de:	98 00       	.word	0x0098	; ????
    12e0:	7a 00       	.word	0x007a	; ????
    12e2:	00 00       	nop
    12e4:	00 00       	nop
    12e6:	00 00       	nop
    12e8:	44 00       	.word	0x0044	; ????
    12ea:	99 00       	.word	0x0099	; ????
    12ec:	80 00       	.word	0x0080	; ????
    12ee:	00 00       	nop
    12f0:	00 00       	nop
    12f2:	00 00       	nop
    12f4:	44 00       	.word	0x0044	; ????
    12f6:	9c 00       	.word	0x009c	; ????
    12f8:	82 00       	.word	0x0082	; ????
    12fa:	00 00       	nop
    12fc:	00 00       	nop
    12fe:	00 00       	nop
    1300:	44 00       	.word	0x0044	; ????
    1302:	9d 00       	.word	0x009d	; ????
    1304:	86 00       	.word	0x0086	; ????
    1306:	00 00       	nop
    1308:	00 00       	nop
    130a:	00 00       	nop
    130c:	44 00       	.word	0x0044	; ????
    130e:	95 00       	.word	0x0095	; ????
    1310:	88 00       	.word	0x0088	; ????
    1312:	00 00       	nop
    1314:	00 00       	nop
    1316:	00 00       	nop
    1318:	44 00       	.word	0x0044	; ????
    131a:	a0 00       	.word	0x00a0	; ????
    131c:	94 00       	.word	0x0094	; ????
    131e:	00 00       	nop
    1320:	00 00       	nop
    1322:	00 00       	nop
    1324:	24 00       	.word	0x0024	; ????
    1326:	00 00       	nop
    1328:	96 00       	.word	0x0096	; ????
    132a:	00 00       	nop
    132c:	00 00       	nop
    132e:	00 00       	nop
    1330:	4e 00       	.word	0x004e	; ????
    1332:	00 00       	nop
    1334:	1e e2       	ldi	r17, 0x2E	; 46
    1336:	01 00       	.word	0x0001	; ????
    1338:	9c 0f       	add	r25, r28
    133a:	00 00       	nop
    133c:	24 00       	.word	0x0024	; ????
    133e:	a3 00       	.word	0x00a3	; ????
    1340:	1e e2       	ldi	r17, 0x2E	; 46
    1342:	01 00       	.word	0x0001	; ????
    1344:	ae 0f       	add	r26, r30
    1346:	00 00       	nop
    1348:	40 00       	.word	0x0040	; ????
    134a:	a3 00       	.word	0x00a3	; ????
    134c:	10 00       	.word	0x0010	; ????
    134e:	00 00       	nop
    1350:	c3 0f       	add	r28, r19
    1352:	00 00       	nop
    1354:	40 00       	.word	0x0040	; ????
    1356:	a3 00       	.word	0x00a3	; ????
    1358:	0e 00       	.word	0x000e	; ????
    135a:	00 00       	nop
    135c:	00 00       	nop
    135e:	00 00       	nop
    1360:	2e 00       	.word	0x002e	; ????
    1362:	00 00       	nop
    1364:	1e e2       	ldi	r17, 0x2E	; 46
    1366:	01 00       	.word	0x0001	; ????
    1368:	00 00       	nop
    136a:	00 00       	nop
    136c:	44 00       	.word	0x0044	; ????
    136e:	a4 00       	.word	0x00a4	; ????
	...
    1378:	44 00       	.word	0x0044	; ????
    137a:	a9 00       	.word	0x00a9	; ????
    137c:	10 00       	.word	0x0010	; ????
    137e:	00 00       	nop
    1380:	00 00       	nop
    1382:	00 00       	nop
    1384:	44 00       	.word	0x0044	; ????
    1386:	aa 00       	.word	0x00aa	; ????
    1388:	14 00       	.word	0x0014	; ????
    138a:	00 00       	nop
    138c:	00 00       	nop
    138e:	00 00       	nop
    1390:	44 00       	.word	0x0044	; ????
    1392:	ab 00       	.word	0x00ab	; ????
    1394:	1c 00       	.word	0x001c	; ????
    1396:	00 00       	nop
    1398:	00 00       	nop
    139a:	00 00       	nop
    139c:	44 00       	.word	0x0044	; ????
    139e:	ac 00       	.word	0x00ac	; ????
    13a0:	20 00       	.word	0x0020	; ????
    13a2:	00 00       	nop
    13a4:	00 00       	nop
    13a6:	00 00       	nop
    13a8:	44 00       	.word	0x0044	; ????
    13aa:	ae 00       	.word	0x00ae	; ????
    13ac:	24 00       	.word	0x0024	; ????
    13ae:	00 00       	nop
    13b0:	00 00       	nop
    13b2:	00 00       	nop
    13b4:	44 00       	.word	0x0044	; ????
    13b6:	af 00       	.word	0x00af	; ????
    13b8:	28 00       	.word	0x0028	; ????
    13ba:	00 00       	nop
    13bc:	00 00       	nop
    13be:	00 00       	nop
    13c0:	44 00       	.word	0x0044	; ????
    13c2:	b1 00       	.word	0x00b1	; ????
    13c4:	2a 00       	.word	0x002a	; ????
    13c6:	00 00       	nop
    13c8:	00 00       	nop
    13ca:	00 00       	nop
    13cc:	44 00       	.word	0x0044	; ????
    13ce:	ae 00       	.word	0x00ae	; ????
    13d0:	3a 00       	.word	0x003a	; ????
    13d2:	00 00       	nop
    13d4:	00 00       	nop
    13d6:	00 00       	nop
    13d8:	44 00       	.word	0x0044	; ????
    13da:	b5 00       	.word	0x00b5	; ????
    13dc:	48 00       	.word	0x0048	; ????
    13de:	00 00       	nop
    13e0:	d6 0f       	add	r29, r22
    13e2:	00 00       	nop
    13e4:	40 00       	.word	0x0040	; ????
    13e6:	ae 00       	.word	0x00ae	; ????
    13e8:	0c 00       	.word	0x000c	; ????
    13ea:	00 00       	nop
    13ec:	00 00       	nop
    13ee:	00 00       	nop
    13f0:	c0 00       	.word	0x00c0	; ????
    13f2:	00 00       	nop
    13f4:	24 00       	.word	0x0024	; ????
    13f6:	00 00       	nop
    13f8:	00 00       	nop
    13fa:	00 00       	nop
    13fc:	e0 00       	.word	0x00e0	; ????
    13fe:	00 00       	nop
    1400:	48 00       	.word	0x0048	; ????
    1402:	00 00       	nop
    1404:	00 00       	nop
    1406:	00 00       	nop
    1408:	24 00       	.word	0x0024	; ????
    140a:	00 00       	nop
    140c:	54 00       	.word	0x0054	; ????
    140e:	00 00       	nop
    1410:	00 00       	nop
    1412:	00 00       	nop
    1414:	4e 00       	.word	0x004e	; ????
    1416:	00 00       	nop
    1418:	72 e2       	ldi	r23, 0x22	; 34
    141a:	01 00       	.word	0x0001	; ????
    141c:	df 0f       	add	r29, r31
    141e:	00 00       	nop
    1420:	24 00       	.word	0x0024	; ????
    1422:	21 01       	movw	r4, r2
    1424:	72 e2       	ldi	r23, 0x22	; 34
    1426:	01 00       	.word	0x0001	; ????
    1428:	f5 0f       	add	r31, r21
    142a:	00 00       	nop
    142c:	40 00       	.word	0x0040	; ????
    142e:	21 01       	movw	r4, r2
    1430:	16 00       	.word	0x0016	; ????
    1432:	00 00       	nop
    1434:	09 10       	cpse	r0, r9
    1436:	00 00       	nop
    1438:	40 00       	.word	0x0040	; ????
    143a:	21 01       	movw	r4, r2
    143c:	14 00       	.word	0x0014	; ????
    143e:	00 00       	nop
    1440:	00 00       	nop
    1442:	00 00       	nop
    1444:	2e 00       	.word	0x002e	; ????
    1446:	00 00       	nop
    1448:	72 e2       	ldi	r23, 0x22	; 34
    144a:	01 00       	.word	0x0001	; ????
    144c:	00 00       	nop
    144e:	00 00       	nop
    1450:	44 00       	.word	0x0044	; ????
    1452:	22 01       	movw	r4, r4
	...
    145c:	44 00       	.word	0x0044	; ????
    145e:	25 01       	movw	r4, r10
    1460:	0c 00       	.word	0x000c	; ????
    1462:	00 00       	nop
    1464:	00 00       	nop
    1466:	00 00       	nop
    1468:	44 00       	.word	0x0044	; ????
    146a:	25 01       	movw	r4, r10
    146c:	12 00       	.word	0x0012	; ????
    146e:	00 00       	nop
    1470:	00 00       	nop
    1472:	00 00       	nop
    1474:	44 00       	.word	0x0044	; ????
    1476:	25 01       	movw	r4, r10
    1478:	16 00       	.word	0x0016	; ????
    147a:	00 00       	nop
    147c:	00 00       	nop
    147e:	00 00       	nop
    1480:	44 00       	.word	0x0044	; ????
    1482:	27 01       	movw	r4, r14
    1484:	28 00       	.word	0x0028	; ????
    1486:	00 00       	nop
    1488:	00 00       	nop
    148a:	00 00       	nop
    148c:	44 00       	.word	0x0044	; ????
    148e:	2b 01       	movw	r4, r22
    1490:	2c 00       	.word	0x002c	; ????
    1492:	00 00       	nop
    1494:	00 00       	nop
    1496:	00 00       	nop
    1498:	44 00       	.word	0x0044	; ????
    149a:	29 01       	movw	r4, r18
    149c:	34 00       	.word	0x0034	; ????
    149e:	00 00       	nop
    14a0:	00 00       	nop
    14a2:	00 00       	nop
    14a4:	44 00       	.word	0x0044	; ????
    14a6:	2a 01       	movw	r4, r20
    14a8:	36 00       	.word	0x0036	; ????
    14aa:	00 00       	nop
    14ac:	00 00       	nop
    14ae:	00 00       	nop
    14b0:	44 00       	.word	0x0044	; ????
    14b2:	2b 01       	movw	r4, r22
    14b4:	44 00       	.word	0x0044	; ????
    14b6:	00 00       	nop
    14b8:	00 00       	nop
    14ba:	00 00       	nop
    14bc:	44 00       	.word	0x0044	; ????
    14be:	2b 01       	movw	r4, r22
    14c0:	4a 00       	.word	0x004a	; ????
    14c2:	00 00       	nop
    14c4:	00 00       	nop
    14c6:	00 00       	nop
    14c8:	44 00       	.word	0x0044	; ????
    14ca:	2b 01       	movw	r4, r22
    14cc:	4e 00       	.word	0x004e	; ????
    14ce:	00 00       	nop
    14d0:	00 00       	nop
    14d2:	00 00       	nop
    14d4:	44 00       	.word	0x0044	; ????
    14d6:	27 01       	movw	r4, r14
    14d8:	5e 00       	.word	0x005e	; ????
    14da:	00 00       	nop
    14dc:	00 00       	nop
    14de:	00 00       	nop
    14e0:	44 00       	.word	0x0044	; ????
    14e2:	2e 01       	movw	r4, r28
    14e4:	74 00       	.word	0x0074	; ????
    14e6:	00 00       	nop
    14e8:	00 00       	nop
    14ea:	00 00       	nop
    14ec:	44 00       	.word	0x0044	; ????
    14ee:	2e 01       	movw	r4, r28
    14f0:	7a 00       	.word	0x007a	; ????
    14f2:	00 00       	nop
    14f4:	00 00       	nop
    14f6:	00 00       	nop
    14f8:	44 00       	.word	0x0044	; ????
    14fa:	2e 01       	movw	r4, r28
    14fc:	7e 00       	.word	0x007e	; ????
    14fe:	00 00       	nop
    1500:	00 00       	nop
    1502:	00 00       	nop
    1504:	44 00       	.word	0x0044	; ????
    1506:	2f 01       	movw	r4, r30
    1508:	8c 00       	.word	0x008c	; ????
    150a:	00 00       	nop
    150c:	00 00       	nop
    150e:	00 00       	nop
    1510:	44 00       	.word	0x0044	; ????
    1512:	2f 01       	movw	r4, r30
    1514:	92 00       	.word	0x0092	; ????
    1516:	00 00       	nop
    1518:	00 00       	nop
    151a:	00 00       	nop
    151c:	44 00       	.word	0x0044	; ????
    151e:	2f 01       	movw	r4, r30
    1520:	96 00       	.word	0x0096	; ????
    1522:	00 00       	nop
    1524:	00 00       	nop
    1526:	00 00       	nop
    1528:	44 00       	.word	0x0044	; ????
    152a:	30 01       	movw	r6, r0
    152c:	9e 00       	.word	0x009e	; ????
    152e:	00 00       	nop
    1530:	d6 0f       	add	r29, r22
    1532:	00 00       	nop
    1534:	40 00       	.word	0x0040	; ????
    1536:	23 01       	movw	r4, r6
    1538:	12 00       	.word	0x0012	; ????
    153a:	00 00       	nop
    153c:	00 00       	nop
    153e:	00 00       	nop
    1540:	c0 00       	.word	0x00c0	; ????
	...
    154a:	00 00       	nop
    154c:	e0 00       	.word	0x00e0	; ????
    154e:	00 00       	nop
    1550:	ac 00       	.word	0x00ac	; ????
    1552:	00 00       	nop
    1554:	00 00       	nop
    1556:	00 00       	nop
    1558:	24 00       	.word	0x0024	; ????
    155a:	00 00       	nop
    155c:	ac 00       	.word	0x00ac	; ????
    155e:	00 00       	nop
    1560:	00 00       	nop
    1562:	00 00       	nop
    1564:	4e 00       	.word	0x004e	; ????
    1566:	00 00       	nop
    1568:	1e e3       	ldi	r17, 0x3E	; 62
    156a:	01 00       	.word	0x0001	; ????
    156c:	16 10       	cpse	r1, r6
    156e:	00 00       	nop
    1570:	24 00       	.word	0x0024	; ????
    1572:	bb 00       	.word	0x00bb	; ????
    1574:	1e e3       	ldi	r17, 0x3E	; 62
    1576:	01 00       	.word	0x0001	; ????
    1578:	00 00       	nop
    157a:	00 00       	nop
    157c:	2e 00       	.word	0x002e	; ????
    157e:	00 00       	nop
    1580:	1e e3       	ldi	r17, 0x3E	; 62
    1582:	01 00       	.word	0x0001	; ????
    1584:	00 00       	nop
    1586:	00 00       	nop
    1588:	44 00       	.word	0x0044	; ????
    158a:	bc 00       	.word	0x00bc	; ????
    158c:	00 00       	nop
    158e:	00 00       	nop
    1590:	5c 0f       	add	r21, r28
    1592:	00 00       	nop
    1594:	84 00       	.word	0x0084	; ????
    1596:	00 00       	nop
    1598:	2a e3       	ldi	r18, 0x3A	; 58
    159a:	01 00       	.word	0x0001	; ????
    159c:	00 00       	nop
    159e:	00 00       	nop
    15a0:	44 00       	.word	0x0044	; ????
    15a2:	a9 01       	movw	r20, r18
    15a4:	0c 00       	.word	0x000c	; ????
    15a6:	00 00       	nop
    15a8:	48 0d       	add	r20, r8
    15aa:	00 00       	nop
    15ac:	84 00       	.word	0x0084	; ????
    15ae:	00 00       	nop
    15b0:	3e e3       	ldi	r19, 0x3E	; 62
    15b2:	01 00       	.word	0x0001	; ????
    15b4:	00 00       	nop
    15b6:	00 00       	nop
    15b8:	44 00       	.word	0x0044	; ????
    15ba:	cc 00       	.word	0x00cc	; ????
    15bc:	20 00       	.word	0x0020	; ????
    15be:	00 00       	nop
    15c0:	00 00       	nop
    15c2:	00 00       	nop
    15c4:	44 00       	.word	0x0044	; ????
    15c6:	ce 00       	.word	0x00ce	; ????
    15c8:	28 00       	.word	0x0028	; ????
    15ca:	00 00       	nop
    15cc:	00 00       	nop
    15ce:	00 00       	nop
    15d0:	44 00       	.word	0x0044	; ????
    15d2:	d2 00       	.word	0x00d2	; ????
    15d4:	2a 00       	.word	0x002a	; ????
    15d6:	00 00       	nop
    15d8:	00 00       	nop
    15da:	00 00       	nop
    15dc:	44 00       	.word	0x0044	; ????
    15de:	d3 00       	.word	0x00d3	; ????
    15e0:	2e 00       	.word	0x002e	; ????
    15e2:	00 00       	nop
    15e4:	00 00       	nop
    15e6:	00 00       	nop
    15e8:	44 00       	.word	0x0044	; ????
    15ea:	d4 00       	.word	0x00d4	; ????
    15ec:	36 00       	.word	0x0036	; ????
    15ee:	00 00       	nop
    15f0:	00 00       	nop
    15f2:	00 00       	nop
    15f4:	44 00       	.word	0x0044	; ????
    15f6:	d5 00       	.word	0x00d5	; ????
    15f8:	3a 00       	.word	0x003a	; ????
    15fa:	00 00       	nop
    15fc:	00 00       	nop
    15fe:	00 00       	nop
    1600:	44 00       	.word	0x0044	; ????
    1602:	d8 00       	.word	0x00d8	; ????
    1604:	3c 00       	.word	0x003c	; ????
    1606:	00 00       	nop
    1608:	00 00       	nop
    160a:	00 00       	nop
    160c:	44 00       	.word	0x0044	; ????
    160e:	d9 00       	.word	0x00d9	; ????
    1610:	40 00       	.word	0x0040	; ????
    1612:	00 00       	nop
    1614:	00 00       	nop
    1616:	00 00       	nop
    1618:	44 00       	.word	0x0044	; ????
    161a:	da 00       	.word	0x00da	; ????
    161c:	48 00       	.word	0x0048	; ????
    161e:	00 00       	nop
    1620:	00 00       	nop
    1622:	00 00       	nop
    1624:	44 00       	.word	0x0044	; ????
    1626:	db 00       	.word	0x00db	; ????
    1628:	4c 00       	.word	0x004c	; ????
    162a:	00 00       	nop
    162c:	00 00       	nop
    162e:	00 00       	nop
    1630:	44 00       	.word	0x0044	; ????
    1632:	df 00       	.word	0x00df	; ????
    1634:	4e 00       	.word	0x004e	; ????
    1636:	00 00       	nop
    1638:	00 00       	nop
    163a:	00 00       	nop
    163c:	44 00       	.word	0x0044	; ????
    163e:	df 00       	.word	0x00df	; ????
    1640:	54 00       	.word	0x0054	; ????
    1642:	00 00       	nop
    1644:	00 00       	nop
    1646:	00 00       	nop
    1648:	44 00       	.word	0x0044	; ????
    164a:	e1 00       	.word	0x00e1	; ????
    164c:	62 00       	.word	0x0062	; ????
    164e:	00 00       	nop
    1650:	00 00       	nop
    1652:	00 00       	nop
    1654:	44 00       	.word	0x0044	; ????
    1656:	e5 00       	.word	0x00e5	; ????
    1658:	68 00       	.word	0x0068	; ????
    165a:	00 00       	nop
    165c:	00 00       	nop
    165e:	00 00       	nop
    1660:	44 00       	.word	0x0044	; ????
    1662:	e6 00       	.word	0x00e6	; ????
    1664:	68 00       	.word	0x0068	; ????
    1666:	00 00       	nop
    1668:	00 00       	nop
    166a:	00 00       	nop
    166c:	44 00       	.word	0x0044	; ????
    166e:	eb 00       	.word	0x00eb	; ????
    1670:	6a 00       	.word	0x006a	; ????
    1672:	00 00       	nop
    1674:	00 00       	nop
    1676:	00 00       	nop
    1678:	44 00       	.word	0x0044	; ????
    167a:	ec 00       	.word	0x00ec	; ????
    167c:	6c 00       	.word	0x006c	; ????
    167e:	00 00       	nop
    1680:	00 00       	nop
    1682:	00 00       	nop
    1684:	44 00       	.word	0x0044	; ????
    1686:	f0 00       	.word	0x00f0	; ????
    1688:	76 00       	.word	0x0076	; ????
    168a:	00 00       	nop
    168c:	00 00       	nop
    168e:	00 00       	nop
    1690:	44 00       	.word	0x0044	; ????
    1692:	f1 00       	.word	0x00f1	; ????
    1694:	78 00       	.word	0x0078	; ????
    1696:	00 00       	nop
    1698:	00 00       	nop
    169a:	00 00       	nop
    169c:	44 00       	.word	0x0044	; ????
    169e:	f2 00       	.word	0x00f2	; ????
    16a0:	82 00       	.word	0x0082	; ????
    16a2:	00 00       	nop
    16a4:	00 00       	nop
    16a6:	00 00       	nop
    16a8:	44 00       	.word	0x0044	; ????
    16aa:	f4 00       	.word	0x00f4	; ????
    16ac:	84 00       	.word	0x0084	; ????
    16ae:	00 00       	nop
    16b0:	00 00       	nop
    16b2:	00 00       	nop
    16b4:	44 00       	.word	0x0044	; ????
    16b6:	c4 00       	.word	0x00c4	; ????
    16b8:	8a 00       	.word	0x008a	; ????
    16ba:	00 00       	nop
    16bc:	00 00       	nop
    16be:	00 00       	nop
    16c0:	44 00       	.word	0x0044	; ????
    16c2:	f9 00       	.word	0x00f9	; ????
    16c4:	8e 00       	.word	0x008e	; ????
    16c6:	00 00       	nop
    16c8:	00 00       	nop
    16ca:	00 00       	nop
    16cc:	44 00       	.word	0x0044	; ????
    16ce:	fb 00       	.word	0x00fb	; ????
    16d0:	90 00       	.word	0x0090	; ????
    16d2:	00 00       	nop
    16d4:	00 00       	nop
    16d6:	00 00       	nop
    16d8:	44 00       	.word	0x0044	; ????
    16da:	02 01       	movw	r0, r4
    16dc:	9c 00       	.word	0x009c	; ????
    16de:	00 00       	nop
    16e0:	00 00       	nop
    16e2:	00 00       	nop
    16e4:	44 00       	.word	0x0044	; ????
    16e6:	03 01       	movw	r0, r6
    16e8:	9e 00       	.word	0x009e	; ????
    16ea:	00 00       	nop
    16ec:	00 00       	nop
    16ee:	00 00       	nop
    16f0:	44 00       	.word	0x0044	; ????
    16f2:	04 01       	movw	r0, r8
    16f4:	ae 00       	.word	0x00ae	; ????
    16f6:	00 00       	nop
    16f8:	00 00       	nop
    16fa:	00 00       	nop
    16fc:	44 00       	.word	0x0044	; ????
    16fe:	08 01       	movw	r0, r16
    1700:	b0 00       	.word	0x00b0	; ????
    1702:	00 00       	nop
    1704:	00 00       	nop
    1706:	00 00       	nop
    1708:	44 00       	.word	0x0044	; ????
    170a:	09 01       	movw	r0, r18
    170c:	b6 00       	.word	0x00b6	; ????
    170e:	00 00       	nop
    1710:	00 00       	nop
    1712:	00 00       	nop
    1714:	44 00       	.word	0x0044	; ????
    1716:	0a 01       	movw	r0, r20
    1718:	bc 00       	.word	0x00bc	; ????
    171a:	00 00       	nop
    171c:	00 00       	nop
    171e:	00 00       	nop
    1720:	44 00       	.word	0x0044	; ????
    1722:	0c 01       	movw	r0, r24
    1724:	c2 00       	.word	0x00c2	; ????
    1726:	00 00       	nop
    1728:	00 00       	nop
    172a:	00 00       	nop
    172c:	44 00       	.word	0x0044	; ????
    172e:	10 01       	movw	r2, r0
    1730:	c4 00       	.word	0x00c4	; ????
    1732:	00 00       	nop
    1734:	00 00       	nop
    1736:	00 00       	nop
    1738:	44 00       	.word	0x0044	; ????
    173a:	11 01       	movw	r2, r2
    173c:	ca 00       	.word	0x00ca	; ????
    173e:	00 00       	nop
    1740:	2c 10       	cpse	r2, r12
    1742:	00 00       	nop
    1744:	80 00       	.word	0x0080	; ????
    1746:	bf 00       	.word	0x00bf	; ????
    1748:	01 00       	.word	0x0001	; ????
    174a:	00 00       	nop
    174c:	61 10       	cpse	r6, r1
    174e:	00 00       	nop
    1750:	40 00       	.word	0x0040	; ????
    1752:	c4 00       	.word	0x00c4	; ????
    1754:	10 00       	.word	0x0010	; ????
    1756:	00 00       	nop
    1758:	00 00       	nop
    175a:	00 00       	nop
    175c:	c0 00       	.word	0x00c0	; ????
	...
    1766:	00 00       	nop
    1768:	e0 00       	.word	0x00e0	; ????
    176a:	00 00       	nop
    176c:	cc 00       	.word	0x00cc	; ????
    176e:	00 00       	nop
    1770:	00 00       	nop
    1772:	00 00       	nop
    1774:	24 00       	.word	0x0024	; ????
    1776:	00 00       	nop
    1778:	cc 00       	.word	0x00cc	; ????
    177a:	00 00       	nop
    177c:	00 00       	nop
    177e:	00 00       	nop
    1780:	4e 00       	.word	0x004e	; ????
    1782:	00 00       	nop
    1784:	ea e3       	ldi	r30, 0x3A	; 58
    1786:	01 00       	.word	0x0001	; ????
    1788:	6d 10       	cpse	r6, r13
    178a:	00 00       	nop
    178c:	24 00       	.word	0x0024	; ????
    178e:	35 00       	.word	0x0035	; ????
    1790:	08 ea       	ldi	r16, 0xA8	; 168
    1792:	01 00       	.word	0x0001	; ????
    1794:	00 00       	nop
    1796:	00 00       	nop
    1798:	2e 00       	.word	0x002e	; ????
    179a:	00 00       	nop
    179c:	08 ea       	ldi	r16, 0xA8	; 168
    179e:	01 00       	.word	0x0001	; ????
    17a0:	00 00       	nop
    17a2:	00 00       	nop
    17a4:	44 00       	.word	0x0044	; ????
    17a6:	36 00       	.word	0x0036	; ????
	...
    17b0:	44 00       	.word	0x0044	; ????
    17b2:	38 00       	.word	0x0038	; ????
	...
    17bc:	44 00       	.word	0x0044	; ????
    17be:	3a 00       	.word	0x003a	; ????
    17c0:	04 00       	.word	0x0004	; ????
    17c2:	00 00       	nop
    17c4:	00 00       	nop
    17c6:	00 00       	nop
    17c8:	44 00       	.word	0x0044	; ????
    17ca:	3b 00       	.word	0x003b	; ????
    17cc:	08 00       	.word	0x0008	; ????
    17ce:	00 00       	nop
    17d0:	00 00       	nop
    17d2:	00 00       	nop
    17d4:	44 00       	.word	0x0044	; ????
    17d6:	3e 00       	.word	0x003e	; ????
    17d8:	0a 00       	.word	0x000a	; ????
    17da:	00 00       	nop
    17dc:	00 00       	nop
    17de:	00 00       	nop
    17e0:	44 00       	.word	0x0044	; ????
    17e2:	41 00       	.word	0x0041	; ????
    17e4:	10 00       	.word	0x0010	; ????
    17e6:	00 00       	nop
    17e8:	00 00       	nop
    17ea:	00 00       	nop
    17ec:	44 00       	.word	0x0044	; ????
    17ee:	44 00       	.word	0x0044	; ????
    17f0:	16 00       	.word	0x0016	; ????
    17f2:	00 00       	nop
    17f4:	00 00       	nop
    17f6:	00 00       	nop
    17f8:	44 00       	.word	0x0044	; ????
    17fa:	46 00       	.word	0x0046	; ????
    17fc:	1a 00       	.word	0x001a	; ????
    17fe:	00 00       	nop
    1800:	00 00       	nop
    1802:	00 00       	nop
    1804:	44 00       	.word	0x0044	; ????
    1806:	47 00       	.word	0x0047	; ????
    1808:	20 00       	.word	0x0020	; ????
    180a:	00 00       	nop
    180c:	00 00       	nop
    180e:	00 00       	nop
    1810:	44 00       	.word	0x0044	; ????
    1812:	49 00       	.word	0x0049	; ????
    1814:	24 00       	.word	0x0024	; ????
    1816:	00 00       	nop
    1818:	00 00       	nop
    181a:	00 00       	nop
    181c:	44 00       	.word	0x0044	; ????
    181e:	4b 00       	.word	0x004b	; ????
    1820:	28 00       	.word	0x0028	; ????
    1822:	00 00       	nop
    1824:	00 00       	nop
    1826:	00 00       	nop
    1828:	44 00       	.word	0x0044	; ????
    182a:	4c 00       	.word	0x004c	; ????
    182c:	2e 00       	.word	0x002e	; ????
    182e:	00 00       	nop
    1830:	00 00       	nop
    1832:	00 00       	nop
    1834:	44 00       	.word	0x0044	; ????
    1836:	50 00       	.word	0x0050	; ????
    1838:	32 00       	.word	0x0032	; ????
    183a:	00 00       	nop
    183c:	00 00       	nop
    183e:	00 00       	nop
    1840:	44 00       	.word	0x0044	; ????
    1842:	51 00       	.word	0x0051	; ????
    1844:	38 00       	.word	0x0038	; ????
    1846:	00 00       	nop
    1848:	00 00       	nop
    184a:	00 00       	nop
    184c:	44 00       	.word	0x0044	; ????
    184e:	53 00       	.word	0x0053	; ????
    1850:	3c 00       	.word	0x003c	; ????
    1852:	00 00       	nop
    1854:	00 00       	nop
    1856:	00 00       	nop
    1858:	24 00       	.word	0x0024	; ????
    185a:	00 00       	nop
    185c:	42 00       	.word	0x0042	; ????
    185e:	00 00       	nop
    1860:	00 00       	nop
    1862:	00 00       	nop
    1864:	4e 00       	.word	0x004e	; ????
    1866:	00 00       	nop
    1868:	4a ea       	ldi	r20, 0xAA	; 170
    186a:	01 00       	.word	0x0001	; ????
    186c:	79 10       	cpse	r7, r9
    186e:	00 00       	nop
    1870:	20 00       	.word	0x0020	; ????
    1872:	32 00       	.word	0x0032	; ????
    1874:	00 00       	nop
    1876:	00 00       	nop
    1878:	88 10       	cpse	r8, r8
    187a:	00 00       	nop
    187c:	20 00       	.word	0x0020	; ????
    187e:	33 00       	.word	0x0033	; ????
	...
    1888:	64 00       	.word	0x0064	; ????
    188a:	00 00       	nop
    188c:	ea e3       	ldi	r30, 0x3A	; 58
    188e:	01 00       	.word	0x0001	; ????
    1890:	08 00       	.word	0x0008	; ????
    1892:	00 00       	nop
    1894:	64 00       	.word	0x0064	; ????
    1896:	02 00       	.word	0x0002	; ????
    1898:	ea e3       	ldi	r30, 0x3A	; 58
    189a:	01 00       	.word	0x0001	; ????
    189c:	9a 10       	cpse	r9, r10
    189e:	00 00       	nop
    18a0:	64 00       	.word	0x0064	; ????
    18a2:	02 00       	.word	0x0002	; ????
    18a4:	ea e3       	ldi	r30, 0x3A	; 58
    18a6:	01 00       	.word	0x0001	; ????
    18a8:	33 00       	.word	0x0033	; ????
    18aa:	00 00       	nop
    18ac:	3c 00       	.word	0x003c	; ????
    18ae:	00 00       	nop
    18b0:	00 00       	nop
    18b2:	00 00       	nop
    18b4:	42 00       	.word	0x0042	; ????
    18b6:	00 00       	nop
    18b8:	80 00       	.word	0x0080	; ????
    18ba:	00 00       	nop
    18bc:	00 00       	nop
    18be:	00 00       	nop
    18c0:	62 00       	.word	0x0062	; ????
    18c2:	00 00       	nop
    18c4:	80 00       	.word	0x0080	; ????
    18c6:	00 00       	nop
    18c8:	00 00       	nop
    18ca:	00 00       	nop
    18cc:	7c 00       	.word	0x007c	; ????
    18ce:	00 00       	nop
    18d0:	80 00       	.word	0x0080	; ????
    18d2:	00 00       	nop
    18d4:	00 00       	nop
    18d6:	00 00       	nop
    18d8:	b3 00       	.word	0x00b3	; ????
    18da:	00 00       	nop
    18dc:	80 00       	.word	0x0080	; ????
    18de:	00 00       	nop
    18e0:	00 00       	nop
    18e2:	00 00       	nop
    18e4:	d9 00       	.word	0x00d9	; ????
    18e6:	00 00       	nop
    18e8:	80 00       	.word	0x0080	; ????
    18ea:	00 00       	nop
    18ec:	00 00       	nop
    18ee:	00 00       	nop
    18f0:	0e 01       	movw	r0, r28
    18f2:	00 00       	nop
    18f4:	80 00       	.word	0x0080	; ????
    18f6:	00 00       	nop
    18f8:	00 00       	nop
    18fa:	00 00       	nop
    18fc:	5f 01       	movw	r10, r30
    18fe:	00 00       	nop
    1900:	80 00       	.word	0x0080	; ????
    1902:	00 00       	nop
    1904:	00 00       	nop
    1906:	00 00       	nop
    1908:	a4 01       	movw	r20, r8
    190a:	00 00       	nop
    190c:	80 00       	.word	0x0080	; ????
    190e:	00 00       	nop
    1910:	00 00       	nop
    1912:	00 00       	nop
    1914:	ca 01       	movw	r24, r20
    1916:	00 00       	nop
    1918:	80 00       	.word	0x0080	; ????
    191a:	00 00       	nop
    191c:	00 00       	nop
    191e:	00 00       	nop
    1920:	f6 01       	movw	r30, r12
    1922:	00 00       	nop
    1924:	80 00       	.word	0x0080	; ????
    1926:	00 00       	nop
    1928:	00 00       	nop
    192a:	00 00       	nop
    192c:	20 02       	muls	r18, r16
    192e:	00 00       	nop
    1930:	80 00       	.word	0x0080	; ????
    1932:	00 00       	nop
    1934:	00 00       	nop
    1936:	00 00       	nop
    1938:	49 02       	muls	r20, r25
    193a:	00 00       	nop
    193c:	80 00       	.word	0x0080	; ????
    193e:	00 00       	nop
    1940:	00 00       	nop
    1942:	00 00       	nop
    1944:	63 02       	muls	r22, r19
    1946:	00 00       	nop
    1948:	80 00       	.word	0x0080	; ????
    194a:	00 00       	nop
    194c:	00 00       	nop
    194e:	00 00       	nop
    1950:	7e 02       	muls	r23, r30
    1952:	00 00       	nop
    1954:	80 00       	.word	0x0080	; ????
    1956:	00 00       	nop
    1958:	00 00       	nop
    195a:	00 00       	nop
    195c:	9e 02       	muls	r25, r30
    195e:	00 00       	nop
    1960:	80 00       	.word	0x0080	; ????
    1962:	00 00       	nop
    1964:	00 00       	nop
    1966:	00 00       	nop
    1968:	bf 02       	muls	r27, r31
    196a:	00 00       	nop
    196c:	80 00       	.word	0x0080	; ????
    196e:	00 00       	nop
    1970:	00 00       	nop
    1972:	00 00       	nop
    1974:	da 02       	muls	r29, r26
    1976:	00 00       	nop
    1978:	80 00       	.word	0x0080	; ????
    197a:	00 00       	nop
    197c:	00 00       	nop
    197e:	00 00       	nop
    1980:	fa 02       	muls	r31, r26
    1982:	00 00       	nop
    1984:	80 00       	.word	0x0080	; ????
    1986:	00 00       	nop
    1988:	00 00       	nop
    198a:	00 00       	nop
    198c:	1f 03       	fmul	r17, r23
    198e:	00 00       	nop
    1990:	80 00       	.word	0x0080	; ????
    1992:	00 00       	nop
    1994:	00 00       	nop
    1996:	00 00       	nop
    1998:	49 03       	fmul	r20, r17
    199a:	00 00       	nop
    199c:	80 00       	.word	0x0080	; ????
    199e:	00 00       	nop
    19a0:	00 00       	nop
    19a2:	00 00       	nop
    19a4:	6d 03       	fmul	r22, r21
    19a6:	00 00       	nop
    19a8:	80 00       	.word	0x0080	; ????
    19aa:	00 00       	nop
    19ac:	00 00       	nop
    19ae:	00 00       	nop
    19b0:	96 03       	fmuls	r17, r22
    19b2:	00 00       	nop
    19b4:	80 00       	.word	0x0080	; ????
    19b6:	00 00       	nop
    19b8:	00 00       	nop
    19ba:	00 00       	nop
    19bc:	c4 03       	fmuls	r20, r20
    19be:	00 00       	nop
    19c0:	80 00       	.word	0x0080	; ????
    19c2:	00 00       	nop
    19c4:	00 00       	nop
    19c6:	00 00       	nop
    19c8:	ea 03       	fmulsu	r22, r18
    19ca:	00 00       	nop
    19cc:	80 00       	.word	0x0080	; ????
    19ce:	00 00       	nop
    19d0:	00 00       	nop
    19d2:	00 00       	nop
    19d4:	0a 04       	cpc	r0, r10
    19d6:	00 00       	nop
    19d8:	80 00       	.word	0x0080	; ????
    19da:	00 00       	nop
    19dc:	00 00       	nop
    19de:	00 00       	nop
    19e0:	2f 04       	cpc	r2, r15
    19e2:	00 00       	nop
    19e4:	80 00       	.word	0x0080	; ????
    19e6:	00 00       	nop
    19e8:	00 00       	nop
    19ea:	00 00       	nop
    19ec:	59 04       	cpc	r5, r9
    19ee:	00 00       	nop
    19f0:	80 00       	.word	0x0080	; ????
    19f2:	00 00       	nop
    19f4:	00 00       	nop
    19f6:	00 00       	nop
    19f8:	88 04       	cpc	r8, r8
    19fa:	00 00       	nop
    19fc:	80 00       	.word	0x0080	; ????
    19fe:	00 00       	nop
    1a00:	00 00       	nop
    1a02:	00 00       	nop
    1a04:	b1 04       	cpc	r11, r1
    1a06:	00 00       	nop
    1a08:	80 00       	.word	0x0080	; ????
    1a0a:	00 00       	nop
    1a0c:	00 00       	nop
    1a0e:	00 00       	nop
    1a10:	df 04       	cpc	r13, r15
    1a12:	00 00       	nop
    1a14:	80 00       	.word	0x0080	; ????
    1a16:	00 00       	nop
    1a18:	00 00       	nop
    1a1a:	00 00       	nop
    1a1c:	12 05       	cpc	r17, r2
    1a1e:	00 00       	nop
    1a20:	80 00       	.word	0x0080	; ????
    1a22:	00 00       	nop
    1a24:	00 00       	nop
    1a26:	00 00       	nop
    1a28:	33 05       	cpc	r19, r3
    1a2a:	00 00       	nop
    1a2c:	80 00       	.word	0x0080	; ????
    1a2e:	00 00       	nop
    1a30:	00 00       	nop
    1a32:	00 00       	nop
    1a34:	4e 05       	cpc	r20, r14
    1a36:	00 00       	nop
    1a38:	80 00       	.word	0x0080	; ????
    1a3a:	00 00       	nop
    1a3c:	00 00       	nop
    1a3e:	00 00       	nop
    1a40:	6e 05       	cpc	r22, r14
    1a42:	00 00       	nop
    1a44:	80 00       	.word	0x0080	; ????
    1a46:	00 00       	nop
    1a48:	00 00       	nop
    1a4a:	00 00       	nop
    1a4c:	93 05       	cpc	r25, r3
    1a4e:	00 00       	nop
    1a50:	80 00       	.word	0x0080	; ????
    1a52:	00 00       	nop
    1a54:	00 00       	nop
    1a56:	00 00       	nop
    1a58:	bd 05       	cpc	r27, r13
    1a5a:	00 00       	nop
    1a5c:	80 00       	.word	0x0080	; ????
    1a5e:	00 00       	nop
    1a60:	00 00       	nop
    1a62:	00 00       	nop
    1a64:	e1 05       	cpc	r30, r1
    1a66:	00 00       	nop
    1a68:	80 00       	.word	0x0080	; ????
    1a6a:	00 00       	nop
    1a6c:	00 00       	nop
    1a6e:	00 00       	nop
    1a70:	0a 06       	cpc	r0, r26
    1a72:	00 00       	nop
    1a74:	80 00       	.word	0x0080	; ????
    1a76:	00 00       	nop
    1a78:	00 00       	nop
    1a7a:	00 00       	nop
    1a7c:	38 06       	cpc	r3, r24
    1a7e:	00 00       	nop
    1a80:	80 00       	.word	0x0080	; ????
    1a82:	00 00       	nop
    1a84:	00 00       	nop
    1a86:	00 00       	nop
    1a88:	5e 06       	cpc	r5, r30
    1a8a:	00 00       	nop
    1a8c:	80 00       	.word	0x0080	; ????
    1a8e:	00 00       	nop
    1a90:	00 00       	nop
    1a92:	00 00       	nop
    1a94:	7e 06       	cpc	r7, r30
    1a96:	00 00       	nop
    1a98:	80 00       	.word	0x0080	; ????
    1a9a:	00 00       	nop
    1a9c:	00 00       	nop
    1a9e:	00 00       	nop
    1aa0:	a3 06       	cpc	r10, r19
    1aa2:	00 00       	nop
    1aa4:	80 00       	.word	0x0080	; ????
    1aa6:	00 00       	nop
    1aa8:	00 00       	nop
    1aaa:	00 00       	nop
    1aac:	cd 06       	cpc	r12, r29
    1aae:	00 00       	nop
    1ab0:	80 00       	.word	0x0080	; ????
    1ab2:	00 00       	nop
    1ab4:	00 00       	nop
    1ab6:	00 00       	nop
    1ab8:	fc 06       	cpc	r15, r28
    1aba:	00 00       	nop
    1abc:	80 00       	.word	0x0080	; ????
    1abe:	00 00       	nop
    1ac0:	00 00       	nop
    1ac2:	00 00       	nop
    1ac4:	25 07       	cpc	r18, r21
    1ac6:	00 00       	nop
    1ac8:	80 00       	.word	0x0080	; ????
    1aca:	00 00       	nop
    1acc:	00 00       	nop
    1ace:	00 00       	nop
    1ad0:	53 07       	cpc	r21, r19
    1ad2:	00 00       	nop
    1ad4:	80 00       	.word	0x0080	; ????
    1ad6:	00 00       	nop
    1ad8:	00 00       	nop
    1ada:	00 00       	nop
    1adc:	86 07       	cpc	r24, r22
    1ade:	00 00       	nop
    1ae0:	80 00       	.word	0x0080	; ????
    1ae2:	00 00       	nop
    1ae4:	00 00       	nop
    1ae6:	00 00       	nop
    1ae8:	fc 07       	cpc	r31, r28
    1aea:	00 00       	nop
    1aec:	c2 00       	.word	0x00c2	; ????
    1aee:	00 00       	nop
    1af0:	00 00       	nop
    1af2:	00 00       	nop
    1af4:	24 08       	sbc	r2, r4
    1af6:	00 00       	nop
    1af8:	c2 00       	.word	0x00c2	; ????
    1afa:	00 00       	nop
    1afc:	33 b8       	out	0x03, r3	; 3
    1afe:	00 00       	nop
    1b00:	a4 10       	cpse	r10, r4
    1b02:	00 00       	nop
    1b04:	82 00       	.word	0x0082	; ????
    1b06:	00 00       	nop
    1b08:	00 00       	nop
    1b0a:	00 00       	nop
    1b0c:	d7 0d       	add	r29, r7
    1b0e:	00 00       	nop
    1b10:	c2 00       	.word	0x00c2	; ????
    1b12:	00 00       	nop
    1b14:	d8 04       	cpc	r13, r8
    1b16:	00 00       	nop
    1b18:	00 00       	nop
    1b1a:	00 00       	nop
    1b1c:	a2 00       	.word	0x00a2	; ????
    1b1e:	00 00       	nop
    1b20:	00 00       	nop
    1b22:	00 00       	nop
    1b24:	c2 10       	cpse	r12, r2
    1b26:	00 00       	nop
    1b28:	82 00       	.word	0x0082	; ????
    1b2a:	00 00       	nop
    1b2c:	00 00       	nop
    1b2e:	00 00       	nop
    1b30:	dc 07       	cpc	r29, r28
    1b32:	00 00       	nop
    1b34:	c2 00       	.word	0x00c2	; ????
    1b36:	00 00       	nop
    1b38:	25 0f       	add	r18, r21
    1b3a:	00 00       	nop
    1b3c:	9a 07       	cpc	r25, r26
    1b3e:	00 00       	nop
    1b40:	c2 00       	.word	0x00c2	; ????
    1b42:	00 00       	nop
    1b44:	00 00       	nop
    1b46:	00 00       	nop
    1b48:	3c 0b       	sbc	r19, r28
    1b4a:	00 00       	nop
    1b4c:	c2 00       	.word	0x00c2	; ????
    1b4e:	00 00       	nop
    1b50:	68 13       	cpse	r22, r24
    1b52:	00 00       	nop
    1b54:	00 00       	nop
    1b56:	00 00       	nop
    1b58:	a2 00       	.word	0x00a2	; ????
    1b5a:	00 00       	nop
    1b5c:	00 00       	nop
    1b5e:	00 00       	nop
    1b60:	d6 0e       	add	r13, r22
    1b62:	00 00       	nop
    1b64:	c2 00       	.word	0x00c2	; ????
    1b66:	00 00       	nop
    1b68:	00 00       	nop
    1b6a:	00 00       	nop
    1b6c:	f6 0e       	add	r15, r22
    1b6e:	00 00       	nop
    1b70:	c2 00       	.word	0x00c2	; ????
    1b72:	00 00       	nop
    1b74:	00 00       	nop
    1b76:	00 00       	nop
    1b78:	d7 0d       	add	r29, r7
    1b7a:	00 00       	nop
    1b7c:	c2 00       	.word	0x00c2	; ????
    1b7e:	00 00       	nop
    1b80:	39 0b       	sbc	r19, r25
    1b82:	00 00       	nop
    1b84:	e6 10       	cpse	r14, r6
    1b86:	00 00       	nop
    1b88:	80 00       	.word	0x0080	; ????
    1b8a:	3d 00       	.word	0x003d	; ????
    1b8c:	00 00       	nop
    1b8e:	00 00       	nop
    1b90:	37 11       	cpse	r19, r7
    1b92:	00 00       	nop
    1b94:	24 00       	.word	0x0024	; ????
    1b96:	df 00       	.word	0x00df	; ????
    1b98:	ea e3       	ldi	r30, 0x3A	; 58
    1b9a:	01 00       	.word	0x0001	; ????
    1b9c:	4b 11       	cpse	r20, r11
    1b9e:	00 00       	nop
    1ba0:	40 00       	.word	0x0040	; ????
    1ba2:	df 00       	.word	0x00df	; ????
    1ba4:	18 00       	.word	0x0018	; ????
    1ba6:	00 00       	nop
    1ba8:	00 00       	nop
    1baa:	00 00       	nop
    1bac:	2e 00       	.word	0x002e	; ????
    1bae:	00 00       	nop
    1bb0:	ea e3       	ldi	r30, 0x3A	; 58
    1bb2:	01 00       	.word	0x0001	; ????
    1bb4:	00 00       	nop
    1bb6:	00 00       	nop
    1bb8:	44 00       	.word	0x0044	; ????
    1bba:	e0 00       	.word	0x00e0	; ????
	...
    1bc4:	44 00       	.word	0x0044	; ????
    1bc6:	e6 00       	.word	0x00e6	; ????
    1bc8:	14 00       	.word	0x0014	; ????
    1bca:	00 00       	nop
    1bcc:	00 00       	nop
    1bce:	00 00       	nop
    1bd0:	44 00       	.word	0x0044	; ????
    1bd2:	e0 00       	.word	0x00e0	; ????
    1bd4:	22 00       	.word	0x0022	; ????
    1bd6:	00 00       	nop
    1bd8:	00 00       	nop
    1bda:	00 00       	nop
    1bdc:	44 00       	.word	0x0044	; ????
    1bde:	e6 00       	.word	0x00e6	; ????
    1be0:	2c 00       	.word	0x002c	; ????
    1be2:	00 00       	nop
    1be4:	00 00       	nop
    1be6:	00 00       	nop
    1be8:	44 00       	.word	0x0044	; ????
    1bea:	e4 00       	.word	0x00e4	; ????
    1bec:	38 00       	.word	0x0038	; ????
    1bee:	00 00       	nop
    1bf0:	00 00       	nop
    1bf2:	00 00       	nop
    1bf4:	44 00       	.word	0x0044	; ????
    1bf6:	e2 00       	.word	0x00e2	; ????
    1bf8:	46 00       	.word	0x0046	; ????
    1bfa:	00 00       	nop
    1bfc:	00 00       	nop
    1bfe:	00 00       	nop
    1c00:	44 00       	.word	0x0044	; ????
    1c02:	e9 00       	.word	0x00e9	; ????
    1c04:	4c 00       	.word	0x004c	; ????
    1c06:	00 00       	nop
    1c08:	00 00       	nop
    1c0a:	00 00       	nop
    1c0c:	24 00       	.word	0x0024	; ????
    1c0e:	00 00       	nop
    1c10:	52 00       	.word	0x0052	; ????
    1c12:	00 00       	nop
    1c14:	00 00       	nop
    1c16:	00 00       	nop
    1c18:	4e 00       	.word	0x004e	; ????
    1c1a:	00 00       	nop
    1c1c:	3c e4       	ldi	r19, 0x4C	; 76
    1c1e:	01 00       	.word	0x0001	; ????
    1c20:	58 11       	cpse	r21, r8
    1c22:	00 00       	nop
    1c24:	24 00       	.word	0x0024	; ????
    1c26:	fc 00       	.word	0x00fc	; ????
    1c28:	3c e4       	ldi	r19, 0x4C	; 76
    1c2a:	01 00       	.word	0x0001	; ????
    1c2c:	00 00       	nop
    1c2e:	00 00       	nop
    1c30:	2e 00       	.word	0x002e	; ????
    1c32:	00 00       	nop
    1c34:	3c e4       	ldi	r19, 0x4C	; 76
    1c36:	01 00       	.word	0x0001	; ????
    1c38:	00 00       	nop
    1c3a:	00 00       	nop
    1c3c:	44 00       	.word	0x0044	; ????
    1c3e:	fd 00       	.word	0x00fd	; ????
	...
    1c48:	44 00       	.word	0x0044	; ????
    1c4a:	01 01       	movw	r0, r2
	...
    1c54:	44 00       	.word	0x0044	; ????
    1c56:	02 01       	movw	r0, r4
    1c58:	0a 00       	.word	0x000a	; ????
    1c5a:	00 00       	nop
    1c5c:	00 00       	nop
    1c5e:	00 00       	nop
    1c60:	44 00       	.word	0x0044	; ????
    1c62:	03 01       	movw	r0, r6
    1c64:	0e 00       	.word	0x000e	; ????
    1c66:	00 00       	nop
    1c68:	00 00       	nop
    1c6a:	00 00       	nop
    1c6c:	44 00       	.word	0x0044	; ????
    1c6e:	04 01       	movw	r0, r8
    1c70:	12 00       	.word	0x0012	; ????
    1c72:	00 00       	nop
    1c74:	00 00       	nop
    1c76:	00 00       	nop
    1c78:	44 00       	.word	0x0044	; ????
    1c7a:	05 01       	movw	r0, r10
    1c7c:	16 00       	.word	0x0016	; ????
    1c7e:	00 00       	nop
    1c80:	00 00       	nop
    1c82:	00 00       	nop
    1c84:	44 00       	.word	0x0044	; ????
    1c86:	08 01       	movw	r0, r16
    1c88:	18 00       	.word	0x0018	; ????
    1c8a:	00 00       	nop
    1c8c:	00 00       	nop
    1c8e:	00 00       	nop
    1c90:	44 00       	.word	0x0044	; ????
    1c92:	09 01       	movw	r0, r18
    1c94:	1a 00       	.word	0x001a	; ????
    1c96:	00 00       	nop
    1c98:	00 00       	nop
    1c9a:	00 00       	nop
    1c9c:	44 00       	.word	0x0044	; ????
    1c9e:	0a 01       	movw	r0, r20
    1ca0:	1e 00       	.word	0x001e	; ????
    1ca2:	00 00       	nop
    1ca4:	00 00       	nop
    1ca6:	00 00       	nop
    1ca8:	44 00       	.word	0x0044	; ????
    1caa:	0c 01       	movw	r0, r24
    1cac:	20 00       	.word	0x0020	; ????
    1cae:	00 00       	nop
    1cb0:	00 00       	nop
    1cb2:	00 00       	nop
    1cb4:	44 00       	.word	0x0044	; ????
    1cb6:	0d 01       	movw	r0, r26
    1cb8:	22 00       	.word	0x0022	; ????
    1cba:	00 00       	nop
    1cbc:	00 00       	nop
    1cbe:	00 00       	nop
    1cc0:	44 00       	.word	0x0044	; ????
    1cc2:	0e 01       	movw	r0, r28
    1cc4:	26 00       	.word	0x0026	; ????
    1cc6:	00 00       	nop
    1cc8:	00 00       	nop
    1cca:	00 00       	nop
    1ccc:	44 00       	.word	0x0044	; ????
    1cce:	11 01       	movw	r2, r2
    1cd0:	28 00       	.word	0x0028	; ????
    1cd2:	00 00       	nop
    1cd4:	00 00       	nop
    1cd6:	00 00       	nop
    1cd8:	44 00       	.word	0x0044	; ????
    1cda:	12 01       	movw	r2, r4
    1cdc:	2a 00       	.word	0x002a	; ????
    1cde:	00 00       	nop
    1ce0:	00 00       	nop
    1ce2:	00 00       	nop
    1ce4:	44 00       	.word	0x0044	; ????
    1ce6:	13 01       	movw	r2, r6
    1ce8:	2e 00       	.word	0x002e	; ????
    1cea:	00 00       	nop
    1cec:	00 00       	nop
    1cee:	00 00       	nop
    1cf0:	44 00       	.word	0x0044	; ????
    1cf2:	14 01       	movw	r2, r8
    1cf4:	32 00       	.word	0x0032	; ????
    1cf6:	00 00       	nop
    1cf8:	00 00       	nop
    1cfa:	00 00       	nop
    1cfc:	44 00       	.word	0x0044	; ????
    1cfe:	15 01       	movw	r2, r10
    1d00:	36 00       	.word	0x0036	; ????
    1d02:	00 00       	nop
    1d04:	00 00       	nop
    1d06:	00 00       	nop
    1d08:	24 00       	.word	0x0024	; ????
    1d0a:	00 00       	nop
    1d0c:	3a 00       	.word	0x003a	; ????
    1d0e:	00 00       	nop
    1d10:	00 00       	nop
    1d12:	00 00       	nop
    1d14:	4e 00       	.word	0x004e	; ????
    1d16:	00 00       	nop
    1d18:	76 e4       	ldi	r23, 0x46	; 70
    1d1a:	01 00       	.word	0x0001	; ????
    1d1c:	6a 11       	cpse	r22, r10
    1d1e:	00 00       	nop
    1d20:	24 00       	.word	0x0024	; ????
    1d22:	18 01       	movw	r2, r16
    1d24:	76 e4       	ldi	r23, 0x46	; 70
    1d26:	01 00       	.word	0x0001	; ????
    1d28:	77 11       	cpse	r23, r7
    1d2a:	00 00       	nop
    1d2c:	40 00       	.word	0x0040	; ????
    1d2e:	18 01       	movw	r2, r16
    1d30:	18 00       	.word	0x0018	; ????
    1d32:	00 00       	nop
    1d34:	00 00       	nop
    1d36:	00 00       	nop
    1d38:	2e 00       	.word	0x002e	; ????
    1d3a:	00 00       	nop
    1d3c:	76 e4       	ldi	r23, 0x46	; 70
    1d3e:	01 00       	.word	0x0001	; ????
    1d40:	00 00       	nop
    1d42:	00 00       	nop
    1d44:	44 00       	.word	0x0044	; ????
    1d46:	19 01       	movw	r2, r18
	...
    1d50:	44 00       	.word	0x0044	; ????
    1d52:	1a 01       	movw	r2, r20
	...
    1d5c:	44 00       	.word	0x0044	; ????
    1d5e:	1b 01       	movw	r2, r22
    1d60:	12 00       	.word	0x0012	; ????
    1d62:	00 00       	nop
    1d64:	00 00       	nop
    1d66:	00 00       	nop
    1d68:	24 00       	.word	0x0024	; ????
    1d6a:	00 00       	nop
    1d6c:	16 00       	.word	0x0016	; ????
    1d6e:	00 00       	nop
    1d70:	00 00       	nop
    1d72:	00 00       	nop
    1d74:	4e 00       	.word	0x004e	; ????
    1d76:	00 00       	nop
    1d78:	8c e4       	ldi	r24, 0x4C	; 76
    1d7a:	01 00       	.word	0x0001	; ????
    1d7c:	80 11       	cpse	r24, r0
    1d7e:	00 00       	nop
    1d80:	24 00       	.word	0x0024	; ????
    1d82:	59 01       	movw	r10, r18
    1d84:	8c e4       	ldi	r24, 0x4C	; 76
    1d86:	01 00       	.word	0x0001	; ????
    1d88:	00 00       	nop
    1d8a:	00 00       	nop
    1d8c:	2e 00       	.word	0x002e	; ????
    1d8e:	00 00       	nop
    1d90:	8c e4       	ldi	r24, 0x4C	; 76
    1d92:	01 00       	.word	0x0001	; ????
    1d94:	00 00       	nop
    1d96:	00 00       	nop
    1d98:	44 00       	.word	0x0044	; ????
    1d9a:	5a 01       	movw	r10, r20
	...
    1da4:	44 00       	.word	0x0044	; ????
    1da6:	60 01       	movw	r12, r0
    1da8:	08 00       	.word	0x0008	; ????
    1daa:	00 00       	nop
    1dac:	00 00       	nop
    1dae:	00 00       	nop
    1db0:	44 00       	.word	0x0044	; ????
    1db2:	5a 01       	movw	r10, r20
    1db4:	0a 00       	.word	0x000a	; ????
    1db6:	00 00       	nop
    1db8:	00 00       	nop
    1dba:	00 00       	nop
    1dbc:	44 00       	.word	0x0044	; ????
    1dbe:	98 00       	.word	0x0098	; ????
    1dc0:	0e 00       	.word	0x000e	; ????
    1dc2:	00 00       	nop
    1dc4:	00 00       	nop
    1dc6:	00 00       	nop
    1dc8:	44 00       	.word	0x0044	; ????
    1dca:	60 01       	movw	r12, r0
    1dcc:	18 00       	.word	0x0018	; ????
    1dce:	00 00       	nop
    1dd0:	00 00       	nop
    1dd2:	00 00       	nop
    1dd4:	44 00       	.word	0x0044	; ????
    1dd6:	5e 01       	movw	r10, r28
    1dd8:	1a 00       	.word	0x001a	; ????
    1dda:	00 00       	nop
    1ddc:	00 00       	nop
    1dde:	00 00       	nop
    1de0:	44 00       	.word	0x0044	; ????
    1de2:	5c 01       	movw	r10, r24
    1de4:	28 00       	.word	0x0028	; ????
    1de6:	00 00       	nop
    1de8:	94 11       	cpse	r25, r4
    1dea:	00 00       	nop
    1dec:	40 00       	.word	0x0040	; ????
    1dee:	5b 01       	movw	r10, r22
    1df0:	18 00       	.word	0x0018	; ????
    1df2:	00 00       	nop
    1df4:	00 00       	nop
    1df6:	00 00       	nop
    1df8:	c0 00       	.word	0x00c0	; ????
	...
    1e02:	00 00       	nop
    1e04:	e0 00       	.word	0x00e0	; ????
    1e06:	00 00       	nop
    1e08:	2e 00       	.word	0x002e	; ????
    1e0a:	00 00       	nop
    1e0c:	00 00       	nop
    1e0e:	00 00       	nop
    1e10:	24 00       	.word	0x0024	; ????
    1e12:	00 00       	nop
    1e14:	2e 00       	.word	0x002e	; ????
    1e16:	00 00       	nop
    1e18:	00 00       	nop
    1e1a:	00 00       	nop
    1e1c:	4e 00       	.word	0x004e	; ????
    1e1e:	00 00       	nop
    1e20:	ba e4       	ldi	r27, 0x4A	; 74
    1e22:	01 00       	.word	0x0001	; ????
    1e24:	9d 11       	cpse	r25, r13
    1e26:	00 00       	nop
    1e28:	24 00       	.word	0x0024	; ????
    1e2a:	65 01       	movw	r12, r10
    1e2c:	ba e4       	ldi	r27, 0x4A	; 74
    1e2e:	01 00       	.word	0x0001	; ????
    1e30:	00 00       	nop
    1e32:	00 00       	nop
    1e34:	2e 00       	.word	0x002e	; ????
    1e36:	00 00       	nop
    1e38:	ba e4       	ldi	r27, 0x4A	; 74
    1e3a:	01 00       	.word	0x0001	; ????
    1e3c:	00 00       	nop
    1e3e:	00 00       	nop
    1e40:	44 00       	.word	0x0044	; ????
    1e42:	66 01       	movw	r12, r12
	...
    1e4c:	44 00       	.word	0x0044	; ????
    1e4e:	6a 01       	movw	r12, r20
	...
    1e58:	44 00       	.word	0x0044	; ????
    1e5a:	6b 01       	movw	r12, r22
    1e5c:	0a 00       	.word	0x000a	; ????
    1e5e:	00 00       	nop
    1e60:	00 00       	nop
    1e62:	00 00       	nop
    1e64:	44 00       	.word	0x0044	; ????
    1e66:	6c 01       	movw	r12, r24
    1e68:	0e 00       	.word	0x000e	; ????
    1e6a:	00 00       	nop
    1e6c:	00 00       	nop
    1e6e:	00 00       	nop
    1e70:	44 00       	.word	0x0044	; ????
    1e72:	6d 01       	movw	r12, r26
    1e74:	12 00       	.word	0x0012	; ????
    1e76:	00 00       	nop
    1e78:	00 00       	nop
    1e7a:	00 00       	nop
    1e7c:	44 00       	.word	0x0044	; ????
    1e7e:	6e 01       	movw	r12, r28
    1e80:	16 00       	.word	0x0016	; ????
    1e82:	00 00       	nop
    1e84:	00 00       	nop
    1e86:	00 00       	nop
    1e88:	44 00       	.word	0x0044	; ????
    1e8a:	71 01       	movw	r14, r2
    1e8c:	18 00       	.word	0x0018	; ????
    1e8e:	00 00       	nop
    1e90:	00 00       	nop
    1e92:	00 00       	nop
    1e94:	44 00       	.word	0x0044	; ????
    1e96:	72 01       	movw	r14, r4
    1e98:	1a 00       	.word	0x001a	; ????
    1e9a:	00 00       	nop
    1e9c:	00 00       	nop
    1e9e:	00 00       	nop
    1ea0:	44 00       	.word	0x0044	; ????
    1ea2:	73 01       	movw	r14, r6
    1ea4:	1e 00       	.word	0x001e	; ????
    1ea6:	00 00       	nop
    1ea8:	00 00       	nop
    1eaa:	00 00       	nop
    1eac:	44 00       	.word	0x0044	; ????
    1eae:	75 01       	movw	r14, r10
    1eb0:	20 00       	.word	0x0020	; ????
    1eb2:	00 00       	nop
    1eb4:	00 00       	nop
    1eb6:	00 00       	nop
    1eb8:	44 00       	.word	0x0044	; ????
    1eba:	76 01       	movw	r14, r12
    1ebc:	22 00       	.word	0x0022	; ????
    1ebe:	00 00       	nop
    1ec0:	00 00       	nop
    1ec2:	00 00       	nop
    1ec4:	44 00       	.word	0x0044	; ????
    1ec6:	77 01       	movw	r14, r14
    1ec8:	26 00       	.word	0x0026	; ????
    1eca:	00 00       	nop
    1ecc:	00 00       	nop
    1ece:	00 00       	nop
    1ed0:	44 00       	.word	0x0044	; ????
    1ed2:	7a 01       	movw	r14, r20
    1ed4:	28 00       	.word	0x0028	; ????
    1ed6:	00 00       	nop
    1ed8:	00 00       	nop
    1eda:	00 00       	nop
    1edc:	44 00       	.word	0x0044	; ????
    1ede:	7b 01       	movw	r14, r22
    1ee0:	2a 00       	.word	0x002a	; ????
    1ee2:	00 00       	nop
    1ee4:	00 00       	nop
    1ee6:	00 00       	nop
    1ee8:	44 00       	.word	0x0044	; ????
    1eea:	7c 01       	movw	r14, r24
    1eec:	2e 00       	.word	0x002e	; ????
    1eee:	00 00       	nop
    1ef0:	00 00       	nop
    1ef2:	00 00       	nop
    1ef4:	44 00       	.word	0x0044	; ????
    1ef6:	7d 01       	movw	r14, r26
    1ef8:	32 00       	.word	0x0032	; ????
    1efa:	00 00       	nop
    1efc:	00 00       	nop
    1efe:	00 00       	nop
    1f00:	44 00       	.word	0x0044	; ????
    1f02:	7e 01       	movw	r14, r28
    1f04:	36 00       	.word	0x0036	; ????
    1f06:	00 00       	nop
    1f08:	00 00       	nop
    1f0a:	00 00       	nop
    1f0c:	24 00       	.word	0x0024	; ????
    1f0e:	00 00       	nop
    1f10:	3a 00       	.word	0x003a	; ????
    1f12:	00 00       	nop
    1f14:	00 00       	nop
    1f16:	00 00       	nop
    1f18:	4e 00       	.word	0x004e	; ????
    1f1a:	00 00       	nop
    1f1c:	f4 e4       	ldi	r31, 0x44	; 68
    1f1e:	01 00       	.word	0x0001	; ????
    1f20:	b2 11       	cpse	r27, r2
    1f22:	00 00       	nop
    1f24:	24 00       	.word	0x0024	; ????
    1f26:	ed 00       	.word	0x00ed	; ????
    1f28:	f4 e4       	ldi	r31, 0x44	; 68
    1f2a:	01 00       	.word	0x0001	; ????
    1f2c:	00 00       	nop
    1f2e:	00 00       	nop
    1f30:	2e 00       	.word	0x002e	; ????
    1f32:	00 00       	nop
    1f34:	f4 e4       	ldi	r31, 0x44	; 68
    1f36:	01 00       	.word	0x0001	; ????
    1f38:	00 00       	nop
    1f3a:	00 00       	nop
    1f3c:	44 00       	.word	0x0044	; ????
    1f3e:	ee 00       	.word	0x00ee	; ????
	...
    1f48:	44 00       	.word	0x0044	; ????
    1f4a:	f4 00       	.word	0x00f4	; ????
    1f4c:	08 00       	.word	0x0008	; ????
    1f4e:	00 00       	nop
    1f50:	00 00       	nop
    1f52:	00 00       	nop
    1f54:	44 00       	.word	0x0044	; ????
    1f56:	ee 00       	.word	0x00ee	; ????
    1f58:	0a 00       	.word	0x000a	; ????
    1f5a:	00 00       	nop
    1f5c:	00 00       	nop
    1f5e:	00 00       	nop
    1f60:	44 00       	.word	0x0044	; ????
    1f62:	93 00       	.word	0x0093	; ????
    1f64:	0e 00       	.word	0x000e	; ????
    1f66:	00 00       	nop
    1f68:	00 00       	nop
    1f6a:	00 00       	nop
    1f6c:	44 00       	.word	0x0044	; ????
    1f6e:	f4 00       	.word	0x00f4	; ????
    1f70:	18 00       	.word	0x0018	; ????
    1f72:	00 00       	nop
    1f74:	00 00       	nop
    1f76:	00 00       	nop
    1f78:	44 00       	.word	0x0044	; ????
    1f7a:	f2 00       	.word	0x00f2	; ????
    1f7c:	1a 00       	.word	0x001a	; ????
    1f7e:	00 00       	nop
    1f80:	00 00       	nop
    1f82:	00 00       	nop
    1f84:	44 00       	.word	0x0044	; ????
    1f86:	f0 00       	.word	0x00f0	; ????
    1f88:	28 00       	.word	0x0028	; ????
    1f8a:	00 00       	nop
    1f8c:	94 11       	cpse	r25, r4
    1f8e:	00 00       	nop
    1f90:	40 00       	.word	0x0040	; ????
    1f92:	ef 00       	.word	0x00ef	; ????
    1f94:	18 00       	.word	0x0018	; ????
    1f96:	00 00       	nop
    1f98:	00 00       	nop
    1f9a:	00 00       	nop
    1f9c:	c0 00       	.word	0x00c0	; ????
	...
    1fa6:	00 00       	nop
    1fa8:	e0 00       	.word	0x00e0	; ????
    1faa:	00 00       	nop
    1fac:	2e 00       	.word	0x002e	; ????
    1fae:	00 00       	nop
    1fb0:	00 00       	nop
    1fb2:	00 00       	nop
    1fb4:	24 00       	.word	0x0024	; ????
    1fb6:	00 00       	nop
    1fb8:	2e 00       	.word	0x002e	; ????
    1fba:	00 00       	nop
    1fbc:	00 00       	nop
    1fbe:	00 00       	nop
    1fc0:	4e 00       	.word	0x004e	; ????
    1fc2:	00 00       	nop
    1fc4:	22 e5       	ldi	r18, 0x52	; 82
    1fc6:	01 00       	.word	0x0001	; ????
    1fc8:	c3 11       	cpse	r28, r3
    1fca:	00 00       	nop
    1fcc:	24 00       	.word	0x0024	; ????
    1fce:	9c 00       	.word	0x009c	; ????
    1fd0:	22 e5       	ldi	r18, 0x52	; 82
    1fd2:	01 00       	.word	0x0001	; ????
    1fd4:	00 00       	nop
    1fd6:	00 00       	nop
    1fd8:	2e 00       	.word	0x002e	; ????
    1fda:	00 00       	nop
    1fdc:	22 e5       	ldi	r18, 0x52	; 82
    1fde:	01 00       	.word	0x0001	; ????
    1fe0:	00 00       	nop
    1fe2:	00 00       	nop
    1fe4:	44 00       	.word	0x0044	; ????
    1fe6:	9d 00       	.word	0x009d	; ????
	...
    1ff0:	44 00       	.word	0x0044	; ????
    1ff2:	a4 00       	.word	0x00a4	; ????
    1ff4:	16 00       	.word	0x0016	; ????
    1ff6:	00 00       	nop
    1ff8:	00 00       	nop
    1ffa:	00 00       	nop
    1ffc:	44 00       	.word	0x0044	; ????
    1ffe:	a4 00       	.word	0x00a4	; ????
    2000:	1e 00       	.word	0x001e	; ????
    2002:	00 00       	nop
    2004:	00 00       	nop
    2006:	00 00       	nop
    2008:	44 00       	.word	0x0044	; ????
    200a:	a5 00       	.word	0x00a5	; ????
    200c:	30 00       	.word	0x0030	; ????
    200e:	00 00       	nop
    2010:	00 00       	nop
    2012:	00 00       	nop
    2014:	44 00       	.word	0x0044	; ????
    2016:	a6 00       	.word	0x00a6	; ????
    2018:	40 00       	.word	0x0040	; ????
    201a:	00 00       	nop
    201c:	00 00       	nop
    201e:	00 00       	nop
    2020:	44 00       	.word	0x0044	; ????
    2022:	a7 00       	.word	0x00a7	; ????
    2024:	4c 00       	.word	0x004c	; ????
    2026:	00 00       	nop
    2028:	00 00       	nop
    202a:	00 00       	nop
    202c:	44 00       	.word	0x0044	; ????
    202e:	a2 00       	.word	0x00a2	; ????
    2030:	56 00       	.word	0x0056	; ????
    2032:	00 00       	nop
    2034:	00 00       	nop
    2036:	00 00       	nop
    2038:	44 00       	.word	0x0044	; ????
    203a:	a2 00       	.word	0x00a2	; ????
    203c:	60 00       	.word	0x0060	; ????
    203e:	00 00       	nop
    2040:	00 00       	nop
    2042:	00 00       	nop
    2044:	44 00       	.word	0x0044	; ????
    2046:	a4 00       	.word	0x00a4	; ????
    2048:	70 00       	.word	0x0070	; ????
    204a:	00 00       	nop
    204c:	00 00       	nop
    204e:	00 00       	nop
    2050:	44 00       	.word	0x0044	; ????
    2052:	af 00       	.word	0x00af	; ????
    2054:	80 00       	.word	0x0080	; ????
    2056:	00 00       	nop
    2058:	00 00       	nop
    205a:	00 00       	nop
    205c:	44 00       	.word	0x0044	; ????
    205e:	ad 00       	.word	0x00ad	; ????
    2060:	8e 00       	.word	0x008e	; ????
    2062:	00 00       	nop
    2064:	00 00       	nop
    2066:	00 00       	nop
    2068:	44 00       	.word	0x0044	; ????
    206a:	b1 00       	.word	0x00b1	; ????
    206c:	94 00       	.word	0x0094	; ????
    206e:	00 00       	nop
    2070:	00 00       	nop
    2072:	00 00       	nop
    2074:	44 00       	.word	0x0044	; ????
    2076:	b8 00       	.word	0x00b8	; ????
    2078:	a8 00       	.word	0x00a8	; ????
    207a:	00 00       	nop
    207c:	00 00       	nop
    207e:	00 00       	nop
    2080:	44 00       	.word	0x0044	; ????
    2082:	bb 00       	.word	0x00bb	; ????
    2084:	aa 00       	.word	0x00aa	; ????
    2086:	00 00       	nop
    2088:	00 00       	nop
    208a:	00 00       	nop
    208c:	44 00       	.word	0x0044	; ????
    208e:	93 00       	.word	0x0093	; ????
    2090:	ac 00       	.word	0x00ac	; ????
    2092:	00 00       	nop
    2094:	00 00       	nop
    2096:	00 00       	nop
    2098:	44 00       	.word	0x0044	; ????
    209a:	c5 00       	.word	0x00c5	; ????
    209c:	c0 00       	.word	0x00c0	; ????
    209e:	00 00       	nop
    20a0:	00 00       	nop
    20a2:	00 00       	nop
    20a4:	44 00       	.word	0x0044	; ????
    20a6:	93 00       	.word	0x0093	; ????
    20a8:	c6 00       	.word	0x00c6	; ????
    20aa:	00 00       	nop
    20ac:	00 00       	nop
    20ae:	00 00       	nop
    20b0:	44 00       	.word	0x0044	; ????
    20b2:	c6 00       	.word	0x00c6	; ????
    20b4:	cc 00       	.word	0x00cc	; ????
    20b6:	00 00       	nop
    20b8:	00 00       	nop
    20ba:	00 00       	nop
    20bc:	44 00       	.word	0x0044	; ????
    20be:	93 00       	.word	0x0093	; ????
    20c0:	d2 00       	.word	0x00d2	; ????
    20c2:	00 00       	nop
    20c4:	00 00       	nop
    20c6:	00 00       	nop
    20c8:	44 00       	.word	0x0044	; ????
    20ca:	c7 00       	.word	0x00c7	; ????
    20cc:	d8 00       	.word	0x00d8	; ????
    20ce:	00 00       	nop
    20d0:	00 00       	nop
    20d2:	00 00       	nop
    20d4:	44 00       	.word	0x0044	; ????
    20d6:	ca 00       	.word	0x00ca	; ????
    20d8:	de 00       	.word	0x00de	; ????
    20da:	00 00       	nop
    20dc:	00 00       	nop
    20de:	00 00       	nop
    20e0:	44 00       	.word	0x0044	; ????
    20e2:	d6 00       	.word	0x00d6	; ????
    20e4:	08 01       	movw	r0, r16
    20e6:	00 00       	nop
    20e8:	00 00       	nop
    20ea:	00 00       	nop
    20ec:	44 00       	.word	0x0044	; ????
    20ee:	d7 00       	.word	0x00d7	; ????
    20f0:	1e 01       	movw	r2, r28
    20f2:	00 00       	nop
    20f4:	00 00       	nop
    20f6:	00 00       	nop
    20f8:	44 00       	.word	0x0044	; ????
    20fa:	d8 00       	.word	0x00d8	; ????
    20fc:	34 01       	movw	r6, r8
    20fe:	00 00       	nop
    2100:	00 00       	nop
    2102:	00 00       	nop
    2104:	44 00       	.word	0x0044	; ????
    2106:	d9 00       	.word	0x00d9	; ????
    2108:	46 01       	movw	r8, r12
    210a:	00 00       	nop
    210c:	00 00       	nop
    210e:	00 00       	nop
    2110:	44 00       	.word	0x0044	; ????
    2112:	ab 00       	.word	0x00ab	; ????
    2114:	50 01       	movw	r10, r0
    2116:	00 00       	nop
    2118:	00 00       	nop
    211a:	00 00       	nop
    211c:	44 00       	.word	0x0044	; ????
    211e:	db 00       	.word	0x00db	; ????
    2120:	6a 01       	movw	r12, r20
    2122:	00 00       	nop
    2124:	d8 11       	cpse	r29, r8
    2126:	00 00       	nop
    2128:	40 00       	.word	0x0040	; ????
    212a:	9e 00       	.word	0x009e	; ????
    212c:	0c 00       	.word	0x000c	; ????
    212e:	00 00       	nop
    2130:	e1 11       	cpse	r30, r1
    2132:	00 00       	nop
    2134:	80 00       	.word	0x0080	; ????
    2136:	9f 00       	.word	0x009f	; ????
    2138:	01 00       	.word	0x0001	; ????
    213a:	00 00       	nop
    213c:	00 00       	nop
    213e:	00 00       	nop
    2140:	c0 00       	.word	0x00c0	; ????
	...
    214a:	00 00       	nop
    214c:	e0 00       	.word	0x00e0	; ????
    214e:	00 00       	nop
    2150:	72 01       	movw	r14, r4
    2152:	00 00       	nop
    2154:	00 00       	nop
    2156:	00 00       	nop
    2158:	24 00       	.word	0x0024	; ????
    215a:	00 00       	nop
    215c:	72 01       	movw	r14, r4
    215e:	00 00       	nop
    2160:	00 00       	nop
    2162:	00 00       	nop
    2164:	4e 00       	.word	0x004e	; ????
    2166:	00 00       	nop
    2168:	94 e6       	ldi	r25, 0x64	; 100
    216a:	01 00       	.word	0x0001	; ????
    216c:	ee 11       	cpse	r30, r14
    216e:	00 00       	nop
    2170:	24 00       	.word	0x0024	; ????
    2172:	c6 01       	movw	r24, r12
    2174:	94 e6       	ldi	r25, 0x64	; 100
    2176:	01 00       	.word	0x0001	; ????
    2178:	09 12       	cpse	r0, r25
    217a:	00 00       	nop
    217c:	40 00       	.word	0x0040	; ????
    217e:	c6 01       	movw	r24, r12
    2180:	18 00       	.word	0x0018	; ????
    2182:	00 00       	nop
    2184:	26 12       	cpse	r2, r22
    2186:	00 00       	nop
    2188:	40 00       	.word	0x0040	; ????
    218a:	c6 01       	movw	r24, r12
    218c:	0a 00       	.word	0x000a	; ????
    218e:	00 00       	nop
    2190:	32 12       	cpse	r3, r18
    2192:	00 00       	nop
    2194:	a0 00       	.word	0x00a0	; ????
    2196:	c6 01       	movw	r24, r12
    2198:	05 00       	.word	0x0005	; ????
    219a:	00 00       	nop
    219c:	00 00       	nop
    219e:	00 00       	nop
    21a0:	2e 00       	.word	0x002e	; ????
    21a2:	00 00       	nop
    21a4:	94 e6       	ldi	r25, 0x64	; 100
    21a6:	01 00       	.word	0x0001	; ????
    21a8:	00 00       	nop
    21aa:	00 00       	nop
    21ac:	44 00       	.word	0x0044	; ????
    21ae:	c7 01       	movw	r24, r14
	...
    21b8:	44 00       	.word	0x0044	; ????
    21ba:	c7 01       	movw	r24, r14
    21bc:	18 00       	.word	0x0018	; ????
    21be:	00 00       	nop
    21c0:	00 00       	nop
    21c2:	00 00       	nop
    21c4:	44 00       	.word	0x0044	; ????
    21c6:	bb 01       	movw	r22, r22
    21c8:	1a 00       	.word	0x001a	; ????
    21ca:	00 00       	nop
    21cc:	00 00       	nop
    21ce:	00 00       	nop
    21d0:	44 00       	.word	0x0044	; ????
    21d2:	b9 01       	movw	r22, r18
    21d4:	22 00       	.word	0x0022	; ????
    21d6:	00 00       	nop
    21d8:	00 00       	nop
    21da:	00 00       	nop
    21dc:	44 00       	.word	0x0044	; ????
    21de:	ca 01       	movw	r24, r20
    21e0:	28 00       	.word	0x0028	; ????
    21e2:	00 00       	nop
    21e4:	00 00       	nop
    21e6:	00 00       	nop
    21e8:	44 00       	.word	0x0044	; ????
    21ea:	cc 01       	movw	r24, r24
    21ec:	44 00       	.word	0x0044	; ????
    21ee:	00 00       	nop
    21f0:	00 00       	nop
    21f2:	00 00       	nop
    21f4:	44 00       	.word	0x0044	; ????
    21f6:	cd 01       	movw	r24, r26
    21f8:	48 00       	.word	0x0048	; ????
    21fa:	00 00       	nop
    21fc:	00 00       	nop
    21fe:	00 00       	nop
    2200:	44 00       	.word	0x0044	; ????
    2202:	ce 01       	movw	r24, r28
    2204:	58 00       	.word	0x0058	; ????
    2206:	00 00       	nop
    2208:	00 00       	nop
    220a:	00 00       	nop
    220c:	44 00       	.word	0x0044	; ????
    220e:	cf 01       	movw	r24, r30
    2210:	68 00       	.word	0x0068	; ????
    2212:	00 00       	nop
    2214:	00 00       	nop
    2216:	00 00       	nop
    2218:	44 00       	.word	0x0044	; ????
    221a:	d0 01       	movw	r26, r0
    221c:	6e 00       	.word	0x006e	; ????
    221e:	00 00       	nop
    2220:	00 00       	nop
    2222:	00 00       	nop
    2224:	44 00       	.word	0x0044	; ????
    2226:	cc 01       	movw	r24, r24
    2228:	80 00       	.word	0x0080	; ????
    222a:	00 00       	nop
    222c:	00 00       	nop
    222e:	00 00       	nop
    2230:	44 00       	.word	0x0044	; ????
    2232:	d4 01       	movw	r26, r8
    2234:	8c 00       	.word	0x008c	; ????
    2236:	00 00       	nop
    2238:	00 00       	nop
    223a:	00 00       	nop
    223c:	44 00       	.word	0x0044	; ????
    223e:	d5 01       	movw	r26, r10
    2240:	94 00       	.word	0x0094	; ????
    2242:	00 00       	nop
    2244:	00 00       	nop
    2246:	00 00       	nop
    2248:	44 00       	.word	0x0044	; ????
    224a:	88 01       	movw	r16, r16
    224c:	98 00       	.word	0x0098	; ????
    224e:	00 00       	nop
    2250:	00 00       	nop
    2252:	00 00       	nop
    2254:	44 00       	.word	0x0044	; ????
    2256:	8d 01       	movw	r16, r26
    2258:	9e 00       	.word	0x009e	; ????
    225a:	00 00       	nop
    225c:	00 00       	nop
    225e:	00 00       	nop
    2260:	44 00       	.word	0x0044	; ????
    2262:	8f 01       	movw	r16, r30
    2264:	ca 00       	.word	0x00ca	; ????
    2266:	00 00       	nop
    2268:	00 00       	nop
    226a:	00 00       	nop
    226c:	44 00       	.word	0x0044	; ????
    226e:	90 01       	movw	r18, r0
    2270:	ce 00       	.word	0x00ce	; ????
    2272:	00 00       	nop
    2274:	00 00       	nop
    2276:	00 00       	nop
    2278:	44 00       	.word	0x0044	; ????
    227a:	24 01       	movw	r4, r8
    227c:	de 00       	.word	0x00de	; ????
    227e:	00 00       	nop
    2280:	00 00       	nop
    2282:	00 00       	nop
    2284:	44 00       	.word	0x0044	; ????
    2286:	25 01       	movw	r4, r10
    2288:	e2 00       	.word	0x00e2	; ????
    228a:	00 00       	nop
    228c:	00 00       	nop
    228e:	00 00       	nop
    2290:	44 00       	.word	0x0044	; ????
    2292:	26 01       	movw	r4, r12
    2294:	f4 00       	.word	0x00f4	; ????
    2296:	00 00       	nop
    2298:	00 00       	nop
    229a:	00 00       	nop
    229c:	44 00       	.word	0x0044	; ????
    229e:	27 01       	movw	r4, r14
    22a0:	00 01       	movw	r0, r0
    22a2:	00 00       	nop
    22a4:	00 00       	nop
    22a6:	00 00       	nop
    22a8:	44 00       	.word	0x0044	; ????
    22aa:	28 01       	movw	r4, r16
    22ac:	1a 01       	movw	r2, r20
    22ae:	00 00       	nop
    22b0:	00 00       	nop
    22b2:	00 00       	nop
    22b4:	44 00       	.word	0x0044	; ????
    22b6:	29 01       	movw	r4, r18
    22b8:	36 01       	movw	r6, r12
    22ba:	00 00       	nop
    22bc:	00 00       	nop
    22be:	00 00       	nop
    22c0:	44 00       	.word	0x0044	; ????
    22c2:	22 01       	movw	r4, r4
    22c4:	64 01       	movw	r12, r8
    22c6:	00 00       	nop
    22c8:	00 00       	nop
    22ca:	00 00       	nop
    22cc:	44 00       	.word	0x0044	; ????
    22ce:	92 01       	movw	r18, r4
    22d0:	6c 01       	movw	r12, r24
    22d2:	00 00       	nop
    22d4:	00 00       	nop
    22d6:	00 00       	nop
    22d8:	44 00       	.word	0x0044	; ????
    22da:	8d 01       	movw	r16, r26
    22dc:	72 01       	movw	r14, r4
    22de:	00 00       	nop
    22e0:	00 00       	nop
    22e2:	00 00       	nop
    22e4:	44 00       	.word	0x0044	; ????
    22e6:	97 01       	movw	r18, r14
    22e8:	7e 01       	movw	r14, r28
    22ea:	00 00       	nop
    22ec:	00 00       	nop
    22ee:	00 00       	nop
    22f0:	44 00       	.word	0x0044	; ????
    22f2:	98 01       	movw	r18, r16
    22f4:	82 01       	movw	r16, r4
    22f6:	00 00       	nop
    22f8:	00 00       	nop
    22fa:	00 00       	nop
    22fc:	44 00       	.word	0x0044	; ????
    22fe:	99 01       	movw	r18, r18
    2300:	86 01       	movw	r16, r12
    2302:	00 00       	nop
    2304:	00 00       	nop
    2306:	00 00       	nop
    2308:	44 00       	.word	0x0044	; ????
    230a:	d9 01       	movw	r26, r18
    230c:	8c 01       	movw	r16, r24
    230e:	00 00       	nop
    2310:	d6 0f       	add	r29, r22
    2312:	00 00       	nop
    2314:	40 00       	.word	0x0040	; ????
    2316:	cc 01       	movw	r24, r24
    2318:	10 00       	.word	0x0010	; ????
    231a:	00 00       	nop
    231c:	00 00       	nop
    231e:	00 00       	nop
    2320:	c0 00       	.word	0x00c0	; ????
    2322:	00 00       	nop
    2324:	44 00       	.word	0x0044	; ????
    2326:	00 00       	nop
    2328:	00 00       	nop
    232a:	00 00       	nop
    232c:	e0 00       	.word	0x00e0	; ????
    232e:	00 00       	nop
    2330:	8c 00       	.word	0x008c	; ????
    2332:	00 00       	nop
    2334:	48 12       	cpse	r4, r24
    2336:	00 00       	nop
    2338:	80 00       	.word	0x0080	; ????
    233a:	85 01       	movw	r16, r10
    233c:	01 00       	.word	0x0001	; ????
    233e:	00 00       	nop
    2340:	00 00       	nop
    2342:	00 00       	nop
    2344:	c0 00       	.word	0x00c0	; ????
    2346:	00 00       	nop
    2348:	98 00       	.word	0x0098	; ????
    234a:	00 00       	nop
    234c:	54 12       	cpse	r5, r20
    234e:	00 00       	nop
    2350:	40 00       	.word	0x0040	; ????
    2352:	21 01       	movw	r4, r2
    2354:	05 00       	.word	0x0005	; ????
    2356:	00 00       	nop
    2358:	5f 12       	cpse	r5, r31
    235a:	00 00       	nop
    235c:	40 00       	.word	0x0040	; ????
    235e:	21 01       	movw	r4, r2
    2360:	04 00       	.word	0x0004	; ????
    2362:	00 00       	nop
    2364:	00 00       	nop
    2366:	00 00       	nop
    2368:	c0 00       	.word	0x00c0	; ????
    236a:	00 00       	nop
    236c:	de 00       	.word	0x00de	; ????
    236e:	00 00       	nop
    2370:	00 00       	nop
    2372:	00 00       	nop
    2374:	e0 00       	.word	0x00e0	; ????
    2376:	00 00       	nop
    2378:	6c 01       	movw	r12, r24
    237a:	00 00       	nop
    237c:	00 00       	nop
    237e:	00 00       	nop
    2380:	e0 00       	.word	0x00e0	; ????
    2382:	00 00       	nop
    2384:	8c 01       	movw	r16, r24
    2386:	00 00       	nop
    2388:	00 00       	nop
    238a:	00 00       	nop
    238c:	24 00       	.word	0x0024	; ????
    238e:	00 00       	nop
    2390:	94 01       	movw	r18, r8
    2392:	00 00       	nop
    2394:	00 00       	nop
    2396:	00 00       	nop
    2398:	4e 00       	.word	0x004e	; ????
    239a:	00 00       	nop
    239c:	28 e8       	ldi	r18, 0x88	; 136
    239e:	01 00       	.word	0x0001	; ????
    23a0:	68 12       	cpse	r6, r24
    23a2:	00 00       	nop
    23a4:	24 00       	.word	0x0024	; ????
    23a6:	db 01       	movw	r26, r22
    23a8:	28 e8       	ldi	r18, 0x88	; 136
    23aa:	01 00       	.word	0x0001	; ????
    23ac:	83 12       	cpse	r8, r19
    23ae:	00 00       	nop
    23b0:	40 00       	.word	0x0040	; ????
    23b2:	db 01       	movw	r26, r22
    23b4:	18 00       	.word	0x0018	; ????
    23b6:	00 00       	nop
    23b8:	26 12       	cpse	r2, r22
    23ba:	00 00       	nop
    23bc:	40 00       	.word	0x0040	; ????
    23be:	db 01       	movw	r26, r22
    23c0:	0c 00       	.word	0x000c	; ????
    23c2:	00 00       	nop
    23c4:	91 12       	cpse	r9, r17
    23c6:	00 00       	nop
    23c8:	40 00       	.word	0x0040	; ????
    23ca:	db 01       	movw	r26, r22
    23cc:	0a 00       	.word	0x000a	; ????
    23ce:	00 00       	nop
    23d0:	00 00       	nop
    23d2:	00 00       	nop
    23d4:	2e 00       	.word	0x002e	; ????
    23d6:	00 00       	nop
    23d8:	28 e8       	ldi	r18, 0x88	; 136
    23da:	01 00       	.word	0x0001	; ????
    23dc:	00 00       	nop
    23de:	00 00       	nop
    23e0:	44 00       	.word	0x0044	; ????
    23e2:	dc 01       	movw	r26, r24
	...
    23ec:	44 00       	.word	0x0044	; ????
    23ee:	dc 01       	movw	r26, r24
    23f0:	16 00       	.word	0x0016	; ????
    23f2:	00 00       	nop
    23f4:	00 00       	nop
    23f6:	00 00       	nop
    23f8:	44 00       	.word	0x0044	; ????
    23fa:	bb 01       	movw	r22, r22
    23fc:	18 00       	.word	0x0018	; ????
    23fe:	00 00       	nop
    2400:	00 00       	nop
    2402:	00 00       	nop
    2404:	44 00       	.word	0x0044	; ????
    2406:	b9 01       	movw	r22, r18
    2408:	20 00       	.word	0x0020	; ????
    240a:	00 00       	nop
    240c:	00 00       	nop
    240e:	00 00       	nop
    2410:	44 00       	.word	0x0044	; ????
    2412:	df 01       	movw	r26, r30
    2414:	26 00       	.word	0x0026	; ????
    2416:	00 00       	nop
    2418:	00 00       	nop
    241a:	00 00       	nop
    241c:	44 00       	.word	0x0044	; ????
    241e:	e1 01       	movw	r28, r2
    2420:	3a 00       	.word	0x003a	; ????
    2422:	00 00       	nop
    2424:	00 00       	nop
    2426:	00 00       	nop
    2428:	44 00       	.word	0x0044	; ????
    242a:	e2 01       	movw	r28, r4
    242c:	3e 00       	.word	0x003e	; ????
    242e:	00 00       	nop
    2430:	00 00       	nop
    2432:	00 00       	nop
    2434:	44 00       	.word	0x0044	; ????
    2436:	e3 01       	movw	r28, r6
    2438:	4e 00       	.word	0x004e	; ????
    243a:	00 00       	nop
    243c:	00 00       	nop
    243e:	00 00       	nop
    2440:	44 00       	.word	0x0044	; ????
    2442:	e4 01       	movw	r28, r8
    2444:	5e 00       	.word	0x005e	; ????
    2446:	00 00       	nop
    2448:	00 00       	nop
    244a:	00 00       	nop
    244c:	44 00       	.word	0x0044	; ????
    244e:	e5 01       	movw	r28, r10
    2450:	66 00       	.word	0x0066	; ????
    2452:	00 00       	nop
    2454:	00 00       	nop
    2456:	00 00       	nop
    2458:	44 00       	.word	0x0044	; ????
    245a:	e1 01       	movw	r28, r2
    245c:	78 00       	.word	0x0078	; ????
    245e:	00 00       	nop
    2460:	00 00       	nop
    2462:	00 00       	nop
    2464:	44 00       	.word	0x0044	; ????
    2466:	ea 01       	movw	r28, r20
    2468:	86 00       	.word	0x0086	; ????
    246a:	00 00       	nop
    246c:	00 00       	nop
    246e:	00 00       	nop
    2470:	44 00       	.word	0x0044	; ????
    2472:	eb 01       	movw	r28, r22
    2474:	8e 00       	.word	0x008e	; ????
    2476:	00 00       	nop
    2478:	00 00       	nop
    247a:	00 00       	nop
    247c:	44 00       	.word	0x0044	; ????
    247e:	a1 01       	movw	r20, r2
    2480:	92 00       	.word	0x0092	; ????
    2482:	00 00       	nop
    2484:	00 00       	nop
    2486:	00 00       	nop
    2488:	44 00       	.word	0x0044	; ????
    248a:	a6 01       	movw	r20, r12
    248c:	98 00       	.word	0x0098	; ????
    248e:	00 00       	nop
    2490:	00 00       	nop
    2492:	00 00       	nop
    2494:	44 00       	.word	0x0044	; ????
    2496:	a8 01       	movw	r20, r16
    2498:	ac 00       	.word	0x00ac	; ????
    249a:	00 00       	nop
    249c:	00 00       	nop
    249e:	00 00       	nop
    24a0:	44 00       	.word	0x0044	; ????
    24a2:	a9 01       	movw	r20, r18
    24a4:	b0 00       	.word	0x00b0	; ????
    24a6:	00 00       	nop
    24a8:	00 00       	nop
    24aa:	00 00       	nop
    24ac:	44 00       	.word	0x0044	; ????
    24ae:	aa 01       	movw	r20, r20
    24b0:	b4 00       	.word	0x00b4	; ????
    24b2:	00 00       	nop
    24b4:	00 00       	nop
    24b6:	00 00       	nop
    24b8:	44 00       	.word	0x0044	; ????
    24ba:	4a 01       	movw	r8, r20
    24bc:	c0 00       	.word	0x00c0	; ????
    24be:	00 00       	nop
    24c0:	00 00       	nop
    24c2:	00 00       	nop
    24c4:	44 00       	.word	0x0044	; ????
    24c6:	4b 01       	movw	r8, r22
    24c8:	cc 00       	.word	0x00cc	; ????
    24ca:	00 00       	nop
    24cc:	00 00       	nop
    24ce:	00 00       	nop
    24d0:	44 00       	.word	0x0044	; ????
    24d2:	4c 01       	movw	r8, r24
    24d4:	d0 00       	.word	0x00d0	; ????
    24d6:	00 00       	nop
    24d8:	00 00       	nop
    24da:	00 00       	nop
    24dc:	44 00       	.word	0x0044	; ????
    24de:	4d 01       	movw	r8, r26
    24e0:	d6 00       	.word	0x00d6	; ????
    24e2:	00 00       	nop
    24e4:	00 00       	nop
    24e6:	00 00       	nop
    24e8:	44 00       	.word	0x0044	; ????
    24ea:	4f 01       	movw	r8, r30
    24ec:	da 00       	.word	0x00da	; ????
    24ee:	00 00       	nop
    24f0:	00 00       	nop
    24f2:	00 00       	nop
    24f4:	44 00       	.word	0x0044	; ????
    24f6:	50 01       	movw	r10, r0
    24f8:	72 01       	movw	r14, r4
    24fa:	00 00       	nop
    24fc:	00 00       	nop
    24fe:	00 00       	nop
    2500:	44 00       	.word	0x0044	; ????
    2502:	51 01       	movw	r10, r2
    2504:	90 01       	movw	r18, r0
    2506:	00 00       	nop
    2508:	00 00       	nop
    250a:	00 00       	nop
    250c:	44 00       	.word	0x0044	; ????
    250e:	52 01       	movw	r10, r4
    2510:	a6 01       	movw	r20, r12
    2512:	00 00       	nop
    2514:	00 00       	nop
    2516:	00 00       	nop
    2518:	44 00       	.word	0x0044	; ????
    251a:	48 01       	movw	r8, r16
    251c:	b8 01       	movw	r22, r16
    251e:	00 00       	nop
    2520:	00 00       	nop
    2522:	00 00       	nop
    2524:	44 00       	.word	0x0044	; ????
    2526:	a6 01       	movw	r20, r12
    2528:	c4 01       	movw	r24, r8
    252a:	00 00       	nop
    252c:	00 00       	nop
    252e:	00 00       	nop
    2530:	44 00       	.word	0x0044	; ????
    2532:	b0 01       	movw	r22, r0
    2534:	ca 01       	movw	r24, r20
    2536:	00 00       	nop
    2538:	00 00       	nop
    253a:	00 00       	nop
    253c:	44 00       	.word	0x0044	; ????
    253e:	b1 01       	movw	r22, r2
    2540:	ce 01       	movw	r24, r28
    2542:	00 00       	nop
    2544:	00 00       	nop
    2546:	00 00       	nop
    2548:	44 00       	.word	0x0044	; ????
    254a:	b2 01       	movw	r22, r4
    254c:	d2 01       	movw	r26, r4
    254e:	00 00       	nop
    2550:	00 00       	nop
    2552:	00 00       	nop
    2554:	44 00       	.word	0x0044	; ????
    2556:	ee 01       	movw	r28, r28
    2558:	d8 01       	movw	r26, r16
    255a:	00 00       	nop
    255c:	d6 0f       	add	r29, r22
    255e:	00 00       	nop
    2560:	40 00       	.word	0x0040	; ????
    2562:	e1 01       	movw	r28, r2
    2564:	08 00       	.word	0x0008	; ????
    2566:	00 00       	nop
    2568:	00 00       	nop
    256a:	00 00       	nop
    256c:	c0 00       	.word	0x00c0	; ????
    256e:	00 00       	nop
    2570:	3a 00       	.word	0x003a	; ????
    2572:	00 00       	nop
    2574:	00 00       	nop
    2576:	00 00       	nop
    2578:	e0 00       	.word	0x00e0	; ????
    257a:	00 00       	nop
    257c:	86 00       	.word	0x0086	; ????
    257e:	00 00       	nop
    2580:	a0 12       	cpse	r10, r16
    2582:	00 00       	nop
    2584:	40 00       	.word	0x0040	; ????
    2586:	9e 01       	movw	r18, r28
    2588:	02 00       	.word	0x0002	; ????
    258a:	00 00       	nop
    258c:	00 00       	nop
    258e:	00 00       	nop
    2590:	c0 00       	.word	0x00c0	; ????
    2592:	00 00       	nop
    2594:	92 00       	.word	0x0092	; ????
    2596:	00 00       	nop
    2598:	ad 12       	cpse	r10, r29
    259a:	00 00       	nop
    259c:	40 00       	.word	0x0040	; ????
    259e:	47 01       	movw	r8, r14
    25a0:	11 00       	.word	0x0011	; ????
    25a2:	00 00       	nop
    25a4:	b6 12       	cpse	r11, r22
    25a6:	00 00       	nop
    25a8:	40 00       	.word	0x0040	; ????
    25aa:	47 01       	movw	r8, r14
    25ac:	16 00       	.word	0x0016	; ????
    25ae:	00 00       	nop
    25b0:	bf 12       	cpse	r11, r31
    25b2:	00 00       	nop
    25b4:	40 00       	.word	0x0040	; ????
    25b6:	47 01       	movw	r8, r14
    25b8:	0e 00       	.word	0x000e	; ????
    25ba:	00 00       	nop
    25bc:	c8 12       	cpse	r12, r24
    25be:	00 00       	nop
    25c0:	40 00       	.word	0x0040	; ????
    25c2:	47 01       	movw	r8, r14
    25c4:	10 00       	.word	0x0010	; ????
    25c6:	00 00       	nop
    25c8:	00 00       	nop
    25ca:	00 00       	nop
    25cc:	c0 00       	.word	0x00c0	; ????
    25ce:	00 00       	nop
    25d0:	c0 00       	.word	0x00c0	; ????
    25d2:	00 00       	nop
    25d4:	00 00       	nop
    25d6:	00 00       	nop
    25d8:	e0 00       	.word	0x00e0	; ????
    25da:	00 00       	nop
    25dc:	c4 01       	movw	r24, r8
    25de:	00 00       	nop
    25e0:	00 00       	nop
    25e2:	00 00       	nop
    25e4:	e0 00       	.word	0x00e0	; ????
    25e6:	00 00       	nop
    25e8:	d8 01       	movw	r26, r16
    25ea:	00 00       	nop
    25ec:	00 00       	nop
    25ee:	00 00       	nop
    25f0:	24 00       	.word	0x0024	; ????
    25f2:	00 00       	nop
    25f4:	e0 01       	movw	r28, r0
    25f6:	00 00       	nop
    25f8:	00 00       	nop
    25fa:	00 00       	nop
    25fc:	4e 00       	.word	0x004e	; ????
    25fe:	00 00       	nop
    2600:	08 ea       	ldi	r16, 0xA8	; 168
    2602:	01 00       	.word	0x0001	; ????
    2604:	d1 12       	cpse	r13, r17
    2606:	00 00       	nop
    2608:	28 00       	.word	0x0028	; ????
    260a:	3e 00       	.word	0x003e	; ????
    260c:	b2 01       	movw	r22, r4
    260e:	80 00       	.word	0x0080	; ????
    2610:	e7 12       	cpse	r14, r23
    2612:	00 00       	nop
    2614:	28 00       	.word	0x0028	; ????
    2616:	41 00       	.word	0x0041	; ????
    2618:	02 01       	movw	r0, r4
    261a:	80 00       	.word	0x0080	; ????
    261c:	0d 13       	cpse	r16, r29
    261e:	00 00       	nop
    2620:	28 00       	.word	0x0028	; ????
    2622:	44 00       	.word	0x0044	; ????
    2624:	00 01       	movw	r0, r0
    2626:	80 00       	.word	0x0080	; ????
    2628:	19 13       	cpse	r17, r25
    262a:	00 00       	nop
    262c:	26 00       	.word	0x0026	; ????
    262e:	4e 00       	.word	0x004e	; ????
    2630:	03 02       	muls	r16, r19
    2632:	81 00       	.word	0x0081	; ????
    2634:	3c 13       	cpse	r19, r28
    2636:	00 00       	nop
    2638:	26 00       	.word	0x0026	; ????
    263a:	63 00       	.word	0x0063	; ????
    263c:	03 01       	movw	r0, r6
    263e:	81 00       	.word	0x0081	; ????
    2640:	4a 13       	cpse	r20, r26
    2642:	00 00       	nop
    2644:	26 00       	.word	0x0026	; ????
    2646:	7a 00       	.word	0x007a	; ????
    2648:	04 00       	.word	0x0004	; ????
    264a:	81 00       	.word	0x0081	; ????
    264c:	6d 13       	cpse	r22, r29
    264e:	00 00       	nop
    2650:	20 00       	.word	0x0020	; ????
    2652:	61 00       	.word	0x0061	; ????
    2654:	00 00       	nop
    2656:	00 00       	nop
    2658:	8f 13       	cpse	r24, r31
    265a:	00 00       	nop
    265c:	20 00       	.word	0x0020	; ????
    265e:	75 00       	.word	0x0075	; ????
    2660:	00 00       	nop
    2662:	00 00       	nop
    2664:	9d 13       	cpse	r25, r29
    2666:	00 00       	nop
    2668:	20 00       	.word	0x0020	; ????
    266a:	8c 00       	.word	0x008c	; ????
	...
    2674:	64 00       	.word	0x0064	; ????
    2676:	00 00       	nop
    2678:	08 ea       	ldi	r16, 0xA8	; 168
    267a:	01 00       	.word	0x0001	; ????

Disassembly of section .stabstr:

00000000 <.stabstr>:
       0:	00 75       	andi	r16, 0x50	; 80
       2:	61 72       	andi	r22, 0x21	; 33
       4:	74 2e       	mov	r7, r20
       6:	63 00       	.word	0x0063	; ????
       8:	2f 68       	ori	r18, 0x8F	; 143
       a:	6f 6d       	ori	r22, 0xDF	; 223
       c:	65 2f       	mov	r22, r21
       e:	75 62       	ori	r23, 0x25	; 37
      10:	75 6e       	ori	r23, 0xE5	; 229
      12:	74 75       	andi	r23, 0x54	; 84
      14:	2f 65       	ori	r18, 0x5F	; 95
      16:	63 74       	andi	r22, 0x43	; 67
      18:	66 31       	cpi	r22, 0x16	; 22
      1a:	37 2f       	mov	r19, r23
      1c:	62 6f       	ori	r22, 0xF2	; 242
      1e:	6f 74       	andi	r22, 0x4F	; 79
      20:	6c 6f       	ori	r22, 0xFC	; 252
      22:	61 64       	ori	r22, 0x41	; 65
      24:	65 72       	andi	r22, 0x25	; 37
      26:	2f 00       	.word	0x002f	; ????
      28:	73 72       	andi	r23, 0x23	; 35
      2a:	63 2f       	mov	r22, r19
      2c:	75 61       	ori	r23, 0x15	; 21
      2e:	72 74       	andi	r23, 0x42	; 66
      30:	2e 63       	ori	r18, 0x3E	; 62
      32:	00 67       	ori	r16, 0x70	; 112
      34:	63 63       	ori	r22, 0x33	; 51
      36:	32 5f       	subi	r19, 0xF2	; 242
      38:	63 6f       	ori	r22, 0xF3	; 243
      3a:	6d 70       	andi	r22, 0x0D	; 13
      3c:	69 6c       	ori	r22, 0xC9	; 201
      3e:	65 64       	ori	r22, 0x45	; 69
      40:	2e 00       	.word	0x002e	; ????
      42:	69 6e       	ori	r22, 0xE9	; 233
      44:	74 3a       	cpi	r23, 0xA4	; 164
      46:	74 28       	or	r7, r4
      48:	30 2c       	mov	r3, r0
      4a:	31 29       	or	r19, r1
      4c:	3d 72       	andi	r19, 0x2D	; 45
      4e:	28 30       	cpi	r18, 0x08	; 8
      50:	2c 31       	cpi	r18, 0x1C	; 28
      52:	29 3b       	cpi	r18, 0xB9	; 185
      54:	2d 33       	cpi	r18, 0x3D	; 61
      56:	32 37       	cpi	r19, 0x72	; 114
      58:	36 38       	cpi	r19, 0x86	; 134
      5a:	3b 33       	cpi	r19, 0x3B	; 59
      5c:	32 37       	cpi	r19, 0x72	; 114
      5e:	36 37       	cpi	r19, 0x76	; 118
      60:	3b 00       	.word	0x003b	; ????
      62:	63 68       	ori	r22, 0x83	; 131
      64:	61 72       	andi	r22, 0x21	; 33
      66:	3a 74       	andi	r19, 0x4A	; 74
      68:	28 30       	cpi	r18, 0x08	; 8
      6a:	2c 32       	cpi	r18, 0x2C	; 44
      6c:	29 3d       	cpi	r18, 0xD9	; 217
      6e:	72 28       	or	r7, r2
      70:	30 2c       	mov	r3, r0
      72:	32 29       	or	r19, r2
      74:	3b 30       	cpi	r19, 0x0B	; 11
      76:	3b 31       	cpi	r19, 0x1B	; 27
      78:	32 37       	cpi	r19, 0x72	; 114
      7a:	3b 00       	.word	0x003b	; ????
      7c:	6c 6f       	ori	r22, 0xFC	; 252
      7e:	6e 67       	ori	r22, 0x7E	; 126
      80:	20 69       	ori	r18, 0x90	; 144
      82:	6e 74       	andi	r22, 0x4E	; 78
      84:	3a 74       	andi	r19, 0x4A	; 74
      86:	28 30       	cpi	r18, 0x08	; 8
      88:	2c 33       	cpi	r18, 0x3C	; 60
      8a:	29 3d       	cpi	r18, 0xD9	; 217
      8c:	40 73       	andi	r20, 0x30	; 48
      8e:	33 32       	cpi	r19, 0x23	; 35
      90:	3b 72       	andi	r19, 0x2B	; 43
      92:	28 30       	cpi	r18, 0x08	; 8
      94:	2c 33       	cpi	r18, 0x3C	; 60
      96:	29 3b       	cpi	r18, 0xB9	; 185
      98:	30 32       	cpi	r19, 0x20	; 32
      9a:	30 30       	cpi	r19, 0x00	; 0
      9c:	30 30       	cpi	r19, 0x00	; 0
      9e:	30 30       	cpi	r19, 0x00	; 0
      a0:	30 30       	cpi	r19, 0x00	; 0
      a2:	30 30       	cpi	r19, 0x00	; 0
      a4:	3b 30       	cpi	r19, 0x0B	; 11
      a6:	31 37       	cpi	r19, 0x71	; 113
      a8:	37 37       	cpi	r19, 0x77	; 119
      aa:	37 37       	cpi	r19, 0x77	; 119
      ac:	37 37       	cpi	r19, 0x77	; 119
      ae:	37 37       	cpi	r19, 0x77	; 119
      b0:	37 3b       	cpi	r19, 0xB7	; 183
      b2:	00 75       	andi	r16, 0x50	; 80
      b4:	6e 73       	andi	r22, 0x3E	; 62
      b6:	69 67       	ori	r22, 0x79	; 121
      b8:	6e 65       	ori	r22, 0x5E	; 94
      ba:	64 20       	and	r6, r4
      bc:	69 6e       	ori	r22, 0xE9	; 233
      be:	74 3a       	cpi	r23, 0xA4	; 164
      c0:	74 28       	or	r7, r4
      c2:	30 2c       	mov	r3, r0
      c4:	34 29       	or	r19, r4
      c6:	3d 72       	andi	r19, 0x2D	; 45
      c8:	28 30       	cpi	r18, 0x08	; 8
      ca:	2c 34       	cpi	r18, 0x4C	; 76
      cc:	29 3b       	cpi	r18, 0xB9	; 185
      ce:	30 3b       	cpi	r19, 0xB0	; 176
      d0:	30 31       	cpi	r19, 0x10	; 16
      d2:	37 37       	cpi	r19, 0x77	; 119
      d4:	37 37       	cpi	r19, 0x77	; 119
      d6:	37 3b       	cpi	r19, 0xB7	; 183
      d8:	00 6c       	ori	r16, 0xC0	; 192
      da:	6f 6e       	ori	r22, 0xEF	; 239
      dc:	67 20       	and	r6, r7
      de:	75 6e       	ori	r23, 0xE5	; 229
      e0:	73 69       	ori	r23, 0x93	; 147
      e2:	67 6e       	ori	r22, 0xE7	; 231
      e4:	65 64       	ori	r22, 0x45	; 69
      e6:	20 69       	ori	r18, 0x90	; 144
      e8:	6e 74       	andi	r22, 0x4E	; 78
      ea:	3a 74       	andi	r19, 0x4A	; 74
      ec:	28 30       	cpi	r18, 0x08	; 8
      ee:	2c 35       	cpi	r18, 0x5C	; 92
      f0:	29 3d       	cpi	r18, 0xD9	; 217
      f2:	40 73       	andi	r20, 0x30	; 48
      f4:	33 32       	cpi	r19, 0x23	; 35
      f6:	3b 72       	andi	r19, 0x2B	; 43
      f8:	28 30       	cpi	r18, 0x08	; 8
      fa:	2c 35       	cpi	r18, 0x5C	; 92
      fc:	29 3b       	cpi	r18, 0xB9	; 185
      fe:	30 3b       	cpi	r19, 0xB0	; 176
     100:	30 33       	cpi	r19, 0x30	; 48
     102:	37 37       	cpi	r19, 0x77	; 119
     104:	37 37       	cpi	r19, 0x77	; 119
     106:	37 37       	cpi	r19, 0x77	; 119
     108:	37 37       	cpi	r19, 0x77	; 119
     10a:	37 37       	cpi	r19, 0x77	; 119
     10c:	3b 00       	.word	0x003b	; ????
     10e:	6c 6f       	ori	r22, 0xFC	; 252
     110:	6e 67       	ori	r22, 0x7E	; 126
     112:	20 6c       	ori	r18, 0xC0	; 192
     114:	6f 6e       	ori	r22, 0xEF	; 239
     116:	67 20       	and	r6, r7
     118:	69 6e       	ori	r22, 0xE9	; 233
     11a:	74 3a       	cpi	r23, 0xA4	; 164
     11c:	74 28       	or	r7, r4
     11e:	30 2c       	mov	r3, r0
     120:	36 29       	or	r19, r6
     122:	3d 40       	sbci	r19, 0x0D	; 13
     124:	73 36       	cpi	r23, 0x63	; 99
     126:	34 3b       	cpi	r19, 0xB4	; 180
     128:	72 28       	or	r7, r2
     12a:	30 2c       	mov	r3, r0
     12c:	36 29       	or	r19, r6
     12e:	3b 30       	cpi	r19, 0x0B	; 11
     130:	31 30       	cpi	r19, 0x01	; 1
     132:	30 30       	cpi	r19, 0x00	; 0
     134:	30 30       	cpi	r19, 0x00	; 0
     136:	30 30       	cpi	r19, 0x00	; 0
     138:	30 30       	cpi	r19, 0x00	; 0
     13a:	30 30       	cpi	r19, 0x00	; 0
     13c:	30 30       	cpi	r19, 0x00	; 0
     13e:	30 30       	cpi	r19, 0x00	; 0
     140:	30 30       	cpi	r19, 0x00	; 0
     142:	30 30       	cpi	r19, 0x00	; 0
     144:	30 30       	cpi	r19, 0x00	; 0
     146:	3b 30       	cpi	r19, 0x0B	; 11
     148:	37 37       	cpi	r19, 0x77	; 119
     14a:	37 37       	cpi	r19, 0x77	; 119
     14c:	37 37       	cpi	r19, 0x77	; 119
     14e:	37 37       	cpi	r19, 0x77	; 119
     150:	37 37       	cpi	r19, 0x77	; 119
     152:	37 37       	cpi	r19, 0x77	; 119
     154:	37 37       	cpi	r19, 0x77	; 119
     156:	37 37       	cpi	r19, 0x77	; 119
     158:	37 37       	cpi	r19, 0x77	; 119
     15a:	37 37       	cpi	r19, 0x77	; 119
     15c:	37 3b       	cpi	r19, 0xB7	; 183
     15e:	00 6c       	ori	r16, 0xC0	; 192
     160:	6f 6e       	ori	r22, 0xEF	; 239
     162:	67 20       	and	r6, r7
     164:	6c 6f       	ori	r22, 0xFC	; 252
     166:	6e 67       	ori	r22, 0x7E	; 126
     168:	20 75       	andi	r18, 0x50	; 80
     16a:	6e 73       	andi	r22, 0x3E	; 62
     16c:	69 67       	ori	r22, 0x79	; 121
     16e:	6e 65       	ori	r22, 0x5E	; 94
     170:	64 20       	and	r6, r4
     172:	69 6e       	ori	r22, 0xE9	; 233
     174:	74 3a       	cpi	r23, 0xA4	; 164
     176:	74 28       	or	r7, r4
     178:	30 2c       	mov	r3, r0
     17a:	37 29       	or	r19, r7
     17c:	3d 40       	sbci	r19, 0x0D	; 13
     17e:	73 36       	cpi	r23, 0x63	; 99
     180:	34 3b       	cpi	r19, 0xB4	; 180
     182:	72 28       	or	r7, r2
     184:	30 2c       	mov	r3, r0
     186:	37 29       	or	r19, r7
     188:	3b 30       	cpi	r19, 0x0B	; 11
     18a:	3b 30       	cpi	r19, 0x0B	; 11
     18c:	31 37       	cpi	r19, 0x71	; 113
     18e:	37 37       	cpi	r19, 0x77	; 119
     190:	37 37       	cpi	r19, 0x77	; 119
     192:	37 37       	cpi	r19, 0x77	; 119
     194:	37 37       	cpi	r19, 0x77	; 119
     196:	37 37       	cpi	r19, 0x77	; 119
     198:	37 37       	cpi	r19, 0x77	; 119
     19a:	37 37       	cpi	r19, 0x77	; 119
     19c:	37 37       	cpi	r19, 0x77	; 119
     19e:	37 37       	cpi	r19, 0x77	; 119
     1a0:	37 37       	cpi	r19, 0x77	; 119
     1a2:	3b 00       	.word	0x003b	; ????
     1a4:	73 68       	ori	r23, 0x83	; 131
     1a6:	6f 72       	andi	r22, 0x2F	; 47
     1a8:	74 20       	and	r7, r4
     1aa:	69 6e       	ori	r22, 0xE9	; 233
     1ac:	74 3a       	cpi	r23, 0xA4	; 164
     1ae:	74 28       	or	r7, r4
     1b0:	30 2c       	mov	r3, r0
     1b2:	38 29       	or	r19, r8
     1b4:	3d 72       	andi	r19, 0x2D	; 45
     1b6:	28 30       	cpi	r18, 0x08	; 8
     1b8:	2c 38       	cpi	r18, 0x8C	; 140
     1ba:	29 3b       	cpi	r18, 0xB9	; 185
     1bc:	2d 33       	cpi	r18, 0x3D	; 61
     1be:	32 37       	cpi	r19, 0x72	; 114
     1c0:	36 38       	cpi	r19, 0x86	; 134
     1c2:	3b 33       	cpi	r19, 0x3B	; 59
     1c4:	32 37       	cpi	r19, 0x72	; 114
     1c6:	36 37       	cpi	r19, 0x76	; 118
     1c8:	3b 00       	.word	0x003b	; ????
     1ca:	73 68       	ori	r23, 0x83	; 131
     1cc:	6f 72       	andi	r22, 0x2F	; 47
     1ce:	74 20       	and	r7, r4
     1d0:	75 6e       	ori	r23, 0xE5	; 229
     1d2:	73 69       	ori	r23, 0x93	; 147
     1d4:	67 6e       	ori	r22, 0xE7	; 231
     1d6:	65 64       	ori	r22, 0x45	; 69
     1d8:	20 69       	ori	r18, 0x90	; 144
     1da:	6e 74       	andi	r22, 0x4E	; 78
     1dc:	3a 74       	andi	r19, 0x4A	; 74
     1de:	28 30       	cpi	r18, 0x08	; 8
     1e0:	2c 39       	cpi	r18, 0x9C	; 156
     1e2:	29 3d       	cpi	r18, 0xD9	; 217
     1e4:	72 28       	or	r7, r2
     1e6:	30 2c       	mov	r3, r0
     1e8:	39 29       	or	r19, r9
     1ea:	3b 30       	cpi	r19, 0x0B	; 11
     1ec:	3b 30       	cpi	r19, 0x0B	; 11
     1ee:	31 37       	cpi	r19, 0x71	; 113
     1f0:	37 37       	cpi	r19, 0x77	; 119
     1f2:	37 37       	cpi	r19, 0x77	; 119
     1f4:	3b 00       	.word	0x003b	; ????
     1f6:	73 69       	ori	r23, 0x93	; 147
     1f8:	67 6e       	ori	r22, 0xE7	; 231
     1fa:	65 64       	ori	r22, 0x45	; 69
     1fc:	20 63       	ori	r18, 0x30	; 48
     1fe:	68 61       	ori	r22, 0x18	; 24
     200:	72 3a       	cpi	r23, 0xA2	; 162
     202:	74 28       	or	r7, r4
     204:	30 2c       	mov	r3, r0
     206:	31 30       	cpi	r19, 0x01	; 1
     208:	29 3d       	cpi	r18, 0xD9	; 217
     20a:	40 73       	andi	r20, 0x30	; 48
     20c:	38 3b       	cpi	r19, 0xB8	; 184
     20e:	72 28       	or	r7, r2
     210:	30 2c       	mov	r3, r0
     212:	31 30       	cpi	r19, 0x01	; 1
     214:	29 3b       	cpi	r18, 0xB9	; 185
     216:	2d 31       	cpi	r18, 0x1D	; 29
     218:	32 38       	cpi	r19, 0x82	; 130
     21a:	3b 31       	cpi	r19, 0x1B	; 27
     21c:	32 37       	cpi	r19, 0x72	; 114
     21e:	3b 00       	.word	0x003b	; ????
     220:	75 6e       	ori	r23, 0xE5	; 229
     222:	73 69       	ori	r23, 0x93	; 147
     224:	67 6e       	ori	r22, 0xE7	; 231
     226:	65 64       	ori	r22, 0x45	; 69
     228:	20 63       	ori	r18, 0x30	; 48
     22a:	68 61       	ori	r22, 0x18	; 24
     22c:	72 3a       	cpi	r23, 0xA2	; 162
     22e:	74 28       	or	r7, r4
     230:	30 2c       	mov	r3, r0
     232:	31 31       	cpi	r19, 0x11	; 17
     234:	29 3d       	cpi	r18, 0xD9	; 217
     236:	40 73       	andi	r20, 0x30	; 48
     238:	38 3b       	cpi	r19, 0xB8	; 184
     23a:	72 28       	or	r7, r2
     23c:	30 2c       	mov	r3, r0
     23e:	31 31       	cpi	r19, 0x11	; 17
     240:	29 3b       	cpi	r18, 0xB9	; 185
     242:	30 3b       	cpi	r19, 0xB0	; 176
     244:	32 35       	cpi	r19, 0x52	; 82
     246:	35 3b       	cpi	r19, 0xB5	; 181
     248:	00 66       	ori	r16, 0x60	; 96
     24a:	6c 6f       	ori	r22, 0xFC	; 252
     24c:	61 74       	andi	r22, 0x41	; 65
     24e:	3a 74       	andi	r19, 0x4A	; 74
     250:	28 30       	cpi	r18, 0x08	; 8
     252:	2c 31       	cpi	r18, 0x1C	; 28
     254:	32 29       	or	r19, r2
     256:	3d 72       	andi	r19, 0x2D	; 45
     258:	28 30       	cpi	r18, 0x08	; 8
     25a:	2c 31       	cpi	r18, 0x1C	; 28
     25c:	29 3b       	cpi	r18, 0xB9	; 185
     25e:	34 3b       	cpi	r19, 0xB4	; 180
     260:	30 3b       	cpi	r19, 0xB0	; 176
     262:	00 64       	ori	r16, 0x40	; 64
     264:	6f 75       	andi	r22, 0x5F	; 95
     266:	62 6c       	ori	r22, 0xC2	; 194
     268:	65 3a       	cpi	r22, 0xA5	; 165
     26a:	74 28       	or	r7, r4
     26c:	30 2c       	mov	r3, r0
     26e:	31 33       	cpi	r19, 0x31	; 49
     270:	29 3d       	cpi	r18, 0xD9	; 217
     272:	72 28       	or	r7, r2
     274:	30 2c       	mov	r3, r0
     276:	31 29       	or	r19, r1
     278:	3b 34       	cpi	r19, 0x4B	; 75
     27a:	3b 30       	cpi	r19, 0x0B	; 11
     27c:	3b 00       	.word	0x003b	; ????
     27e:	6c 6f       	ori	r22, 0xFC	; 252
     280:	6e 67       	ori	r22, 0x7E	; 126
     282:	20 64       	ori	r18, 0x40	; 64
     284:	6f 75       	andi	r22, 0x5F	; 95
     286:	62 6c       	ori	r22, 0xC2	; 194
     288:	65 3a       	cpi	r22, 0xA5	; 165
     28a:	74 28       	or	r7, r4
     28c:	30 2c       	mov	r3, r0
     28e:	31 34       	cpi	r19, 0x41	; 65
     290:	29 3d       	cpi	r18, 0xD9	; 217
     292:	72 28       	or	r7, r2
     294:	30 2c       	mov	r3, r0
     296:	31 29       	or	r19, r1
     298:	3b 34       	cpi	r19, 0x4B	; 75
     29a:	3b 30       	cpi	r19, 0x0B	; 11
     29c:	3b 00       	.word	0x003b	; ????
     29e:	73 68       	ori	r23, 0x83	; 131
     2a0:	6f 72       	andi	r22, 0x2F	; 47
     2a2:	74 20       	and	r7, r4
     2a4:	5f 46       	sbci	r21, 0x6F	; 111
     2a6:	72 61       	ori	r23, 0x12	; 18
     2a8:	63 74       	andi	r22, 0x43	; 67
     2aa:	3a 74       	andi	r19, 0x4A	; 74
     2ac:	28 30       	cpi	r18, 0x08	; 8
     2ae:	2c 31       	cpi	r18, 0x1C	; 28
     2b0:	35 29       	or	r19, r5
     2b2:	3d 72       	andi	r19, 0x2D	; 45
     2b4:	28 30       	cpi	r18, 0x08	; 8
     2b6:	2c 31       	cpi	r18, 0x1C	; 28
     2b8:	29 3b       	cpi	r18, 0xB9	; 185
     2ba:	31 3b       	cpi	r19, 0xB1	; 177
     2bc:	30 3b       	cpi	r19, 0xB0	; 176
     2be:	00 5f       	subi	r16, 0xF0	; 240
     2c0:	46 72       	andi	r20, 0x26	; 38
     2c2:	61 63       	ori	r22, 0x31	; 49
     2c4:	74 3a       	cpi	r23, 0xA4	; 164
     2c6:	74 28       	or	r7, r4
     2c8:	30 2c       	mov	r3, r0
     2ca:	31 36       	cpi	r19, 0x61	; 97
     2cc:	29 3d       	cpi	r18, 0xD9	; 217
     2ce:	72 28       	or	r7, r2
     2d0:	30 2c       	mov	r3, r0
     2d2:	31 29       	or	r19, r1
     2d4:	3b 32       	cpi	r19, 0x2B	; 43
     2d6:	3b 30       	cpi	r19, 0x0B	; 11
     2d8:	3b 00       	.word	0x003b	; ????
     2da:	6c 6f       	ori	r22, 0xFC	; 252
     2dc:	6e 67       	ori	r22, 0x7E	; 126
     2de:	20 5f       	subi	r18, 0xF0	; 240
     2e0:	46 72       	andi	r20, 0x26	; 38
     2e2:	61 63       	ori	r22, 0x31	; 49
     2e4:	74 3a       	cpi	r23, 0xA4	; 164
     2e6:	74 28       	or	r7, r4
     2e8:	30 2c       	mov	r3, r0
     2ea:	31 37       	cpi	r19, 0x71	; 113
     2ec:	29 3d       	cpi	r18, 0xD9	; 217
     2ee:	72 28       	or	r7, r2
     2f0:	30 2c       	mov	r3, r0
     2f2:	31 29       	or	r19, r1
     2f4:	3b 34       	cpi	r19, 0x4B	; 75
     2f6:	3b 30       	cpi	r19, 0x0B	; 11
     2f8:	3b 00       	.word	0x003b	; ????
     2fa:	6c 6f       	ori	r22, 0xFC	; 252
     2fc:	6e 67       	ori	r22, 0x7E	; 126
     2fe:	20 6c       	ori	r18, 0xC0	; 192
     300:	6f 6e       	ori	r22, 0xEF	; 239
     302:	67 20       	and	r6, r7
     304:	5f 46       	sbci	r21, 0x6F	; 111
     306:	72 61       	ori	r23, 0x12	; 18
     308:	63 74       	andi	r22, 0x43	; 67
     30a:	3a 74       	andi	r19, 0x4A	; 74
     30c:	28 30       	cpi	r18, 0x08	; 8
     30e:	2c 31       	cpi	r18, 0x1C	; 28
     310:	38 29       	or	r19, r8
     312:	3d 72       	andi	r19, 0x2D	; 45
     314:	28 30       	cpi	r18, 0x08	; 8
     316:	2c 31       	cpi	r18, 0x1C	; 28
     318:	29 3b       	cpi	r18, 0xB9	; 185
     31a:	38 3b       	cpi	r19, 0xB8	; 184
     31c:	30 3b       	cpi	r19, 0xB0	; 176
     31e:	00 75       	andi	r16, 0x50	; 80
     320:	6e 73       	andi	r22, 0x3E	; 62
     322:	69 67       	ori	r22, 0x79	; 121
     324:	6e 65       	ori	r22, 0x5E	; 94
     326:	64 20       	and	r6, r4
     328:	73 68       	ori	r23, 0x83	; 131
     32a:	6f 72       	andi	r22, 0x2F	; 47
     32c:	74 20       	and	r7, r4
     32e:	5f 46       	sbci	r21, 0x6F	; 111
     330:	72 61       	ori	r23, 0x12	; 18
     332:	63 74       	andi	r22, 0x43	; 67
     334:	3a 74       	andi	r19, 0x4A	; 74
     336:	28 30       	cpi	r18, 0x08	; 8
     338:	2c 31       	cpi	r18, 0x1C	; 28
     33a:	39 29       	or	r19, r9
     33c:	3d 72       	andi	r19, 0x2D	; 45
     33e:	28 30       	cpi	r18, 0x08	; 8
     340:	2c 31       	cpi	r18, 0x1C	; 28
     342:	29 3b       	cpi	r18, 0xB9	; 185
     344:	31 3b       	cpi	r19, 0xB1	; 177
     346:	30 3b       	cpi	r19, 0xB0	; 176
     348:	00 75       	andi	r16, 0x50	; 80
     34a:	6e 73       	andi	r22, 0x3E	; 62
     34c:	69 67       	ori	r22, 0x79	; 121
     34e:	6e 65       	ori	r22, 0x5E	; 94
     350:	64 20       	and	r6, r4
     352:	5f 46       	sbci	r21, 0x6F	; 111
     354:	72 61       	ori	r23, 0x12	; 18
     356:	63 74       	andi	r22, 0x43	; 67
     358:	3a 74       	andi	r19, 0x4A	; 74
     35a:	28 30       	cpi	r18, 0x08	; 8
     35c:	2c 32       	cpi	r18, 0x2C	; 44
     35e:	30 29       	or	r19, r0
     360:	3d 72       	andi	r19, 0x2D	; 45
     362:	28 30       	cpi	r18, 0x08	; 8
     364:	2c 31       	cpi	r18, 0x1C	; 28
     366:	29 3b       	cpi	r18, 0xB9	; 185
     368:	32 3b       	cpi	r19, 0xB2	; 178
     36a:	30 3b       	cpi	r19, 0xB0	; 176
     36c:	00 75       	andi	r16, 0x50	; 80
     36e:	6e 73       	andi	r22, 0x3E	; 62
     370:	69 67       	ori	r22, 0x79	; 121
     372:	6e 65       	ori	r22, 0x5E	; 94
     374:	64 20       	and	r6, r4
     376:	6c 6f       	ori	r22, 0xFC	; 252
     378:	6e 67       	ori	r22, 0x7E	; 126
     37a:	20 5f       	subi	r18, 0xF0	; 240
     37c:	46 72       	andi	r20, 0x26	; 38
     37e:	61 63       	ori	r22, 0x31	; 49
     380:	74 3a       	cpi	r23, 0xA4	; 164
     382:	74 28       	or	r7, r4
     384:	30 2c       	mov	r3, r0
     386:	32 31       	cpi	r19, 0x12	; 18
     388:	29 3d       	cpi	r18, 0xD9	; 217
     38a:	72 28       	or	r7, r2
     38c:	30 2c       	mov	r3, r0
     38e:	31 29       	or	r19, r1
     390:	3b 34       	cpi	r19, 0x4B	; 75
     392:	3b 30       	cpi	r19, 0x0B	; 11
     394:	3b 00       	.word	0x003b	; ????
     396:	75 6e       	ori	r23, 0xE5	; 229
     398:	73 69       	ori	r23, 0x93	; 147
     39a:	67 6e       	ori	r22, 0xE7	; 231
     39c:	65 64       	ori	r22, 0x45	; 69
     39e:	20 6c       	ori	r18, 0xC0	; 192
     3a0:	6f 6e       	ori	r22, 0xEF	; 239
     3a2:	67 20       	and	r6, r7
     3a4:	6c 6f       	ori	r22, 0xFC	; 252
     3a6:	6e 67       	ori	r22, 0x7E	; 126
     3a8:	20 5f       	subi	r18, 0xF0	; 240
     3aa:	46 72       	andi	r20, 0x26	; 38
     3ac:	61 63       	ori	r22, 0x31	; 49
     3ae:	74 3a       	cpi	r23, 0xA4	; 164
     3b0:	74 28       	or	r7, r4
     3b2:	30 2c       	mov	r3, r0
     3b4:	32 32       	cpi	r19, 0x22	; 34
     3b6:	29 3d       	cpi	r18, 0xD9	; 217
     3b8:	72 28       	or	r7, r2
     3ba:	30 2c       	mov	r3, r0
     3bc:	31 29       	or	r19, r1
     3be:	3b 38       	cpi	r19, 0x8B	; 139
     3c0:	3b 30       	cpi	r19, 0x0B	; 11
     3c2:	3b 00       	.word	0x003b	; ????
     3c4:	5f 53       	subi	r21, 0x3F	; 63
     3c6:	61 74       	andi	r22, 0x41	; 65
     3c8:	20 73       	andi	r18, 0x30	; 48
     3ca:	68 6f       	ori	r22, 0xF8	; 248
     3cc:	72 74       	andi	r23, 0x42	; 66
     3ce:	20 5f       	subi	r18, 0xF0	; 240
     3d0:	46 72       	andi	r20, 0x26	; 38
     3d2:	61 63       	ori	r22, 0x31	; 49
     3d4:	74 3a       	cpi	r23, 0xA4	; 164
     3d6:	74 28       	or	r7, r4
     3d8:	30 2c       	mov	r3, r0
     3da:	32 33       	cpi	r19, 0x32	; 50
     3dc:	29 3d       	cpi	r18, 0xD9	; 217
     3de:	72 28       	or	r7, r2
     3e0:	30 2c       	mov	r3, r0
     3e2:	31 29       	or	r19, r1
     3e4:	3b 31       	cpi	r19, 0x1B	; 27
     3e6:	3b 30       	cpi	r19, 0x0B	; 11
     3e8:	3b 00       	.word	0x003b	; ????
     3ea:	5f 53       	subi	r21, 0x3F	; 63
     3ec:	61 74       	andi	r22, 0x41	; 65
     3ee:	20 5f       	subi	r18, 0xF0	; 240
     3f0:	46 72       	andi	r20, 0x26	; 38
     3f2:	61 63       	ori	r22, 0x31	; 49
     3f4:	74 3a       	cpi	r23, 0xA4	; 164
     3f6:	74 28       	or	r7, r4
     3f8:	30 2c       	mov	r3, r0
     3fa:	32 34       	cpi	r19, 0x42	; 66
     3fc:	29 3d       	cpi	r18, 0xD9	; 217
     3fe:	72 28       	or	r7, r2
     400:	30 2c       	mov	r3, r0
     402:	31 29       	or	r19, r1
     404:	3b 32       	cpi	r19, 0x2B	; 43
     406:	3b 30       	cpi	r19, 0x0B	; 11
     408:	3b 00       	.word	0x003b	; ????
     40a:	5f 53       	subi	r21, 0x3F	; 63
     40c:	61 74       	andi	r22, 0x41	; 65
     40e:	20 6c       	ori	r18, 0xC0	; 192
     410:	6f 6e       	ori	r22, 0xEF	; 239
     412:	67 20       	and	r6, r7
     414:	5f 46       	sbci	r21, 0x6F	; 111
     416:	72 61       	ori	r23, 0x12	; 18
     418:	63 74       	andi	r22, 0x43	; 67
     41a:	3a 74       	andi	r19, 0x4A	; 74
     41c:	28 30       	cpi	r18, 0x08	; 8
     41e:	2c 32       	cpi	r18, 0x2C	; 44
     420:	35 29       	or	r19, r5
     422:	3d 72       	andi	r19, 0x2D	; 45
     424:	28 30       	cpi	r18, 0x08	; 8
     426:	2c 31       	cpi	r18, 0x1C	; 28
     428:	29 3b       	cpi	r18, 0xB9	; 185
     42a:	34 3b       	cpi	r19, 0xB4	; 180
     42c:	30 3b       	cpi	r19, 0xB0	; 176
     42e:	00 5f       	subi	r16, 0xF0	; 240
     430:	53 61       	ori	r21, 0x13	; 19
     432:	74 20       	and	r7, r4
     434:	6c 6f       	ori	r22, 0xFC	; 252
     436:	6e 67       	ori	r22, 0x7E	; 126
     438:	20 6c       	ori	r18, 0xC0	; 192
     43a:	6f 6e       	ori	r22, 0xEF	; 239
     43c:	67 20       	and	r6, r7
     43e:	5f 46       	sbci	r21, 0x6F	; 111
     440:	72 61       	ori	r23, 0x12	; 18
     442:	63 74       	andi	r22, 0x43	; 67
     444:	3a 74       	andi	r19, 0x4A	; 74
     446:	28 30       	cpi	r18, 0x08	; 8
     448:	2c 32       	cpi	r18, 0x2C	; 44
     44a:	36 29       	or	r19, r6
     44c:	3d 72       	andi	r19, 0x2D	; 45
     44e:	28 30       	cpi	r18, 0x08	; 8
     450:	2c 31       	cpi	r18, 0x1C	; 28
     452:	29 3b       	cpi	r18, 0xB9	; 185
     454:	38 3b       	cpi	r19, 0xB8	; 184
     456:	30 3b       	cpi	r19, 0xB0	; 176
     458:	00 5f       	subi	r16, 0xF0	; 240
     45a:	53 61       	ori	r21, 0x13	; 19
     45c:	74 20       	and	r7, r4
     45e:	75 6e       	ori	r23, 0xE5	; 229
     460:	73 69       	ori	r23, 0x93	; 147
     462:	67 6e       	ori	r22, 0xE7	; 231
     464:	65 64       	ori	r22, 0x45	; 69
     466:	20 73       	andi	r18, 0x30	; 48
     468:	68 6f       	ori	r22, 0xF8	; 248
     46a:	72 74       	andi	r23, 0x42	; 66
     46c:	20 5f       	subi	r18, 0xF0	; 240
     46e:	46 72       	andi	r20, 0x26	; 38
     470:	61 63       	ori	r22, 0x31	; 49
     472:	74 3a       	cpi	r23, 0xA4	; 164
     474:	74 28       	or	r7, r4
     476:	30 2c       	mov	r3, r0
     478:	32 37       	cpi	r19, 0x72	; 114
     47a:	29 3d       	cpi	r18, 0xD9	; 217
     47c:	72 28       	or	r7, r2
     47e:	30 2c       	mov	r3, r0
     480:	31 29       	or	r19, r1
     482:	3b 31       	cpi	r19, 0x1B	; 27
     484:	3b 30       	cpi	r19, 0x0B	; 11
     486:	3b 00       	.word	0x003b	; ????
     488:	5f 53       	subi	r21, 0x3F	; 63
     48a:	61 74       	andi	r22, 0x41	; 65
     48c:	20 75       	andi	r18, 0x50	; 80
     48e:	6e 73       	andi	r22, 0x3E	; 62
     490:	69 67       	ori	r22, 0x79	; 121
     492:	6e 65       	ori	r22, 0x5E	; 94
     494:	64 20       	and	r6, r4
     496:	5f 46       	sbci	r21, 0x6F	; 111
     498:	72 61       	ori	r23, 0x12	; 18
     49a:	63 74       	andi	r22, 0x43	; 67
     49c:	3a 74       	andi	r19, 0x4A	; 74
     49e:	28 30       	cpi	r18, 0x08	; 8
     4a0:	2c 32       	cpi	r18, 0x2C	; 44
     4a2:	38 29       	or	r19, r8
     4a4:	3d 72       	andi	r19, 0x2D	; 45
     4a6:	28 30       	cpi	r18, 0x08	; 8
     4a8:	2c 31       	cpi	r18, 0x1C	; 28
     4aa:	29 3b       	cpi	r18, 0xB9	; 185
     4ac:	32 3b       	cpi	r19, 0xB2	; 178
     4ae:	30 3b       	cpi	r19, 0xB0	; 176
     4b0:	00 5f       	subi	r16, 0xF0	; 240
     4b2:	53 61       	ori	r21, 0x13	; 19
     4b4:	74 20       	and	r7, r4
     4b6:	75 6e       	ori	r23, 0xE5	; 229
     4b8:	73 69       	ori	r23, 0x93	; 147
     4ba:	67 6e       	ori	r22, 0xE7	; 231
     4bc:	65 64       	ori	r22, 0x45	; 69
     4be:	20 6c       	ori	r18, 0xC0	; 192
     4c0:	6f 6e       	ori	r22, 0xEF	; 239
     4c2:	67 20       	and	r6, r7
     4c4:	5f 46       	sbci	r21, 0x6F	; 111
     4c6:	72 61       	ori	r23, 0x12	; 18
     4c8:	63 74       	andi	r22, 0x43	; 67
     4ca:	3a 74       	andi	r19, 0x4A	; 74
     4cc:	28 30       	cpi	r18, 0x08	; 8
     4ce:	2c 32       	cpi	r18, 0x2C	; 44
     4d0:	39 29       	or	r19, r9
     4d2:	3d 72       	andi	r19, 0x2D	; 45
     4d4:	28 30       	cpi	r18, 0x08	; 8
     4d6:	2c 31       	cpi	r18, 0x1C	; 28
     4d8:	29 3b       	cpi	r18, 0xB9	; 185
     4da:	34 3b       	cpi	r19, 0xB4	; 180
     4dc:	30 3b       	cpi	r19, 0xB0	; 176
     4de:	00 5f       	subi	r16, 0xF0	; 240
     4e0:	53 61       	ori	r21, 0x13	; 19
     4e2:	74 20       	and	r7, r4
     4e4:	75 6e       	ori	r23, 0xE5	; 229
     4e6:	73 69       	ori	r23, 0x93	; 147
     4e8:	67 6e       	ori	r22, 0xE7	; 231
     4ea:	65 64       	ori	r22, 0x45	; 69
     4ec:	20 6c       	ori	r18, 0xC0	; 192
     4ee:	6f 6e       	ori	r22, 0xEF	; 239
     4f0:	67 20       	and	r6, r7
     4f2:	6c 6f       	ori	r22, 0xFC	; 252
     4f4:	6e 67       	ori	r22, 0x7E	; 126
     4f6:	20 5f       	subi	r18, 0xF0	; 240
     4f8:	46 72       	andi	r20, 0x26	; 38
     4fa:	61 63       	ori	r22, 0x31	; 49
     4fc:	74 3a       	cpi	r23, 0xA4	; 164
     4fe:	74 28       	or	r7, r4
     500:	30 2c       	mov	r3, r0
     502:	33 30       	cpi	r19, 0x03	; 3
     504:	29 3d       	cpi	r18, 0xD9	; 217
     506:	72 28       	or	r7, r2
     508:	30 2c       	mov	r3, r0
     50a:	31 29       	or	r19, r1
     50c:	3b 38       	cpi	r19, 0x8B	; 139
     50e:	3b 30       	cpi	r19, 0x0B	; 11
     510:	3b 00       	.word	0x003b	; ????
     512:	73 68       	ori	r23, 0x83	; 131
     514:	6f 72       	andi	r22, 0x2F	; 47
     516:	74 20       	and	r7, r4
     518:	5f 41       	sbci	r21, 0x1F	; 31
     51a:	63 63       	ori	r22, 0x33	; 51
     51c:	75 6d       	ori	r23, 0xD5	; 213
     51e:	3a 74       	andi	r19, 0x4A	; 74
     520:	28 30       	cpi	r18, 0x08	; 8
     522:	2c 33       	cpi	r18, 0x3C	; 60
     524:	31 29       	or	r19, r1
     526:	3d 72       	andi	r19, 0x2D	; 45
     528:	28 30       	cpi	r18, 0x08	; 8
     52a:	2c 31       	cpi	r18, 0x1C	; 28
     52c:	29 3b       	cpi	r18, 0xB9	; 185
     52e:	32 3b       	cpi	r19, 0xB2	; 178
     530:	30 3b       	cpi	r19, 0xB0	; 176
     532:	00 5f       	subi	r16, 0xF0	; 240
     534:	41 63       	ori	r20, 0x31	; 49
     536:	63 75       	andi	r22, 0x53	; 83
     538:	6d 3a       	cpi	r22, 0xAD	; 173
     53a:	74 28       	or	r7, r4
     53c:	30 2c       	mov	r3, r0
     53e:	33 32       	cpi	r19, 0x23	; 35
     540:	29 3d       	cpi	r18, 0xD9	; 217
     542:	72 28       	or	r7, r2
     544:	30 2c       	mov	r3, r0
     546:	31 29       	or	r19, r1
     548:	3b 34       	cpi	r19, 0x4B	; 75
     54a:	3b 30       	cpi	r19, 0x0B	; 11
     54c:	3b 00       	.word	0x003b	; ????
     54e:	6c 6f       	ori	r22, 0xFC	; 252
     550:	6e 67       	ori	r22, 0x7E	; 126
     552:	20 5f       	subi	r18, 0xF0	; 240
     554:	41 63       	ori	r20, 0x31	; 49
     556:	63 75       	andi	r22, 0x53	; 83
     558:	6d 3a       	cpi	r22, 0xAD	; 173
     55a:	74 28       	or	r7, r4
     55c:	30 2c       	mov	r3, r0
     55e:	33 33       	cpi	r19, 0x33	; 51
     560:	29 3d       	cpi	r18, 0xD9	; 217
     562:	72 28       	or	r7, r2
     564:	30 2c       	mov	r3, r0
     566:	31 29       	or	r19, r1
     568:	3b 38       	cpi	r19, 0x8B	; 139
     56a:	3b 30       	cpi	r19, 0x0B	; 11
     56c:	3b 00       	.word	0x003b	; ????
     56e:	6c 6f       	ori	r22, 0xFC	; 252
     570:	6e 67       	ori	r22, 0x7E	; 126
     572:	20 6c       	ori	r18, 0xC0	; 192
     574:	6f 6e       	ori	r22, 0xEF	; 239
     576:	67 20       	and	r6, r7
     578:	5f 41       	sbci	r21, 0x1F	; 31
     57a:	63 63       	ori	r22, 0x33	; 51
     57c:	75 6d       	ori	r23, 0xD5	; 213
     57e:	3a 74       	andi	r19, 0x4A	; 74
     580:	28 30       	cpi	r18, 0x08	; 8
     582:	2c 33       	cpi	r18, 0x3C	; 60
     584:	34 29       	or	r19, r4
     586:	3d 72       	andi	r19, 0x2D	; 45
     588:	28 30       	cpi	r18, 0x08	; 8
     58a:	2c 31       	cpi	r18, 0x1C	; 28
     58c:	29 3b       	cpi	r18, 0xB9	; 185
     58e:	38 3b       	cpi	r19, 0xB8	; 184
     590:	30 3b       	cpi	r19, 0xB0	; 176
     592:	00 75       	andi	r16, 0x50	; 80
     594:	6e 73       	andi	r22, 0x3E	; 62
     596:	69 67       	ori	r22, 0x79	; 121
     598:	6e 65       	ori	r22, 0x5E	; 94
     59a:	64 20       	and	r6, r4
     59c:	73 68       	ori	r23, 0x83	; 131
     59e:	6f 72       	andi	r22, 0x2F	; 47
     5a0:	74 20       	and	r7, r4
     5a2:	5f 41       	sbci	r21, 0x1F	; 31
     5a4:	63 63       	ori	r22, 0x33	; 51
     5a6:	75 6d       	ori	r23, 0xD5	; 213
     5a8:	3a 74       	andi	r19, 0x4A	; 74
     5aa:	28 30       	cpi	r18, 0x08	; 8
     5ac:	2c 33       	cpi	r18, 0x3C	; 60
     5ae:	35 29       	or	r19, r5
     5b0:	3d 72       	andi	r19, 0x2D	; 45
     5b2:	28 30       	cpi	r18, 0x08	; 8
     5b4:	2c 31       	cpi	r18, 0x1C	; 28
     5b6:	29 3b       	cpi	r18, 0xB9	; 185
     5b8:	32 3b       	cpi	r19, 0xB2	; 178
     5ba:	30 3b       	cpi	r19, 0xB0	; 176
     5bc:	00 75       	andi	r16, 0x50	; 80
     5be:	6e 73       	andi	r22, 0x3E	; 62
     5c0:	69 67       	ori	r22, 0x79	; 121
     5c2:	6e 65       	ori	r22, 0x5E	; 94
     5c4:	64 20       	and	r6, r4
     5c6:	5f 41       	sbci	r21, 0x1F	; 31
     5c8:	63 63       	ori	r22, 0x33	; 51
     5ca:	75 6d       	ori	r23, 0xD5	; 213
     5cc:	3a 74       	andi	r19, 0x4A	; 74
     5ce:	28 30       	cpi	r18, 0x08	; 8
     5d0:	2c 33       	cpi	r18, 0x3C	; 60
     5d2:	36 29       	or	r19, r6
     5d4:	3d 72       	andi	r19, 0x2D	; 45
     5d6:	28 30       	cpi	r18, 0x08	; 8
     5d8:	2c 31       	cpi	r18, 0x1C	; 28
     5da:	29 3b       	cpi	r18, 0xB9	; 185
     5dc:	34 3b       	cpi	r19, 0xB4	; 180
     5de:	30 3b       	cpi	r19, 0xB0	; 176
     5e0:	00 75       	andi	r16, 0x50	; 80
     5e2:	6e 73       	andi	r22, 0x3E	; 62
     5e4:	69 67       	ori	r22, 0x79	; 121
     5e6:	6e 65       	ori	r22, 0x5E	; 94
     5e8:	64 20       	and	r6, r4
     5ea:	6c 6f       	ori	r22, 0xFC	; 252
     5ec:	6e 67       	ori	r22, 0x7E	; 126
     5ee:	20 5f       	subi	r18, 0xF0	; 240
     5f0:	41 63       	ori	r20, 0x31	; 49
     5f2:	63 75       	andi	r22, 0x53	; 83
     5f4:	6d 3a       	cpi	r22, 0xAD	; 173
     5f6:	74 28       	or	r7, r4
     5f8:	30 2c       	mov	r3, r0
     5fa:	33 37       	cpi	r19, 0x73	; 115
     5fc:	29 3d       	cpi	r18, 0xD9	; 217
     5fe:	72 28       	or	r7, r2
     600:	30 2c       	mov	r3, r0
     602:	31 29       	or	r19, r1
     604:	3b 38       	cpi	r19, 0x8B	; 139
     606:	3b 30       	cpi	r19, 0x0B	; 11
     608:	3b 00       	.word	0x003b	; ????
     60a:	75 6e       	ori	r23, 0xE5	; 229
     60c:	73 69       	ori	r23, 0x93	; 147
     60e:	67 6e       	ori	r22, 0xE7	; 231
     610:	65 64       	ori	r22, 0x45	; 69
     612:	20 6c       	ori	r18, 0xC0	; 192
     614:	6f 6e       	ori	r22, 0xEF	; 239
     616:	67 20       	and	r6, r7
     618:	6c 6f       	ori	r22, 0xFC	; 252
     61a:	6e 67       	ori	r22, 0x7E	; 126
     61c:	20 5f       	subi	r18, 0xF0	; 240
     61e:	41 63       	ori	r20, 0x31	; 49
     620:	63 75       	andi	r22, 0x53	; 83
     622:	6d 3a       	cpi	r22, 0xAD	; 173
     624:	74 28       	or	r7, r4
     626:	30 2c       	mov	r3, r0
     628:	33 38       	cpi	r19, 0x83	; 131
     62a:	29 3d       	cpi	r18, 0xD9	; 217
     62c:	72 28       	or	r7, r2
     62e:	30 2c       	mov	r3, r0
     630:	31 29       	or	r19, r1
     632:	3b 38       	cpi	r19, 0x8B	; 139
     634:	3b 30       	cpi	r19, 0x0B	; 11
     636:	3b 00       	.word	0x003b	; ????
     638:	5f 53       	subi	r21, 0x3F	; 63
     63a:	61 74       	andi	r22, 0x41	; 65
     63c:	20 73       	andi	r18, 0x30	; 48
     63e:	68 6f       	ori	r22, 0xF8	; 248
     640:	72 74       	andi	r23, 0x42	; 66
     642:	20 5f       	subi	r18, 0xF0	; 240
     644:	41 63       	ori	r20, 0x31	; 49
     646:	63 75       	andi	r22, 0x53	; 83
     648:	6d 3a       	cpi	r22, 0xAD	; 173
     64a:	74 28       	or	r7, r4
     64c:	30 2c       	mov	r3, r0
     64e:	33 39       	cpi	r19, 0x93	; 147
     650:	29 3d       	cpi	r18, 0xD9	; 217
     652:	72 28       	or	r7, r2
     654:	30 2c       	mov	r3, r0
     656:	31 29       	or	r19, r1
     658:	3b 32       	cpi	r19, 0x2B	; 43
     65a:	3b 30       	cpi	r19, 0x0B	; 11
     65c:	3b 00       	.word	0x003b	; ????
     65e:	5f 53       	subi	r21, 0x3F	; 63
     660:	61 74       	andi	r22, 0x41	; 65
     662:	20 5f       	subi	r18, 0xF0	; 240
     664:	41 63       	ori	r20, 0x31	; 49
     666:	63 75       	andi	r22, 0x53	; 83
     668:	6d 3a       	cpi	r22, 0xAD	; 173
     66a:	74 28       	or	r7, r4
     66c:	30 2c       	mov	r3, r0
     66e:	34 30       	cpi	r19, 0x04	; 4
     670:	29 3d       	cpi	r18, 0xD9	; 217
     672:	72 28       	or	r7, r2
     674:	30 2c       	mov	r3, r0
     676:	31 29       	or	r19, r1
     678:	3b 34       	cpi	r19, 0x4B	; 75
     67a:	3b 30       	cpi	r19, 0x0B	; 11
     67c:	3b 00       	.word	0x003b	; ????
     67e:	5f 53       	subi	r21, 0x3F	; 63
     680:	61 74       	andi	r22, 0x41	; 65
     682:	20 6c       	ori	r18, 0xC0	; 192
     684:	6f 6e       	ori	r22, 0xEF	; 239
     686:	67 20       	and	r6, r7
     688:	5f 41       	sbci	r21, 0x1F	; 31
     68a:	63 63       	ori	r22, 0x33	; 51
     68c:	75 6d       	ori	r23, 0xD5	; 213
     68e:	3a 74       	andi	r19, 0x4A	; 74
     690:	28 30       	cpi	r18, 0x08	; 8
     692:	2c 34       	cpi	r18, 0x4C	; 76
     694:	31 29       	or	r19, r1
     696:	3d 72       	andi	r19, 0x2D	; 45
     698:	28 30       	cpi	r18, 0x08	; 8
     69a:	2c 31       	cpi	r18, 0x1C	; 28
     69c:	29 3b       	cpi	r18, 0xB9	; 185
     69e:	38 3b       	cpi	r19, 0xB8	; 184
     6a0:	30 3b       	cpi	r19, 0xB0	; 176
     6a2:	00 5f       	subi	r16, 0xF0	; 240
     6a4:	53 61       	ori	r21, 0x13	; 19
     6a6:	74 20       	and	r7, r4
     6a8:	6c 6f       	ori	r22, 0xFC	; 252
     6aa:	6e 67       	ori	r22, 0x7E	; 126
     6ac:	20 6c       	ori	r18, 0xC0	; 192
     6ae:	6f 6e       	ori	r22, 0xEF	; 239
     6b0:	67 20       	and	r6, r7
     6b2:	5f 41       	sbci	r21, 0x1F	; 31
     6b4:	63 63       	ori	r22, 0x33	; 51
     6b6:	75 6d       	ori	r23, 0xD5	; 213
     6b8:	3a 74       	andi	r19, 0x4A	; 74
     6ba:	28 30       	cpi	r18, 0x08	; 8
     6bc:	2c 34       	cpi	r18, 0x4C	; 76
     6be:	32 29       	or	r19, r2
     6c0:	3d 72       	andi	r19, 0x2D	; 45
     6c2:	28 30       	cpi	r18, 0x08	; 8
     6c4:	2c 31       	cpi	r18, 0x1C	; 28
     6c6:	29 3b       	cpi	r18, 0xB9	; 185
     6c8:	38 3b       	cpi	r19, 0xB8	; 184
     6ca:	30 3b       	cpi	r19, 0xB0	; 176
     6cc:	00 5f       	subi	r16, 0xF0	; 240
     6ce:	53 61       	ori	r21, 0x13	; 19
     6d0:	74 20       	and	r7, r4
     6d2:	75 6e       	ori	r23, 0xE5	; 229
     6d4:	73 69       	ori	r23, 0x93	; 147
     6d6:	67 6e       	ori	r22, 0xE7	; 231
     6d8:	65 64       	ori	r22, 0x45	; 69
     6da:	20 73       	andi	r18, 0x30	; 48
     6dc:	68 6f       	ori	r22, 0xF8	; 248
     6de:	72 74       	andi	r23, 0x42	; 66
     6e0:	20 5f       	subi	r18, 0xF0	; 240
     6e2:	41 63       	ori	r20, 0x31	; 49
     6e4:	63 75       	andi	r22, 0x53	; 83
     6e6:	6d 3a       	cpi	r22, 0xAD	; 173
     6e8:	74 28       	or	r7, r4
     6ea:	30 2c       	mov	r3, r0
     6ec:	34 33       	cpi	r19, 0x34	; 52
     6ee:	29 3d       	cpi	r18, 0xD9	; 217
     6f0:	72 28       	or	r7, r2
     6f2:	30 2c       	mov	r3, r0
     6f4:	31 29       	or	r19, r1
     6f6:	3b 32       	cpi	r19, 0x2B	; 43
     6f8:	3b 30       	cpi	r19, 0x0B	; 11
     6fa:	3b 00       	.word	0x003b	; ????
     6fc:	5f 53       	subi	r21, 0x3F	; 63
     6fe:	61 74       	andi	r22, 0x41	; 65
     700:	20 75       	andi	r18, 0x50	; 80
     702:	6e 73       	andi	r22, 0x3E	; 62
     704:	69 67       	ori	r22, 0x79	; 121
     706:	6e 65       	ori	r22, 0x5E	; 94
     708:	64 20       	and	r6, r4
     70a:	5f 41       	sbci	r21, 0x1F	; 31
     70c:	63 63       	ori	r22, 0x33	; 51
     70e:	75 6d       	ori	r23, 0xD5	; 213
     710:	3a 74       	andi	r19, 0x4A	; 74
     712:	28 30       	cpi	r18, 0x08	; 8
     714:	2c 34       	cpi	r18, 0x4C	; 76
     716:	34 29       	or	r19, r4
     718:	3d 72       	andi	r19, 0x2D	; 45
     71a:	28 30       	cpi	r18, 0x08	; 8
     71c:	2c 31       	cpi	r18, 0x1C	; 28
     71e:	29 3b       	cpi	r18, 0xB9	; 185
     720:	34 3b       	cpi	r19, 0xB4	; 180
     722:	30 3b       	cpi	r19, 0xB0	; 176
     724:	00 5f       	subi	r16, 0xF0	; 240
     726:	53 61       	ori	r21, 0x13	; 19
     728:	74 20       	and	r7, r4
     72a:	75 6e       	ori	r23, 0xE5	; 229
     72c:	73 69       	ori	r23, 0x93	; 147
     72e:	67 6e       	ori	r22, 0xE7	; 231
     730:	65 64       	ori	r22, 0x45	; 69
     732:	20 6c       	ori	r18, 0xC0	; 192
     734:	6f 6e       	ori	r22, 0xEF	; 239
     736:	67 20       	and	r6, r7
     738:	5f 41       	sbci	r21, 0x1F	; 31
     73a:	63 63       	ori	r22, 0x33	; 51
     73c:	75 6d       	ori	r23, 0xD5	; 213
     73e:	3a 74       	andi	r19, 0x4A	; 74
     740:	28 30       	cpi	r18, 0x08	; 8
     742:	2c 34       	cpi	r18, 0x4C	; 76
     744:	35 29       	or	r19, r5
     746:	3d 72       	andi	r19, 0x2D	; 45
     748:	28 30       	cpi	r18, 0x08	; 8
     74a:	2c 31       	cpi	r18, 0x1C	; 28
     74c:	29 3b       	cpi	r18, 0xB9	; 185
     74e:	38 3b       	cpi	r19, 0xB8	; 184
     750:	30 3b       	cpi	r19, 0xB0	; 176
     752:	00 5f       	subi	r16, 0xF0	; 240
     754:	53 61       	ori	r21, 0x13	; 19
     756:	74 20       	and	r7, r4
     758:	75 6e       	ori	r23, 0xE5	; 229
     75a:	73 69       	ori	r23, 0x93	; 147
     75c:	67 6e       	ori	r22, 0xE7	; 231
     75e:	65 64       	ori	r22, 0x45	; 69
     760:	20 6c       	ori	r18, 0xC0	; 192
     762:	6f 6e       	ori	r22, 0xEF	; 239
     764:	67 20       	and	r6, r7
     766:	6c 6f       	ori	r22, 0xFC	; 252
     768:	6e 67       	ori	r22, 0x7E	; 126
     76a:	20 5f       	subi	r18, 0xF0	; 240
     76c:	41 63       	ori	r20, 0x31	; 49
     76e:	63 75       	andi	r22, 0x53	; 83
     770:	6d 3a       	cpi	r22, 0xAD	; 173
     772:	74 28       	or	r7, r4
     774:	30 2c       	mov	r3, r0
     776:	34 36       	cpi	r19, 0x64	; 100
     778:	29 3d       	cpi	r18, 0xD9	; 217
     77a:	72 28       	or	r7, r2
     77c:	30 2c       	mov	r3, r0
     77e:	31 29       	or	r19, r1
     780:	3b 38       	cpi	r19, 0x8B	; 139
     782:	3b 30       	cpi	r19, 0x0B	; 11
     784:	3b 00       	.word	0x003b	; ????
     786:	76 6f       	ori	r23, 0xF6	; 246
     788:	69 64       	ori	r22, 0x49	; 73
     78a:	3a 74       	andi	r19, 0x4A	; 74
     78c:	28 30       	cpi	r18, 0x08	; 8
     78e:	2c 34       	cpi	r18, 0x4C	; 76
     790:	37 29       	or	r19, r7
     792:	3d 28       	or	r3, r13
     794:	30 2c       	mov	r3, r0
     796:	34 37       	cpi	r19, 0x74	; 116
     798:	29 00       	.word	0x0029	; ????
     79a:	2f 75       	andi	r18, 0x5F	; 95
     79c:	73 72       	andi	r23, 0x23	; 35
     79e:	2f 6c       	ori	r18, 0xCF	; 207
     7a0:	69 62       	ori	r22, 0x29	; 41
     7a2:	2f 61       	ori	r18, 0x1F	; 31
     7a4:	76 72       	andi	r23, 0x26	; 38
     7a6:	2f 69       	ori	r18, 0x9F	; 159
     7a8:	6e 63       	ori	r22, 0x3E	; 62
     7aa:	6c 75       	andi	r22, 0x5C	; 92
     7ac:	64 65       	ori	r22, 0x54	; 84
     7ae:	2f 61       	ori	r18, 0x1F	; 31
     7b0:	76 72       	andi	r23, 0x26	; 38
     7b2:	2f 69       	ori	r18, 0x9F	; 159
     7b4:	6f 2e       	mov	r6, r31
     7b6:	68 00       	.word	0x0068	; ????
     7b8:	2f 75       	andi	r18, 0x5F	; 95
     7ba:	73 72       	andi	r23, 0x23	; 35
     7bc:	2f 6c       	ori	r18, 0xCF	; 207
     7be:	69 62       	ori	r22, 0x29	; 41
     7c0:	2f 61       	ori	r18, 0x1F	; 31
     7c2:	76 72       	andi	r23, 0x26	; 38
     7c4:	2f 69       	ori	r18, 0x9F	; 159
     7c6:	6e 63       	ori	r22, 0x3E	; 62
     7c8:	6c 75       	andi	r22, 0x5C	; 92
     7ca:	64 65       	ori	r22, 0x54	; 84
     7cc:	2f 61       	ori	r18, 0x1F	; 31
     7ce:	76 72       	andi	r23, 0x26	; 38
     7d0:	2f 73       	andi	r18, 0x3F	; 63
     7d2:	66 72       	andi	r22, 0x26	; 38
     7d4:	5f 64       	ori	r21, 0x4F	; 79
     7d6:	65 66       	ori	r22, 0x65	; 101
     7d8:	73 2e       	mov	r7, r19
     7da:	68 00       	.word	0x0068	; ????
     7dc:	2f 75       	andi	r18, 0x5F	; 95
     7de:	73 72       	andi	r23, 0x23	; 35
     7e0:	2f 6c       	ori	r18, 0xCF	; 207
     7e2:	69 62       	ori	r22, 0x29	; 41
     7e4:	2f 61       	ori	r18, 0x1F	; 31
     7e6:	76 72       	andi	r23, 0x26	; 38
     7e8:	2f 69       	ori	r18, 0x9F	; 159
     7ea:	6e 63       	ori	r22, 0x3E	; 62
     7ec:	6c 75       	andi	r22, 0x5C	; 92
     7ee:	64 65       	ori	r22, 0x54	; 84
     7f0:	2f 69       	ori	r18, 0x9F	; 159
     7f2:	6e 74       	andi	r22, 0x4E	; 78
     7f4:	74 79       	andi	r23, 0x94	; 148
     7f6:	70 65       	ori	r23, 0x50	; 80
     7f8:	73 2e       	mov	r7, r19
     7fa:	68 00       	.word	0x0068	; ????
     7fc:	2f 75       	andi	r18, 0x5F	; 95
     7fe:	73 72       	andi	r23, 0x23	; 35
     800:	2f 6c       	ori	r18, 0xCF	; 207
     802:	69 62       	ori	r22, 0x29	; 41
     804:	2f 67       	ori	r18, 0x7F	; 127
     806:	63 63       	ori	r22, 0x33	; 51
     808:	2f 61       	ori	r18, 0x1F	; 31
     80a:	76 72       	andi	r23, 0x26	; 38
     80c:	2f 34       	cpi	r18, 0x4F	; 79
     80e:	2e 39       	cpi	r18, 0x9E	; 158
     810:	2e 32       	cpi	r18, 0x2E	; 46
     812:	2f 69       	ori	r18, 0x9F	; 159
     814:	6e 63       	ori	r22, 0x3E	; 62
     816:	6c 75       	andi	r22, 0x5C	; 92
     818:	64 65       	ori	r22, 0x54	; 84
     81a:	2f 73       	andi	r18, 0x3F	; 63
     81c:	74 64       	ori	r23, 0x44	; 68
     81e:	69 6e       	ori	r22, 0xE9	; 233
     820:	74 2e       	mov	r7, r20
     822:	68 00       	.word	0x0068	; ????
     824:	2f 75       	andi	r18, 0x5F	; 95
     826:	73 72       	andi	r23, 0x23	; 35
     828:	2f 6c       	ori	r18, 0xCF	; 207
     82a:	69 62       	ori	r22, 0x29	; 41
     82c:	2f 61       	ori	r18, 0x1F	; 31
     82e:	76 72       	andi	r23, 0x26	; 38
     830:	2f 69       	ori	r18, 0x9F	; 159
     832:	6e 63       	ori	r22, 0x3E	; 62
     834:	6c 75       	andi	r22, 0x5C	; 92
     836:	64 65       	ori	r22, 0x54	; 84
     838:	2f 73       	andi	r18, 0x3F	; 63
     83a:	74 64       	ori	r23, 0x44	; 68
     83c:	69 6e       	ori	r22, 0xE9	; 233
     83e:	74 2e       	mov	r7, r20
     840:	68 00       	.word	0x0068	; ????
     842:	69 6e       	ori	r22, 0xE9	; 233
     844:	74 38       	cpi	r23, 0x84	; 132
     846:	5f 74       	andi	r21, 0x4F	; 79
     848:	3a 74       	andi	r19, 0x4A	; 74
     84a:	28 35       	cpi	r18, 0x58	; 88
     84c:	2c 31       	cpi	r18, 0x1C	; 28
     84e:	29 3d       	cpi	r18, 0xD9	; 217
     850:	28 30       	cpi	r18, 0x08	; 8
     852:	2c 31       	cpi	r18, 0x1C	; 28
     854:	30 29       	or	r19, r0
     856:	00 75       	andi	r16, 0x50	; 80
     858:	69 6e       	ori	r22, 0xE9	; 233
     85a:	74 38       	cpi	r23, 0x84	; 132
     85c:	5f 74       	andi	r21, 0x4F	; 79
     85e:	3a 74       	andi	r19, 0x4A	; 74
     860:	28 35       	cpi	r18, 0x58	; 88
     862:	2c 32       	cpi	r18, 0x2C	; 44
     864:	29 3d       	cpi	r18, 0xD9	; 217
     866:	28 30       	cpi	r18, 0x08	; 8
     868:	2c 31       	cpi	r18, 0x1C	; 28
     86a:	31 29       	or	r19, r1
     86c:	00 69       	ori	r16, 0x90	; 144
     86e:	6e 74       	andi	r22, 0x4E	; 78
     870:	31 36       	cpi	r19, 0x61	; 97
     872:	5f 74       	andi	r21, 0x4F	; 79
     874:	3a 74       	andi	r19, 0x4A	; 74
     876:	28 35       	cpi	r18, 0x58	; 88
     878:	2c 33       	cpi	r18, 0x3C	; 60
     87a:	29 3d       	cpi	r18, 0xD9	; 217
     87c:	28 30       	cpi	r18, 0x08	; 8
     87e:	2c 31       	cpi	r18, 0x1C	; 28
     880:	29 00       	.word	0x0029	; ????
     882:	75 69       	ori	r23, 0x95	; 149
     884:	6e 74       	andi	r22, 0x4E	; 78
     886:	31 36       	cpi	r19, 0x61	; 97
     888:	5f 74       	andi	r21, 0x4F	; 79
     88a:	3a 74       	andi	r19, 0x4A	; 74
     88c:	28 35       	cpi	r18, 0x58	; 88
     88e:	2c 34       	cpi	r18, 0x4C	; 76
     890:	29 3d       	cpi	r18, 0xD9	; 217
     892:	28 30       	cpi	r18, 0x08	; 8
     894:	2c 34       	cpi	r18, 0x4C	; 76
     896:	29 00       	.word	0x0029	; ????
     898:	69 6e       	ori	r22, 0xE9	; 233
     89a:	74 33       	cpi	r23, 0x34	; 52
     89c:	32 5f       	subi	r19, 0xF2	; 242
     89e:	74 3a       	cpi	r23, 0xA4	; 164
     8a0:	74 28       	or	r7, r4
     8a2:	35 2c       	mov	r3, r5
     8a4:	35 29       	or	r19, r5
     8a6:	3d 28       	or	r3, r13
     8a8:	30 2c       	mov	r3, r0
     8aa:	33 29       	or	r19, r3
     8ac:	00 75       	andi	r16, 0x50	; 80
     8ae:	69 6e       	ori	r22, 0xE9	; 233
     8b0:	74 33       	cpi	r23, 0x34	; 52
     8b2:	32 5f       	subi	r19, 0xF2	; 242
     8b4:	74 3a       	cpi	r23, 0xA4	; 164
     8b6:	74 28       	or	r7, r4
     8b8:	35 2c       	mov	r3, r5
     8ba:	36 29       	or	r19, r6
     8bc:	3d 28       	or	r3, r13
     8be:	30 2c       	mov	r3, r0
     8c0:	35 29       	or	r19, r5
     8c2:	00 69       	ori	r16, 0x90	; 144
     8c4:	6e 74       	andi	r22, 0x4E	; 78
     8c6:	36 34       	cpi	r19, 0x46	; 70
     8c8:	5f 74       	andi	r21, 0x4F	; 79
     8ca:	3a 74       	andi	r19, 0x4A	; 74
     8cc:	28 35       	cpi	r18, 0x58	; 88
     8ce:	2c 37       	cpi	r18, 0x7C	; 124
     8d0:	29 3d       	cpi	r18, 0xD9	; 217
     8d2:	28 30       	cpi	r18, 0x08	; 8
     8d4:	2c 36       	cpi	r18, 0x6C	; 108
     8d6:	29 00       	.word	0x0029	; ????
     8d8:	75 69       	ori	r23, 0x95	; 149
     8da:	6e 74       	andi	r22, 0x4E	; 78
     8dc:	36 34       	cpi	r19, 0x46	; 70
     8de:	5f 74       	andi	r21, 0x4F	; 79
     8e0:	3a 74       	andi	r19, 0x4A	; 74
     8e2:	28 35       	cpi	r18, 0x58	; 88
     8e4:	2c 38       	cpi	r18, 0x8C	; 140
     8e6:	29 3d       	cpi	r18, 0xD9	; 217
     8e8:	28 30       	cpi	r18, 0x08	; 8
     8ea:	2c 37       	cpi	r18, 0x7C	; 124
     8ec:	29 00       	.word	0x0029	; ????
     8ee:	69 6e       	ori	r22, 0xE9	; 233
     8f0:	74 70       	andi	r23, 0x04	; 4
     8f2:	74 72       	andi	r23, 0x24	; 36
     8f4:	5f 74       	andi	r21, 0x4F	; 79
     8f6:	3a 74       	andi	r19, 0x4A	; 74
     8f8:	28 35       	cpi	r18, 0x58	; 88
     8fa:	2c 39       	cpi	r18, 0x9C	; 156
     8fc:	29 3d       	cpi	r18, 0xD9	; 217
     8fe:	28 35       	cpi	r18, 0x58	; 88
     900:	2c 33       	cpi	r18, 0x3C	; 60
     902:	29 00       	.word	0x0029	; ????
     904:	75 69       	ori	r23, 0x95	; 149
     906:	6e 74       	andi	r22, 0x4E	; 78
     908:	70 74       	andi	r23, 0x40	; 64
     90a:	72 5f       	subi	r23, 0xF2	; 242
     90c:	74 3a       	cpi	r23, 0xA4	; 164
     90e:	74 28       	or	r7, r4
     910:	35 2c       	mov	r3, r5
     912:	31 30       	cpi	r19, 0x01	; 1
     914:	29 3d       	cpi	r18, 0xD9	; 217
     916:	28 35       	cpi	r18, 0x58	; 88
     918:	2c 34       	cpi	r18, 0x4C	; 76
     91a:	29 00       	.word	0x0029	; ????
     91c:	69 6e       	ori	r22, 0xE9	; 233
     91e:	74 5f       	subi	r23, 0xF4	; 244
     920:	6c 65       	ori	r22, 0x5C	; 92
     922:	61 73       	andi	r22, 0x31	; 49
     924:	74 38       	cpi	r23, 0x84	; 132
     926:	5f 74       	andi	r21, 0x4F	; 79
     928:	3a 74       	andi	r19, 0x4A	; 74
     92a:	28 35       	cpi	r18, 0x58	; 88
     92c:	2c 31       	cpi	r18, 0x1C	; 28
     92e:	31 29       	or	r19, r1
     930:	3d 28       	or	r3, r13
     932:	35 2c       	mov	r3, r5
     934:	31 29       	or	r19, r1
     936:	00 75       	andi	r16, 0x50	; 80
     938:	69 6e       	ori	r22, 0xE9	; 233
     93a:	74 5f       	subi	r23, 0xF4	; 244
     93c:	6c 65       	ori	r22, 0x5C	; 92
     93e:	61 73       	andi	r22, 0x31	; 49
     940:	74 38       	cpi	r23, 0x84	; 132
     942:	5f 74       	andi	r21, 0x4F	; 79
     944:	3a 74       	andi	r19, 0x4A	; 74
     946:	28 35       	cpi	r18, 0x58	; 88
     948:	2c 31       	cpi	r18, 0x1C	; 28
     94a:	32 29       	or	r19, r2
     94c:	3d 28       	or	r3, r13
     94e:	35 2c       	mov	r3, r5
     950:	32 29       	or	r19, r2
     952:	00 69       	ori	r16, 0x90	; 144
     954:	6e 74       	andi	r22, 0x4E	; 78
     956:	5f 6c       	ori	r21, 0xCF	; 207
     958:	65 61       	ori	r22, 0x15	; 21
     95a:	73 74       	andi	r23, 0x43	; 67
     95c:	31 36       	cpi	r19, 0x61	; 97
     95e:	5f 74       	andi	r21, 0x4F	; 79
     960:	3a 74       	andi	r19, 0x4A	; 74
     962:	28 35       	cpi	r18, 0x58	; 88
     964:	2c 31       	cpi	r18, 0x1C	; 28
     966:	33 29       	or	r19, r3
     968:	3d 28       	or	r3, r13
     96a:	35 2c       	mov	r3, r5
     96c:	33 29       	or	r19, r3
     96e:	00 75       	andi	r16, 0x50	; 80
     970:	69 6e       	ori	r22, 0xE9	; 233
     972:	74 5f       	subi	r23, 0xF4	; 244
     974:	6c 65       	ori	r22, 0x5C	; 92
     976:	61 73       	andi	r22, 0x31	; 49
     978:	74 31       	cpi	r23, 0x14	; 20
     97a:	36 5f       	subi	r19, 0xF6	; 246
     97c:	74 3a       	cpi	r23, 0xA4	; 164
     97e:	74 28       	or	r7, r4
     980:	35 2c       	mov	r3, r5
     982:	31 34       	cpi	r19, 0x41	; 65
     984:	29 3d       	cpi	r18, 0xD9	; 217
     986:	28 35       	cpi	r18, 0x58	; 88
     988:	2c 34       	cpi	r18, 0x4C	; 76
     98a:	29 00       	.word	0x0029	; ????
     98c:	69 6e       	ori	r22, 0xE9	; 233
     98e:	74 5f       	subi	r23, 0xF4	; 244
     990:	6c 65       	ori	r22, 0x5C	; 92
     992:	61 73       	andi	r22, 0x31	; 49
     994:	74 33       	cpi	r23, 0x34	; 52
     996:	32 5f       	subi	r19, 0xF2	; 242
     998:	74 3a       	cpi	r23, 0xA4	; 164
     99a:	74 28       	or	r7, r4
     99c:	35 2c       	mov	r3, r5
     99e:	31 35       	cpi	r19, 0x51	; 81
     9a0:	29 3d       	cpi	r18, 0xD9	; 217
     9a2:	28 35       	cpi	r18, 0x58	; 88
     9a4:	2c 35       	cpi	r18, 0x5C	; 92
     9a6:	29 00       	.word	0x0029	; ????
     9a8:	75 69       	ori	r23, 0x95	; 149
     9aa:	6e 74       	andi	r22, 0x4E	; 78
     9ac:	5f 6c       	ori	r21, 0xCF	; 207
     9ae:	65 61       	ori	r22, 0x15	; 21
     9b0:	73 74       	andi	r23, 0x43	; 67
     9b2:	33 32       	cpi	r19, 0x23	; 35
     9b4:	5f 74       	andi	r21, 0x4F	; 79
     9b6:	3a 74       	andi	r19, 0x4A	; 74
     9b8:	28 35       	cpi	r18, 0x58	; 88
     9ba:	2c 31       	cpi	r18, 0x1C	; 28
     9bc:	36 29       	or	r19, r6
     9be:	3d 28       	or	r3, r13
     9c0:	35 2c       	mov	r3, r5
     9c2:	36 29       	or	r19, r6
     9c4:	00 69       	ori	r16, 0x90	; 144
     9c6:	6e 74       	andi	r22, 0x4E	; 78
     9c8:	5f 6c       	ori	r21, 0xCF	; 207
     9ca:	65 61       	ori	r22, 0x15	; 21
     9cc:	73 74       	andi	r23, 0x43	; 67
     9ce:	36 34       	cpi	r19, 0x46	; 70
     9d0:	5f 74       	andi	r21, 0x4F	; 79
     9d2:	3a 74       	andi	r19, 0x4A	; 74
     9d4:	28 35       	cpi	r18, 0x58	; 88
     9d6:	2c 31       	cpi	r18, 0x1C	; 28
     9d8:	37 29       	or	r19, r7
     9da:	3d 28       	or	r3, r13
     9dc:	35 2c       	mov	r3, r5
     9de:	37 29       	or	r19, r7
     9e0:	00 75       	andi	r16, 0x50	; 80
     9e2:	69 6e       	ori	r22, 0xE9	; 233
     9e4:	74 5f       	subi	r23, 0xF4	; 244
     9e6:	6c 65       	ori	r22, 0x5C	; 92
     9e8:	61 73       	andi	r22, 0x31	; 49
     9ea:	74 36       	cpi	r23, 0x64	; 100
     9ec:	34 5f       	subi	r19, 0xF4	; 244
     9ee:	74 3a       	cpi	r23, 0xA4	; 164
     9f0:	74 28       	or	r7, r4
     9f2:	35 2c       	mov	r3, r5
     9f4:	31 38       	cpi	r19, 0x81	; 129
     9f6:	29 3d       	cpi	r18, 0xD9	; 217
     9f8:	28 35       	cpi	r18, 0x58	; 88
     9fa:	2c 38       	cpi	r18, 0x8C	; 140
     9fc:	29 00       	.word	0x0029	; ????
     9fe:	69 6e       	ori	r22, 0xE9	; 233
     a00:	74 5f       	subi	r23, 0xF4	; 244
     a02:	66 61       	ori	r22, 0x16	; 22
     a04:	73 74       	andi	r23, 0x43	; 67
     a06:	38 5f       	subi	r19, 0xF8	; 248
     a08:	74 3a       	cpi	r23, 0xA4	; 164
     a0a:	74 28       	or	r7, r4
     a0c:	35 2c       	mov	r3, r5
     a0e:	31 39       	cpi	r19, 0x91	; 145
     a10:	29 3d       	cpi	r18, 0xD9	; 217
     a12:	28 35       	cpi	r18, 0x58	; 88
     a14:	2c 31       	cpi	r18, 0x1C	; 28
     a16:	29 00       	.word	0x0029	; ????
     a18:	75 69       	ori	r23, 0x95	; 149
     a1a:	6e 74       	andi	r22, 0x4E	; 78
     a1c:	5f 66       	ori	r21, 0x6F	; 111
     a1e:	61 73       	andi	r22, 0x31	; 49
     a20:	74 38       	cpi	r23, 0x84	; 132
     a22:	5f 74       	andi	r21, 0x4F	; 79
     a24:	3a 74       	andi	r19, 0x4A	; 74
     a26:	28 35       	cpi	r18, 0x58	; 88
     a28:	2c 32       	cpi	r18, 0x2C	; 44
     a2a:	30 29       	or	r19, r0
     a2c:	3d 28       	or	r3, r13
     a2e:	35 2c       	mov	r3, r5
     a30:	32 29       	or	r19, r2
     a32:	00 69       	ori	r16, 0x90	; 144
     a34:	6e 74       	andi	r22, 0x4E	; 78
     a36:	5f 66       	ori	r21, 0x6F	; 111
     a38:	61 73       	andi	r22, 0x31	; 49
     a3a:	74 31       	cpi	r23, 0x14	; 20
     a3c:	36 5f       	subi	r19, 0xF6	; 246
     a3e:	74 3a       	cpi	r23, 0xA4	; 164
     a40:	74 28       	or	r7, r4
     a42:	35 2c       	mov	r3, r5
     a44:	32 31       	cpi	r19, 0x12	; 18
     a46:	29 3d       	cpi	r18, 0xD9	; 217
     a48:	28 35       	cpi	r18, 0x58	; 88
     a4a:	2c 33       	cpi	r18, 0x3C	; 60
     a4c:	29 00       	.word	0x0029	; ????
     a4e:	75 69       	ori	r23, 0x95	; 149
     a50:	6e 74       	andi	r22, 0x4E	; 78
     a52:	5f 66       	ori	r21, 0x6F	; 111
     a54:	61 73       	andi	r22, 0x31	; 49
     a56:	74 31       	cpi	r23, 0x14	; 20
     a58:	36 5f       	subi	r19, 0xF6	; 246
     a5a:	74 3a       	cpi	r23, 0xA4	; 164
     a5c:	74 28       	or	r7, r4
     a5e:	35 2c       	mov	r3, r5
     a60:	32 32       	cpi	r19, 0x22	; 34
     a62:	29 3d       	cpi	r18, 0xD9	; 217
     a64:	28 35       	cpi	r18, 0x58	; 88
     a66:	2c 34       	cpi	r18, 0x4C	; 76
     a68:	29 00       	.word	0x0029	; ????
     a6a:	69 6e       	ori	r22, 0xE9	; 233
     a6c:	74 5f       	subi	r23, 0xF4	; 244
     a6e:	66 61       	ori	r22, 0x16	; 22
     a70:	73 74       	andi	r23, 0x43	; 67
     a72:	33 32       	cpi	r19, 0x23	; 35
     a74:	5f 74       	andi	r21, 0x4F	; 79
     a76:	3a 74       	andi	r19, 0x4A	; 74
     a78:	28 35       	cpi	r18, 0x58	; 88
     a7a:	2c 32       	cpi	r18, 0x2C	; 44
     a7c:	33 29       	or	r19, r3
     a7e:	3d 28       	or	r3, r13
     a80:	35 2c       	mov	r3, r5
     a82:	35 29       	or	r19, r5
     a84:	00 75       	andi	r16, 0x50	; 80
     a86:	69 6e       	ori	r22, 0xE9	; 233
     a88:	74 5f       	subi	r23, 0xF4	; 244
     a8a:	66 61       	ori	r22, 0x16	; 22
     a8c:	73 74       	andi	r23, 0x43	; 67
     a8e:	33 32       	cpi	r19, 0x23	; 35
     a90:	5f 74       	andi	r21, 0x4F	; 79
     a92:	3a 74       	andi	r19, 0x4A	; 74
     a94:	28 35       	cpi	r18, 0x58	; 88
     a96:	2c 32       	cpi	r18, 0x2C	; 44
     a98:	34 29       	or	r19, r4
     a9a:	3d 28       	or	r3, r13
     a9c:	35 2c       	mov	r3, r5
     a9e:	36 29       	or	r19, r6
     aa0:	00 69       	ori	r16, 0x90	; 144
     aa2:	6e 74       	andi	r22, 0x4E	; 78
     aa4:	5f 66       	ori	r21, 0x6F	; 111
     aa6:	61 73       	andi	r22, 0x31	; 49
     aa8:	74 36       	cpi	r23, 0x64	; 100
     aaa:	34 5f       	subi	r19, 0xF4	; 244
     aac:	74 3a       	cpi	r23, 0xA4	; 164
     aae:	74 28       	or	r7, r4
     ab0:	35 2c       	mov	r3, r5
     ab2:	32 35       	cpi	r19, 0x52	; 82
     ab4:	29 3d       	cpi	r18, 0xD9	; 217
     ab6:	28 35       	cpi	r18, 0x58	; 88
     ab8:	2c 37       	cpi	r18, 0x7C	; 124
     aba:	29 00       	.word	0x0029	; ????
     abc:	75 69       	ori	r23, 0x95	; 149
     abe:	6e 74       	andi	r22, 0x4E	; 78
     ac0:	5f 66       	ori	r21, 0x6F	; 111
     ac2:	61 73       	andi	r22, 0x31	; 49
     ac4:	74 36       	cpi	r23, 0x64	; 100
     ac6:	34 5f       	subi	r19, 0xF4	; 244
     ac8:	74 3a       	cpi	r23, 0xA4	; 164
     aca:	74 28       	or	r7, r4
     acc:	35 2c       	mov	r3, r5
     ace:	32 36       	cpi	r19, 0x62	; 98
     ad0:	29 3d       	cpi	r18, 0xD9	; 217
     ad2:	28 35       	cpi	r18, 0x58	; 88
     ad4:	2c 38       	cpi	r18, 0x8C	; 140
     ad6:	29 00       	.word	0x0029	; ????
     ad8:	69 6e       	ori	r22, 0xE9	; 233
     ada:	74 6d       	ori	r23, 0xD4	; 212
     adc:	61 78       	andi	r22, 0x81	; 129
     ade:	5f 74       	andi	r21, 0x4F	; 79
     ae0:	3a 74       	andi	r19, 0x4A	; 74
     ae2:	28 35       	cpi	r18, 0x58	; 88
     ae4:	2c 32       	cpi	r18, 0x2C	; 44
     ae6:	37 29       	or	r19, r7
     ae8:	3d 28       	or	r3, r13
     aea:	35 2c       	mov	r3, r5
     aec:	37 29       	or	r19, r7
     aee:	00 75       	andi	r16, 0x50	; 80
     af0:	69 6e       	ori	r22, 0xE9	; 233
     af2:	74 6d       	ori	r23, 0xD4	; 212
     af4:	61 78       	andi	r22, 0x81	; 129
     af6:	5f 74       	andi	r21, 0x4F	; 79
     af8:	3a 74       	andi	r19, 0x4A	; 74
     afa:	28 35       	cpi	r18, 0x58	; 88
     afc:	2c 32       	cpi	r18, 0x2C	; 44
     afe:	38 29       	or	r19, r8
     b00:	3d 28       	or	r3, r13
     b02:	35 2c       	mov	r3, r5
     b04:	38 29       	or	r19, r8
     b06:	00 69       	ori	r16, 0x90	; 144
     b08:	6e 74       	andi	r22, 0x4E	; 78
     b0a:	5f 66       	ori	r21, 0x6F	; 111
     b0c:	61 72       	andi	r22, 0x21	; 33
     b0e:	70 74       	andi	r23, 0x40	; 64
     b10:	72 5f       	subi	r23, 0xF2	; 242
     b12:	74 3a       	cpi	r23, 0xA4	; 164
     b14:	74 28       	or	r7, r4
     b16:	33 2c       	mov	r3, r3
     b18:	31 29       	or	r19, r1
     b1a:	3d 28       	or	r3, r13
     b1c:	35 2c       	mov	r3, r5
     b1e:	35 29       	or	r19, r5
     b20:	00 75       	andi	r16, 0x50	; 80
     b22:	69 6e       	ori	r22, 0xE9	; 233
     b24:	74 5f       	subi	r23, 0xF4	; 244
     b26:	66 61       	ori	r22, 0x16	; 22
     b28:	72 70       	andi	r23, 0x02	; 2
     b2a:	74 72       	andi	r23, 0x24	; 36
     b2c:	5f 74       	andi	r21, 0x4F	; 79
     b2e:	3a 74       	andi	r19, 0x4A	; 74
     b30:	28 33       	cpi	r18, 0x38	; 56
     b32:	2c 32       	cpi	r18, 0x2C	; 44
     b34:	29 3d       	cpi	r18, 0xD9	; 217
     b36:	28 35       	cpi	r18, 0x58	; 88
     b38:	2c 36       	cpi	r18, 0x6C	; 108
     b3a:	29 00       	.word	0x0029	; ????
     b3c:	2f 75       	andi	r18, 0x5F	; 95
     b3e:	73 72       	andi	r23, 0x23	; 35
     b40:	2f 6c       	ori	r18, 0xCF	; 207
     b42:	69 62       	ori	r22, 0x29	; 41
     b44:	2f 61       	ori	r18, 0x1F	; 31
     b46:	76 72       	andi	r23, 0x26	; 38
     b48:	2f 69       	ori	r18, 0x9F	; 159
     b4a:	6e 63       	ori	r22, 0x3E	; 62
     b4c:	6c 75       	andi	r22, 0x5C	; 92
     b4e:	64 65       	ori	r22, 0x54	; 84
     b50:	2f 61       	ori	r18, 0x1F	; 31
     b52:	76 72       	andi	r23, 0x26	; 38
     b54:	2f 66       	ori	r18, 0x6F	; 111
     b56:	75 73       	andi	r23, 0x35	; 53
     b58:	65 2e       	mov	r6, r21
     b5a:	68 00       	.word	0x0068	; ????
     b5c:	5f 5f       	subi	r21, 0xFF	; 255
     b5e:	66 75       	andi	r22, 0x56	; 86
     b60:	73 65       	ori	r23, 0x53	; 83
     b62:	5f 74       	andi	r21, 0x4F	; 79
     b64:	3a 74       	andi	r19, 0x4A	; 74
     b66:	28 36       	cpi	r18, 0x68	; 104
     b68:	2c 31       	cpi	r18, 0x1C	; 28
     b6a:	29 3d       	cpi	r18, 0xD9	; 217
     b6c:	28 36       	cpi	r18, 0x68	; 104
     b6e:	2c 32       	cpi	r18, 0x2C	; 44
     b70:	29 3d       	cpi	r18, 0xD9	; 217
     b72:	73 33       	cpi	r23, 0x33	; 51
     b74:	6c 6f       	ori	r22, 0xFC	; 252
     b76:	77 3a       	cpi	r23, 0xA7	; 167
     b78:	28 30       	cpi	r18, 0x08	; 8
     b7a:	2c 31       	cpi	r18, 0x1C	; 28
     b7c:	31 29       	or	r19, r1
     b7e:	2c 30       	cpi	r18, 0x0C	; 12
     b80:	2c 38       	cpi	r18, 0x8C	; 140
     b82:	3b 68       	ori	r19, 0x8B	; 139
     b84:	69 67       	ori	r22, 0x79	; 121
     b86:	68 3a       	cpi	r22, 0xA8	; 168
     b88:	28 30       	cpi	r18, 0x08	; 8
     b8a:	2c 31       	cpi	r18, 0x1C	; 28
     b8c:	31 29       	or	r19, r1
     b8e:	2c 38       	cpi	r18, 0x8C	; 140
     b90:	2c 38       	cpi	r18, 0x8C	; 140
     b92:	3b 65       	ori	r19, 0x5B	; 91
     b94:	78 74       	andi	r23, 0x48	; 72
     b96:	65 6e       	ori	r22, 0xE5	; 229
     b98:	64 65       	ori	r22, 0x54	; 84
     b9a:	64 3a       	cpi	r22, 0xA4	; 164
     b9c:	28 30       	cpi	r18, 0x08	; 8
     b9e:	2c 31       	cpi	r18, 0x1C	; 28
     ba0:	31 29       	or	r19, r1
     ba2:	2c 31       	cpi	r18, 0x1C	; 28
     ba4:	36 2c       	mov	r3, r6
     ba6:	38 3b       	cpi	r19, 0xB8	; 184
     ba8:	3b 00       	.word	0x003b	; ????
     baa:	55 41       	sbci	r21, 0x15	; 21
     bac:	52 54       	subi	r21, 0x42	; 66
     bae:	31 5f       	subi	r19, 0xF1	; 241
     bb0:	69 6e       	ori	r22, 0xE9	; 233
     bb2:	69 74       	andi	r22, 0x49	; 73
     bb4:	3a 46       	sbci	r19, 0x6A	; 106
     bb6:	28 30       	cpi	r18, 0x08	; 8
     bb8:	2c 34       	cpi	r18, 0x4C	; 76
     bba:	37 29       	or	r19, r7
     bbc:	00 55       	subi	r16, 0x50	; 80
     bbe:	41 52       	subi	r20, 0x21	; 33
     bc0:	54 31       	cpi	r21, 0x14	; 20
     bc2:	5f 70       	andi	r21, 0x0F	; 15
     bc4:	75 74       	andi	r23, 0x45	; 69
     bc6:	63 68       	ori	r22, 0x83	; 131
     bc8:	61 72       	andi	r22, 0x21	; 33
     bca:	3a 46       	sbci	r19, 0x6A	; 106
     bcc:	28 30       	cpi	r18, 0x08	; 8
     bce:	2c 34       	cpi	r18, 0x4C	; 76
     bd0:	37 29       	or	r19, r7
     bd2:	00 64       	ori	r16, 0x40	; 64
     bd4:	61 74       	andi	r22, 0x41	; 65
     bd6:	61 3a       	cpi	r22, 0xA1	; 161
     bd8:	50 28       	or	r5, r0
     bda:	30 2c       	mov	r3, r0
     bdc:	31 31       	cpi	r19, 0x11	; 17
     bde:	29 00       	.word	0x0029	; ????
     be0:	55 41       	sbci	r21, 0x15	; 21
     be2:	52 54       	subi	r21, 0x42	; 66
     be4:	31 5f       	subi	r19, 0xF1	; 241
     be6:	64 61       	ori	r22, 0x14	; 20
     be8:	74 61       	ori	r23, 0x14	; 20
     bea:	5f 61       	ori	r21, 0x1F	; 31
     bec:	76 61       	ori	r23, 0x16	; 22
     bee:	69 6c       	ori	r22, 0xC9	; 201
     bf0:	61 62       	ori	r22, 0x21	; 33
     bf2:	6c 65       	ori	r22, 0x5C	; 92
     bf4:	3a 46       	sbci	r19, 0x6A	; 106
     bf6:	28 30       	cpi	r18, 0x08	; 8
     bf8:	2c 34       	cpi	r18, 0x4C	; 76
     bfa:	38 29       	or	r19, r8
     bfc:	3d 40       	sbci	r19, 0x0D	; 13
     bfe:	73 38       	cpi	r23, 0x83	; 131
     c00:	3b 2d       	mov	r19, r11
     c02:	31 36       	cpi	r19, 0x61	; 97
     c04:	3b 00       	.word	0x003b	; ????
     c06:	55 41       	sbci	r21, 0x15	; 21
     c08:	52 54       	subi	r21, 0x42	; 66
     c0a:	31 5f       	subi	r19, 0xF1	; 241
     c0c:	67 65       	ori	r22, 0x57	; 87
     c0e:	74 63       	ori	r23, 0x34	; 52
     c10:	68 61       	ori	r22, 0x18	; 24
     c12:	72 3a       	cpi	r23, 0xA2	; 162
     c14:	46 28       	or	r4, r6
     c16:	30 2c       	mov	r3, r0
     c18:	31 31       	cpi	r19, 0x11	; 17
     c1a:	29 00       	.word	0x0029	; ????
     c1c:	55 41       	sbci	r21, 0x15	; 21
     c1e:	52 54       	subi	r21, 0x42	; 66
     c20:	31 5f       	subi	r19, 0xF1	; 241
     c22:	66 6c       	ori	r22, 0xC6	; 198
     c24:	75 73       	andi	r23, 0x35	; 53
     c26:	68 3a       	cpi	r22, 0xA8	; 168
     c28:	46 28       	or	r4, r6
     c2a:	30 2c       	mov	r3, r0
     c2c:	34 37       	cpi	r19, 0x74	; 116
     c2e:	29 00       	.word	0x0029	; ????
     c30:	64 75       	andi	r22, 0x54	; 84
     c32:	6d 6d       	ori	r22, 0xDD	; 221
     c34:	79 3a       	cpi	r23, 0xA9	; 169
     c36:	72 28       	or	r7, r2
     c38:	30 2c       	mov	r3, r0
     c3a:	31 31       	cpi	r19, 0x11	; 17
     c3c:	29 00       	.word	0x0029	; ????
     c3e:	55 41       	sbci	r21, 0x15	; 21
     c40:	52 54       	subi	r21, 0x42	; 66
     c42:	31 5f       	subi	r19, 0xF1	; 241
     c44:	70 75       	andi	r23, 0x50	; 80
     c46:	74 73       	andi	r23, 0x34	; 52
     c48:	74 72       	andi	r23, 0x24	; 36
     c4a:	69 6e       	ori	r22, 0xE9	; 233
     c4c:	67 3a       	cpi	r22, 0xA7	; 167
     c4e:	46 28       	or	r4, r6
     c50:	30 2c       	mov	r3, r0
     c52:	34 37       	cpi	r19, 0x74	; 116
     c54:	29 00       	.word	0x0029	; ????
     c56:	73 74       	andi	r23, 0x43	; 67
     c58:	72 3a       	cpi	r23, 0xA2	; 162
     c5a:	50 28       	or	r5, r0
     c5c:	30 2c       	mov	r3, r0
     c5e:	34 39       	cpi	r19, 0x94	; 148
     c60:	29 3d       	cpi	r18, 0xD9	; 217
     c62:	2a 28       	or	r2, r10
     c64:	30 2c       	mov	r3, r0
     c66:	32 29       	or	r19, r2
     c68:	00 55       	subi	r16, 0x50	; 80
     c6a:	41 52       	subi	r20, 0x21	; 33
     c6c:	54 30       	cpi	r21, 0x04	; 4
     c6e:	5f 69       	ori	r21, 0x9F	; 159
     c70:	6e 69       	ori	r22, 0x9E	; 158
     c72:	74 3a       	cpi	r23, 0xA4	; 164
     c74:	46 28       	or	r4, r6
     c76:	30 2c       	mov	r3, r0
     c78:	34 37       	cpi	r19, 0x74	; 116
     c7a:	29 00       	.word	0x0029	; ????
     c7c:	55 41       	sbci	r21, 0x15	; 21
     c7e:	52 54       	subi	r21, 0x42	; 66
     c80:	30 5f       	subi	r19, 0xF0	; 240
     c82:	70 75       	andi	r23, 0x50	; 80
     c84:	74 63       	ori	r23, 0x34	; 52
     c86:	68 61       	ori	r22, 0x18	; 24
     c88:	72 3a       	cpi	r23, 0xA2	; 162
     c8a:	46 28       	or	r4, r6
     c8c:	30 2c       	mov	r3, r0
     c8e:	34 37       	cpi	r19, 0x74	; 116
     c90:	29 00       	.word	0x0029	; ????
     c92:	55 41       	sbci	r21, 0x15	; 21
     c94:	52 54       	subi	r21, 0x42	; 66
     c96:	30 5f       	subi	r19, 0xF0	; 240
     c98:	64 61       	ori	r22, 0x14	; 20
     c9a:	74 61       	ori	r23, 0x14	; 20
     c9c:	5f 61       	ori	r21, 0x1F	; 31
     c9e:	76 61       	ori	r23, 0x16	; 22
     ca0:	69 6c       	ori	r22, 0xC9	; 201
     ca2:	61 62       	ori	r22, 0x21	; 33
     ca4:	6c 65       	ori	r22, 0x5C	; 92
     ca6:	3a 46       	sbci	r19, 0x6A	; 106
     ca8:	28 30       	cpi	r18, 0x08	; 8
     caa:	2c 34       	cpi	r18, 0x4C	; 76
     cac:	38 29       	or	r19, r8
     cae:	00 55       	subi	r16, 0x50	; 80
     cb0:	41 52       	subi	r20, 0x21	; 33
     cb2:	54 30       	cpi	r21, 0x04	; 4
     cb4:	5f 67       	ori	r21, 0x7F	; 127
     cb6:	65 74       	andi	r22, 0x45	; 69
     cb8:	63 68       	ori	r22, 0x83	; 131
     cba:	61 72       	andi	r22, 0x21	; 33
     cbc:	3a 46       	sbci	r19, 0x6A	; 106
     cbe:	28 30       	cpi	r18, 0x08	; 8
     cc0:	2c 31       	cpi	r18, 0x1C	; 28
     cc2:	31 29       	or	r19, r1
     cc4:	00 55       	subi	r16, 0x50	; 80
     cc6:	41 52       	subi	r20, 0x21	; 33
     cc8:	54 30       	cpi	r21, 0x04	; 4
     cca:	5f 66       	ori	r21, 0x6F	; 111
     ccc:	6c 75       	andi	r22, 0x5C	; 92
     cce:	73 68       	ori	r23, 0x83	; 131
     cd0:	3a 46       	sbci	r19, 0x6A	; 106
     cd2:	28 30       	cpi	r18, 0x08	; 8
     cd4:	2c 34       	cpi	r18, 0x4C	; 76
     cd6:	37 29       	or	r19, r7
     cd8:	00 55       	subi	r16, 0x50	; 80
     cda:	41 52       	subi	r20, 0x21	; 33
     cdc:	54 30       	cpi	r21, 0x04	; 4
     cde:	5f 70       	andi	r21, 0x0F	; 15
     ce0:	75 74       	andi	r23, 0x45	; 69
     ce2:	73 74       	andi	r23, 0x43	; 67
     ce4:	72 69       	ori	r23, 0x92	; 146
     ce6:	6e 67       	ori	r22, 0x7E	; 126
     ce8:	3a 46       	sbci	r19, 0x6A	; 106
     cea:	28 30       	cpi	r18, 0x08	; 8
     cec:	2c 34       	cpi	r18, 0x4C	; 76
     cee:	37 29       	or	r19, r7
     cf0:	00 73       	andi	r16, 0x30	; 48
     cf2:	74 72       	andi	r23, 0x24	; 36
     cf4:	3a 50       	subi	r19, 0x0A	; 10
     cf6:	28 30       	cpi	r18, 0x08	; 8
     cf8:	2c 34       	cpi	r18, 0x4C	; 76
     cfa:	39 29       	or	r19, r9
     cfc:	00 73       	andi	r16, 0x30	; 48
     cfe:	72 63       	ori	r23, 0x32	; 50
     d00:	2f 73       	andi	r18, 0x3F	; 63
     d02:	79 73       	andi	r23, 0x39	; 57
     d04:	5f 73       	andi	r21, 0x3F	; 63
     d06:	74 61       	ori	r23, 0x14	; 20
     d08:	72 74       	andi	r23, 0x42	; 66
     d0a:	75 70       	andi	r23, 0x05	; 5
     d0c:	2e 63       	ori	r18, 0x3E	; 62
     d0e:	00 5f       	subi	r16, 0xF0	; 240
     d10:	5f 49       	sbci	r21, 0x9F	; 159
     d12:	6e 69       	ori	r22, 0x9E	; 158
     d14:	74 3a       	cpi	r23, 0xA4	; 164
     d16:	46 28       	or	r4, r6
     d18:	30 2c       	mov	r3, r0
     d1a:	34 37       	cpi	r19, 0x74	; 116
     d1c:	29 00       	.word	0x0029	; ????
     d1e:	5f 5f       	subi	r21, 0xFF	; 255
     d20:	64 6f       	ori	r22, 0xF4	; 244
     d22:	5f 63       	ori	r21, 0x3F	; 63
     d24:	6f 70       	andi	r22, 0x0F	; 15
     d26:	79 5f       	subi	r23, 0xF9	; 249
     d28:	64 61       	ori	r22, 0x14	; 20
     d2a:	74 61       	ori	r23, 0x14	; 20
     d2c:	3a 46       	sbci	r19, 0x6A	; 106
     d2e:	28 30       	cpi	r18, 0x08	; 8
     d30:	2c 34       	cpi	r18, 0x4C	; 76
     d32:	37 29       	or	r19, r7
     d34:	00 5f       	subi	r16, 0xF0	; 240
     d36:	5f 6a       	ori	r21, 0xAF	; 175
     d38:	75 6d       	ori	r23, 0xD5	; 213
     d3a:	70 4d       	sbci	r23, 0xD0	; 208
     d3c:	61 69       	ori	r22, 0x91	; 145
     d3e:	6e 3a       	cpi	r22, 0xAE	; 174
     d40:	46 28       	or	r4, r6
     d42:	30 2c       	mov	r3, r0
     d44:	34 37       	cpi	r19, 0x74	; 116
     d46:	29 00       	.word	0x0029	; ????
     d48:	73 72       	andi	r23, 0x23	; 35
     d4a:	63 2f       	mov	r22, r19
     d4c:	62 6f       	ori	r22, 0xF2	; 242
     d4e:	6f 74       	andi	r22, 0x4F	; 79
     d50:	6c 6f       	ori	r22, 0xFC	; 252
     d52:	61 64       	ori	r22, 0x41	; 65
     d54:	65 72       	andi	r22, 0x25	; 37
     d56:	2e 63       	ori	r18, 0x3E	; 62
     d58:	00 2f       	mov	r16, r16
     d5a:	75 73       	andi	r23, 0x35	; 53
     d5c:	72 2f       	mov	r23, r18
     d5e:	6c 69       	ori	r22, 0x9C	; 156
     d60:	62 2f       	mov	r22, r18
     d62:	61 76       	andi	r22, 0x61	; 97
     d64:	72 2f       	mov	r23, r18
     d66:	69 6e       	ori	r22, 0xE9	; 233
     d68:	63 6c       	ori	r22, 0xC3	; 195
     d6a:	75 64       	ori	r23, 0x45	; 69
     d6c:	65 2f       	mov	r22, r21
     d6e:	73 74       	andi	r23, 0x43	; 67
     d70:	64 69       	ori	r22, 0x94	; 148
     d72:	6f 2e       	mov	r6, r31
     d74:	68 00       	.word	0x0068	; ????
     d76:	2f 75       	andi	r18, 0x5F	; 95
     d78:	73 72       	andi	r23, 0x23	; 35
     d7a:	2f 6c       	ori	r18, 0xCF	; 207
     d7c:	69 62       	ori	r22, 0x29	; 41
     d7e:	2f 67       	ori	r18, 0x7F	; 127
     d80:	63 63       	ori	r22, 0x33	; 51
     d82:	2f 61       	ori	r18, 0x1F	; 31
     d84:	76 72       	andi	r23, 0x26	; 38
     d86:	2f 34       	cpi	r18, 0x4F	; 79
     d88:	2e 39       	cpi	r18, 0x9E	; 158
     d8a:	2e 32       	cpi	r18, 0x2E	; 46
     d8c:	2f 69       	ori	r18, 0x9F	; 159
     d8e:	6e 63       	ori	r22, 0x3E	; 62
     d90:	6c 75       	andi	r22, 0x5C	; 92
     d92:	64 65       	ori	r22, 0x54	; 84
     d94:	2f 73       	andi	r18, 0x3F	; 63
     d96:	74 64       	ori	r23, 0x44	; 68
     d98:	61 72       	andi	r22, 0x21	; 33
     d9a:	67 2e       	mov	r6, r23
     d9c:	68 00       	.word	0x0068	; ????
     d9e:	5f 5f       	subi	r21, 0xFF	; 255
     da0:	67 6e       	ori	r22, 0xE7	; 231
     da2:	75 63       	ori	r23, 0x35	; 53
     da4:	5f 76       	andi	r21, 0x6F	; 111
     da6:	61 5f       	subi	r22, 0xF1	; 241
     da8:	6c 69       	ori	r22, 0x9C	; 156
     daa:	73 74       	andi	r23, 0x43	; 67
     dac:	3a 74       	andi	r19, 0x4A	; 74
     dae:	28 38       	cpi	r18, 0x88	; 136
     db0:	2c 31       	cpi	r18, 0x1C	; 28
     db2:	29 3d       	cpi	r18, 0xD9	; 217
     db4:	28 38       	cpi	r18, 0x88	; 136
     db6:	2c 32       	cpi	r18, 0x2C	; 44
     db8:	29 3d       	cpi	r18, 0xD9	; 217
     dba:	2a 28       	or	r2, r10
     dbc:	30 2c       	mov	r3, r0
     dbe:	34 37       	cpi	r19, 0x74	; 116
     dc0:	29 00       	.word	0x0029	; ????
     dc2:	76 61       	ori	r23, 0x16	; 22
     dc4:	5f 6c       	ori	r21, 0xCF	; 207
     dc6:	69 73       	andi	r22, 0x39	; 57
     dc8:	74 3a       	cpi	r23, 0xA4	; 164
     dca:	74 28       	or	r7, r4
     dcc:	38 2c       	mov	r3, r8
     dce:	33 29       	or	r19, r3
     dd0:	3d 28       	or	r3, r13
     dd2:	38 2c       	mov	r3, r8
     dd4:	31 29       	or	r19, r1
     dd6:	00 2f       	mov	r16, r16
     dd8:	75 73       	andi	r23, 0x35	; 53
     dda:	72 2f       	mov	r23, r18
     ddc:	6c 69       	ori	r22, 0x9C	; 156
     dde:	62 2f       	mov	r22, r18
     de0:	67 63       	ori	r22, 0x37	; 55
     de2:	63 2f       	mov	r22, r19
     de4:	61 76       	andi	r22, 0x61	; 97
     de6:	72 2f       	mov	r23, r18
     de8:	34 2e       	mov	r3, r20
     dea:	39 2e       	mov	r3, r25
     dec:	32 2f       	mov	r19, r18
     dee:	69 6e       	ori	r22, 0xE9	; 233
     df0:	63 6c       	ori	r22, 0xC3	; 195
     df2:	75 64       	ori	r23, 0x45	; 69
     df4:	65 2f       	mov	r22, r21
     df6:	73 74       	andi	r23, 0x43	; 67
     df8:	64 64       	ori	r22, 0x44	; 68
     dfa:	65 66       	ori	r22, 0x65	; 101
     dfc:	2e 68       	ori	r18, 0x8E	; 142
     dfe:	00 73       	andi	r16, 0x30	; 48
     e00:	69 7a       	andi	r22, 0xA9	; 169
     e02:	65 5f       	subi	r22, 0xF5	; 245
     e04:	74 3a       	cpi	r23, 0xA4	; 164
     e06:	74 28       	or	r7, r4
     e08:	39 2c       	mov	r3, r9
     e0a:	31 29       	or	r19, r1
     e0c:	3d 28       	or	r3, r13
     e0e:	30 2c       	mov	r3, r0
     e10:	34 29       	or	r19, r4
     e12:	00 5f       	subi	r16, 0xF0	; 240
     e14:	5f 66       	ori	r21, 0x6F	; 111
     e16:	69 6c       	ori	r22, 0xC9	; 201
     e18:	65 3a       	cpi	r22, 0xA5	; 165
     e1a:	54 28       	or	r5, r4
     e1c:	37 2c       	mov	r3, r7
     e1e:	31 29       	or	r19, r1
     e20:	3d 73       	andi	r19, 0x3D	; 61
     e22:	31 34       	cpi	r19, 0x41	; 65
     e24:	62 75       	andi	r22, 0x52	; 82
     e26:	66 3a       	cpi	r22, 0xA6	; 166
     e28:	28 37       	cpi	r18, 0x78	; 120
     e2a:	2c 32       	cpi	r18, 0x2C	; 44
     e2c:	29 3d       	cpi	r18, 0xD9	; 217
     e2e:	2a 28       	or	r2, r10
     e30:	30 2c       	mov	r3, r0
     e32:	32 29       	or	r19, r2
     e34:	2c 30       	cpi	r18, 0x0C	; 12
     e36:	2c 31       	cpi	r18, 0x1C	; 28
     e38:	36 3b       	cpi	r19, 0xB6	; 182
     e3a:	75 6e       	ori	r23, 0xE5	; 229
     e3c:	67 65       	ori	r22, 0x57	; 87
     e3e:	74 3a       	cpi	r23, 0xA4	; 164
     e40:	28 30       	cpi	r18, 0x08	; 8
     e42:	2c 31       	cpi	r18, 0x1C	; 28
     e44:	31 29       	or	r19, r1
     e46:	2c 31       	cpi	r18, 0x1C	; 28
     e48:	36 2c       	mov	r3, r6
     e4a:	38 3b       	cpi	r19, 0xB8	; 184
     e4c:	66 6c       	ori	r22, 0xC6	; 198
     e4e:	61 67       	ori	r22, 0x71	; 113
     e50:	73 3a       	cpi	r23, 0xA3	; 163
     e52:	28 35       	cpi	r18, 0x58	; 88
     e54:	2c 32       	cpi	r18, 0x2C	; 44
     e56:	29 2c       	mov	r2, r9
     e58:	32 34       	cpi	r19, 0x42	; 66
     e5a:	2c 38       	cpi	r18, 0x8C	; 140
     e5c:	3b 73       	andi	r19, 0x3B	; 59
     e5e:	69 7a       	andi	r22, 0xA9	; 169
     e60:	65 3a       	cpi	r22, 0xA5	; 165
     e62:	28 30       	cpi	r18, 0x08	; 8
     e64:	2c 31       	cpi	r18, 0x1C	; 28
     e66:	29 2c       	mov	r2, r9
     e68:	33 32       	cpi	r19, 0x23	; 35
     e6a:	2c 31       	cpi	r18, 0x1C	; 28
     e6c:	36 3b       	cpi	r19, 0xB6	; 182
     e6e:	6c 65       	ori	r22, 0x5C	; 92
     e70:	6e 3a       	cpi	r22, 0xAE	; 174
     e72:	28 30       	cpi	r18, 0x08	; 8
     e74:	2c 31       	cpi	r18, 0x1C	; 28
     e76:	29 2c       	mov	r2, r9
     e78:	34 38       	cpi	r19, 0x84	; 132
     e7a:	2c 31       	cpi	r18, 0x1C	; 28
     e7c:	36 3b       	cpi	r19, 0xB6	; 182
     e7e:	70 75       	andi	r23, 0x50	; 80
     e80:	74 3a       	cpi	r23, 0xA4	; 164
     e82:	28 37       	cpi	r18, 0x78	; 120
     e84:	2c 33       	cpi	r18, 0x3C	; 60
     e86:	29 3d       	cpi	r18, 0xD9	; 217
     e88:	2a 28       	or	r2, r10
     e8a:	37 2c       	mov	r3, r7
     e8c:	34 29       	or	r19, r4
     e8e:	3d 66       	ori	r19, 0x6D	; 109
     e90:	28 30       	cpi	r18, 0x08	; 8
     e92:	2c 31       	cpi	r18, 0x1C	; 28
     e94:	29 2c       	mov	r2, r9
     e96:	36 34       	cpi	r19, 0x46	; 70
     e98:	2c 31       	cpi	r18, 0x1C	; 28
     e9a:	36 3b       	cpi	r19, 0xB6	; 182
     e9c:	67 65       	ori	r22, 0x57	; 87
     e9e:	74 3a       	cpi	r23, 0xA4	; 164
     ea0:	28 37       	cpi	r18, 0x78	; 120
     ea2:	2c 35       	cpi	r18, 0x5C	; 92
     ea4:	29 3d       	cpi	r18, 0xD9	; 217
     ea6:	2a 28       	or	r2, r10
     ea8:	37 2c       	mov	r3, r7
     eaa:	36 29       	or	r19, r6
     eac:	3d 66       	ori	r19, 0x6D	; 109
     eae:	28 30       	cpi	r18, 0x08	; 8
     eb0:	2c 31       	cpi	r18, 0x1C	; 28
     eb2:	29 2c       	mov	r2, r9
     eb4:	38 30       	cpi	r19, 0x08	; 8
     eb6:	2c 31       	cpi	r18, 0x1C	; 28
     eb8:	36 3b       	cpi	r19, 0xB6	; 182
     eba:	75 64       	ori	r23, 0x45	; 69
     ebc:	61 74       	andi	r22, 0x41	; 65
     ebe:	61 3a       	cpi	r22, 0xA1	; 161
     ec0:	28 37       	cpi	r18, 0x78	; 120
     ec2:	2c 37       	cpi	r18, 0x7C	; 124
     ec4:	29 3d       	cpi	r18, 0xD9	; 217
     ec6:	2a 28       	or	r2, r10
     ec8:	30 2c       	mov	r3, r0
     eca:	34 37       	cpi	r19, 0x74	; 116
     ecc:	29 2c       	mov	r2, r9
     ece:	39 36       	cpi	r19, 0x69	; 105
     ed0:	2c 31       	cpi	r18, 0x1C	; 28
     ed2:	36 3b       	cpi	r19, 0xB6	; 182
     ed4:	3b 00       	.word	0x003b	; ????
     ed6:	2f 75       	andi	r18, 0x5F	; 95
     ed8:	73 72       	andi	r23, 0x23	; 35
     eda:	2f 6c       	ori	r18, 0xCF	; 207
     edc:	69 62       	ori	r22, 0x29	; 41
     ede:	2f 61       	ori	r18, 0x1F	; 31
     ee0:	76 72       	andi	r23, 0x26	; 38
     ee2:	2f 69       	ori	r18, 0x9F	; 159
     ee4:	6e 63       	ori	r22, 0x3E	; 62
     ee6:	6c 75       	andi	r22, 0x5C	; 92
     ee8:	64 65       	ori	r22, 0x54	; 84
     eea:	2f 61       	ori	r18, 0x1F	; 31
     eec:	76 72       	andi	r23, 0x26	; 38
     eee:	2f 62       	ori	r18, 0x2F	; 47
     ef0:	6f 6f       	ori	r22, 0xFF	; 255
     ef2:	74 2e       	mov	r7, r20
     ef4:	68 00       	.word	0x0068	; ????
     ef6:	2f 75       	andi	r18, 0x5F	; 95
     ef8:	73 72       	andi	r23, 0x23	; 35
     efa:	2f 6c       	ori	r18, 0xCF	; 207
     efc:	69 62       	ori	r22, 0x29	; 41
     efe:	2f 61       	ori	r18, 0x1F	; 31
     f00:	76 72       	andi	r23, 0x26	; 38
     f02:	2f 69       	ori	r18, 0x9F	; 159
     f04:	6e 63       	ori	r22, 0x3E	; 62
     f06:	6c 75       	andi	r22, 0x5C	; 92
     f08:	64 65       	ori	r22, 0x54	; 84
     f0a:	2f 61       	ori	r18, 0x1F	; 31
     f0c:	76 72       	andi	r23, 0x26	; 38
     f0e:	2f 65       	ori	r18, 0x5F	; 95
     f10:	65 70       	andi	r22, 0x05	; 5
     f12:	72 6f       	ori	r23, 0xF2	; 242
     f14:	6d 2e       	mov	r6, r29
     f16:	68 00       	.word	0x0068	; ????
     f18:	70 74       	andi	r23, 0x40	; 64
     f1a:	72 64       	ori	r23, 0x42	; 66
     f1c:	69 66       	ori	r22, 0x69	; 105
     f1e:	66 5f       	subi	r22, 0xF6	; 246
     f20:	74 3a       	cpi	r23, 0xA4	; 164
     f22:	74 28       	or	r7, r4
     f24:	31 32       	cpi	r19, 0x21	; 33
     f26:	2c 31       	cpi	r18, 0x1C	; 28
     f28:	29 3d       	cpi	r18, 0xD9	; 217
     f2a:	28 30       	cpi	r18, 0x08	; 8
     f2c:	2c 31       	cpi	r18, 0x1C	; 28
     f2e:	29 00       	.word	0x0029	; ????
     f30:	77 63       	ori	r23, 0x37	; 55
     f32:	68 61       	ori	r22, 0x18	; 24
     f34:	72 5f       	subi	r23, 0xF2	; 242
     f36:	74 3a       	cpi	r23, 0xA4	; 164
     f38:	74 28       	or	r7, r4
     f3a:	31 32       	cpi	r19, 0x21	; 33
     f3c:	2c 32       	cpi	r18, 0x2C	; 44
     f3e:	29 3d       	cpi	r18, 0xD9	; 217
     f40:	28 30       	cpi	r18, 0x08	; 8
     f42:	2c 31       	cpi	r18, 0x1C	; 28
     f44:	29 00       	.word	0x0029	; ????
     f46:	62 6f       	ori	r22, 0xF2	; 242
     f48:	6f 74       	andi	r22, 0x4F	; 79
     f4a:	5f 66       	ori	r21, 0x6F	; 111
     f4c:	69 72       	andi	r22, 0x29	; 41
     f4e:	6d 77       	andi	r22, 0x7D	; 125
     f50:	61 72       	andi	r22, 0x21	; 33
     f52:	65 3a       	cpi	r22, 0xA5	; 165
     f54:	46 28       	or	r4, r6
     f56:	30 2c       	mov	r3, r0
     f58:	34 37       	cpi	r19, 0x74	; 116
     f5a:	29 00       	.word	0x0029	; ????
     f5c:	2f 75       	andi	r18, 0x5F	; 95
     f5e:	73 72       	andi	r23, 0x23	; 35
     f60:	2f 6c       	ori	r18, 0xCF	; 207
     f62:	69 62       	ori	r22, 0x29	; 41
     f64:	2f 61       	ori	r18, 0x1F	; 31
     f66:	76 72       	andi	r23, 0x26	; 38
     f68:	2f 69       	ori	r18, 0x9F	; 159
     f6a:	6e 63       	ori	r22, 0x3E	; 62
     f6c:	6c 75       	andi	r22, 0x5C	; 92
     f6e:	64 65       	ori	r22, 0x54	; 84
     f70:	2f 61       	ori	r18, 0x1F	; 31
     f72:	76 72       	andi	r23, 0x26	; 38
     f74:	2f 77       	andi	r18, 0x7F	; 127
     f76:	64 74       	andi	r22, 0x44	; 68
     f78:	2e 68       	ori	r18, 0x8E	; 142
     f7a:	00 5f       	subi	r16, 0xF0	; 240
     f7c:	5f 61       	ori	r21, 0x1F	; 31
     f7e:	64 64       	ori	r22, 0x44	; 68
     f80:	72 33       	cpi	r23, 0x32	; 50
     f82:	32 3a       	cpi	r19, 0xA2	; 162
     f84:	72 28       	or	r7, r2
     f86:	35 2c       	mov	r3, r5
     f88:	36 29       	or	r19, r6
     f8a:	00 72       	andi	r16, 0x20	; 32
     f8c:	65 61       	ori	r22, 0x15	; 21
     f8e:	64 62       	ori	r22, 0x24	; 36
     f90:	61 63       	ori	r22, 0x31	; 49
     f92:	6b 3a       	cpi	r22, 0xAB	; 171
     f94:	46 28       	or	r4, r6
     f96:	30 2c       	mov	r3, r0
     f98:	34 37       	cpi	r19, 0x74	; 116
     f9a:	29 00       	.word	0x0029	; ????
     f9c:	72 65       	ori	r23, 0x52	; 82
     f9e:	61 64       	ori	r22, 0x41	; 65
     fa0:	5f 66       	ori	r21, 0x6F	; 111
     fa2:	72 61       	ori	r23, 0x12	; 18
     fa4:	6d 65       	ori	r22, 0x5D	; 93
     fa6:	3a 46       	sbci	r19, 0x6A	; 106
     fa8:	28 30       	cpi	r18, 0x08	; 8
     faa:	2c 31       	cpi	r18, 0x1C	; 28
     fac:	29 00       	.word	0x0029	; ????
     fae:	64 61       	ori	r22, 0x14	; 20
     fb0:	74 61       	ori	r23, 0x14	; 20
     fb2:	3a 50       	subi	r19, 0x0A	; 10
     fb4:	28 30       	cpi	r18, 0x08	; 8
     fb6:	2c 34       	cpi	r18, 0x4C	; 76
     fb8:	38 29       	or	r19, r8
     fba:	3d 2a       	or	r3, r29
     fbc:	28 30       	cpi	r18, 0x08	; 8
     fbe:	2c 31       	cpi	r18, 0x1C	; 28
     fc0:	31 29       	or	r19, r1
     fc2:	00 73       	andi	r16, 0x30	; 48
     fc4:	74 61       	ori	r23, 0x14	; 20
     fc6:	72 74       	andi	r23, 0x42	; 66
     fc8:	5f 69       	ori	r21, 0x9F	; 159
     fca:	6e 64       	ori	r22, 0x4E	; 78
     fcc:	65 78       	andi	r22, 0x85	; 133
     fce:	3a 50       	subi	r19, 0x0A	; 10
     fd0:	28 30       	cpi	r18, 0x08	; 8
     fd2:	2c 31       	cpi	r18, 0x1C	; 28
     fd4:	29 00       	.word	0x0029	; ????
     fd6:	69 3a       	cpi	r22, 0xA9	; 169
     fd8:	72 28       	or	r7, r2
     fda:	30 2c       	mov	r3, r0
     fdc:	31 29       	or	r19, r1
     fde:	00 70       	andi	r16, 0x00	; 0
     fe0:	72 6f       	ori	r23, 0xF2	; 242
     fe2:	67 72       	andi	r22, 0x27	; 39
     fe4:	61 6d       	ori	r22, 0xD1	; 209
     fe6:	5f 66       	ori	r21, 0x6F	; 111
     fe8:	6c 61       	ori	r22, 0x1C	; 28
     fea:	73 68       	ori	r23, 0x83	; 131
     fec:	3a 46       	sbci	r19, 0x6A	; 106
     fee:	28 30       	cpi	r18, 0x08	; 8
     ff0:	2c 34       	cpi	r18, 0x4C	; 76
     ff2:	37 29       	or	r19, r7
     ff4:	00 70       	andi	r16, 0x00	; 0
     ff6:	61 67       	ori	r22, 0x71	; 113
     ff8:	65 5f       	subi	r22, 0xF5	; 245
     ffa:	61 64       	ori	r22, 0x41	; 65
     ffc:	64 72       	andi	r22, 0x24	; 36
     ffe:	65 73       	andi	r22, 0x35	; 53
    1000:	73 3a       	cpi	r23, 0xA3	; 163
    1002:	50 28       	or	r5, r0
    1004:	35 2c       	mov	r3, r5
    1006:	36 29       	or	r19, r6
    1008:	00 64       	ori	r16, 0x40	; 64
    100a:	61 74       	andi	r22, 0x41	; 65
    100c:	61 3a       	cpi	r22, 0xA1	; 161
    100e:	50 28       	or	r5, r0
    1010:	30 2c       	mov	r3, r0
    1012:	34 38       	cpi	r19, 0x84	; 132
    1014:	29 00       	.word	0x0029	; ????
    1016:	6c 6f       	ori	r22, 0xFC	; 252
    1018:	61 64       	ori	r22, 0x41	; 65
    101a:	5f 66       	ori	r21, 0x6F	; 111
    101c:	69 72       	andi	r22, 0x29	; 41
    101e:	6d 77       	andi	r22, 0x7D	; 125
    1020:	61 72       	andi	r22, 0x21	; 33
    1022:	65 3a       	cpi	r22, 0xA5	; 165
    1024:	46 28       	or	r4, r6
    1026:	30 2c       	mov	r3, r0
    1028:	34 37       	cpi	r19, 0x74	; 116
    102a:	29 00       	.word	0x0029	; ????
    102c:	64 61       	ori	r22, 0x14	; 20
    102e:	74 61       	ori	r23, 0x14	; 20
    1030:	3a 28       	or	r3, r10
    1032:	30 2c       	mov	r3, r0
    1034:	34 39       	cpi	r19, 0x94	; 148
    1036:	29 3d       	cpi	r18, 0xD9	; 217
    1038:	61 72       	andi	r22, 0x21	; 33
    103a:	28 30       	cpi	r18, 0x08	; 8
    103c:	2c 35       	cpi	r18, 0x5C	; 92
    103e:	30 29       	or	r19, r0
    1040:	3d 72       	andi	r19, 0x2D	; 45
    1042:	28 30       	cpi	r18, 0x08	; 8
    1044:	2c 35       	cpi	r18, 0x5C	; 92
    1046:	30 29       	or	r19, r0
    1048:	3b 30       	cpi	r19, 0x0B	; 11
    104a:	3b 30       	cpi	r19, 0x0B	; 11
    104c:	31 37       	cpi	r19, 0x71	; 113
    104e:	37 37       	cpi	r19, 0x77	; 119
    1050:	37 37       	cpi	r19, 0x77	; 119
    1052:	3b 3b       	cpi	r19, 0xBB	; 187
    1054:	30 3b       	cpi	r19, 0xB0	; 176
    1056:	32 35       	cpi	r19, 0x52	; 82
    1058:	35 3b       	cpi	r19, 0xB5	; 181
    105a:	28 30       	cpi	r18, 0x08	; 8
    105c:	2c 31       	cpi	r18, 0x1C	; 28
    105e:	31 29       	or	r19, r1
    1060:	00 70       	andi	r16, 0x00	; 0
    1062:	61 67       	ori	r22, 0x71	; 113
    1064:	65 3a       	cpi	r22, 0xA5	; 165
    1066:	72 28       	or	r7, r2
    1068:	30 2c       	mov	r3, r0
    106a:	34 29       	or	r19, r4
    106c:	00 6d       	ori	r16, 0xD0	; 208
    106e:	61 69       	ori	r22, 0x91	; 145
    1070:	6e 3a       	cpi	r22, 0xAE	; 174
    1072:	46 28       	or	r4, r6
    1074:	30 2c       	mov	r3, r0
    1076:	31 29       	or	r19, r1
    1078:	00 66       	ori	r16, 0x60	; 96
    107a:	77 5f       	subi	r23, 0xF7	; 247
    107c:	73 69       	ori	r23, 0x93	; 147
    107e:	7a 65       	ori	r23, 0x5A	; 90
    1080:	3a 47       	sbci	r19, 0x7A	; 122
    1082:	28 35       	cpi	r18, 0x58	; 88
    1084:	2c 34       	cpi	r18, 0x4C	; 76
    1086:	29 00       	.word	0x0029	; ????
    1088:	66 77       	andi	r22, 0x76	; 118
    108a:	5f 76       	andi	r21, 0x6F	; 111
    108c:	65 72       	andi	r22, 0x25	; 37
    108e:	73 69       	ori	r23, 0x93	; 147
    1090:	6f 6e       	ori	r22, 0xEF	; 239
    1092:	3a 47       	sbci	r19, 0x7A	; 122
    1094:	28 35       	cpi	r18, 0x58	; 88
    1096:	2c 34       	cpi	r18, 0x4C	; 76
    1098:	29 00       	.word	0x0029	; ????
    109a:	73 72       	andi	r23, 0x23	; 35
    109c:	63 2f       	mov	r22, r19
    109e:	61 65       	ori	r22, 0x51	; 81
    10a0:	73 2e       	mov	r7, r19
    10a2:	63 00       	.word	0x0063	; ????
    10a4:	2f 75       	andi	r18, 0x5F	; 95
    10a6:	73 72       	andi	r23, 0x23	; 35
    10a8:	2f 6c       	ori	r18, 0xCF	; 207
    10aa:	69 62       	ori	r22, 0x29	; 41
    10ac:	2f 61       	ori	r18, 0x1F	; 31
    10ae:	76 72       	andi	r23, 0x26	; 38
    10b0:	2f 69       	ori	r18, 0x9F	; 159
    10b2:	6e 63       	ori	r22, 0x3E	; 62
    10b4:	6c 75       	andi	r22, 0x5C	; 92
    10b6:	64 65       	ori	r22, 0x54	; 84
    10b8:	2f 73       	andi	r18, 0x3F	; 63
    10ba:	74 72       	andi	r23, 0x24	; 36
    10bc:	69 6e       	ori	r22, 0xE9	; 233
    10be:	67 2e       	mov	r6, r23
    10c0:	68 00       	.word	0x0068	; ????
    10c2:	2f 75       	andi	r18, 0x5F	; 95
    10c4:	73 72       	andi	r23, 0x23	; 35
    10c6:	2f 6c       	ori	r18, 0xCF	; 207
    10c8:	69 62       	ori	r22, 0x29	; 41
    10ca:	2f 61       	ori	r18, 0x1F	; 31
    10cc:	76 72       	andi	r23, 0x26	; 38
    10ce:	2f 69       	ori	r18, 0x9F	; 159
    10d0:	6e 63       	ori	r22, 0x3E	; 62
    10d2:	6c 75       	andi	r22, 0x5C	; 92
    10d4:	64 65       	ori	r22, 0x54	; 84
    10d6:	2f 61       	ori	r18, 0x1F	; 31
    10d8:	76 72       	andi	r23, 0x26	; 38
    10da:	2f 70       	andi	r18, 0x0F	; 15
    10dc:	67 6d       	ori	r22, 0xD7	; 215
    10de:	73 70       	andi	r23, 0x03	; 3
    10e0:	61 63       	ori	r22, 0x31	; 49
    10e2:	65 2e       	mov	r6, r21
    10e4:	68 00       	.word	0x0068	; ????
    10e6:	73 74       	andi	r23, 0x43	; 67
    10e8:	61 74       	andi	r22, 0x41	; 65
    10ea:	65 5f       	subi	r22, 0xF5	; 245
    10ec:	74 3a       	cpi	r23, 0xA4	; 164
    10ee:	74 28       	or	r7, r4
    10f0:	30 2c       	mov	r3, r0
    10f2:	34 38       	cpi	r19, 0x84	; 132
    10f4:	29 3d       	cpi	r18, 0xD9	; 217
    10f6:	28 30       	cpi	r18, 0x08	; 8
    10f8:	2c 34       	cpi	r18, 0x4C	; 76
    10fa:	39 29       	or	r19, r9
    10fc:	3d 61       	ori	r19, 0x1D	; 29
    10fe:	72 28       	or	r7, r2
    1100:	30 2c       	mov	r3, r0
    1102:	35 30       	cpi	r19, 0x05	; 5
    1104:	29 3d       	cpi	r18, 0xD9	; 217
    1106:	72 28       	or	r7, r2
    1108:	30 2c       	mov	r3, r0
    110a:	35 30       	cpi	r19, 0x05	; 5
    110c:	29 3b       	cpi	r18, 0xB9	; 185
    110e:	30 3b       	cpi	r19, 0xB0	; 176
    1110:	30 31       	cpi	r19, 0x10	; 16
    1112:	37 37       	cpi	r19, 0x77	; 119
    1114:	37 37       	cpi	r19, 0x77	; 119
    1116:	37 3b       	cpi	r19, 0xB7	; 183
    1118:	3b 30       	cpi	r19, 0x0B	; 11
    111a:	3b 33       	cpi	r19, 0x3B	; 59
    111c:	3b 28       	or	r3, r11
    111e:	30 2c       	mov	r3, r0
    1120:	35 31       	cpi	r19, 0x15	; 21
    1122:	29 3d       	cpi	r18, 0xD9	; 217
    1124:	61 72       	andi	r22, 0x21	; 33
    1126:	28 30       	cpi	r18, 0x08	; 8
    1128:	2c 35       	cpi	r18, 0x5C	; 92
    112a:	30 29       	or	r19, r0
    112c:	3b 30       	cpi	r19, 0x0B	; 11
    112e:	3b 33       	cpi	r19, 0x3B	; 59
    1130:	3b 28       	or	r3, r11
    1132:	32 2c       	mov	r3, r2
    1134:	32 29       	or	r19, r2
    1136:	00 41       	sbci	r16, 0x10	; 16
    1138:	64 64       	ori	r22, 0x44	; 68
    113a:	52 6f       	ori	r21, 0xF2	; 242
    113c:	75 6e       	ori	r23, 0xE5	; 229
    113e:	64 4b       	sbci	r22, 0xB4	; 180
    1140:	65 79       	andi	r22, 0x95	; 149
    1142:	3a 66       	ori	r19, 0x6A	; 106
    1144:	28 30       	cpi	r18, 0x08	; 8
    1146:	2c 34       	cpi	r18, 0x4C	; 76
    1148:	37 29       	or	r19, r7
    114a:	00 72       	andi	r16, 0x20	; 32
    114c:	6f 75       	andi	r22, 0x5F	; 95
    114e:	6e 64       	ori	r22, 0x4E	; 78
    1150:	3a 50       	subi	r19, 0x0A	; 10
    1152:	28 32       	cpi	r18, 0x28	; 40
    1154:	2c 32       	cpi	r18, 0x2C	; 44
    1156:	29 00       	.word	0x0029	; ????
    1158:	53 68       	ori	r21, 0x83	; 131
    115a:	69 66       	ori	r22, 0x69	; 105
    115c:	74 52       	subi	r23, 0x24	; 36
    115e:	6f 77       	andi	r22, 0x7F	; 127
    1160:	73 3a       	cpi	r23, 0xA3	; 163
    1162:	66 28       	or	r6, r6
    1164:	30 2c       	mov	r3, r0
    1166:	34 37       	cpi	r19, 0x74	; 116
    1168:	29 00       	.word	0x0029	; ????
    116a:	78 74       	andi	r23, 0x48	; 72
    116c:	69 6d       	ori	r22, 0xD9	; 217
    116e:	65 3a       	cpi	r22, 0xA5	; 165
    1170:	66 28       	or	r6, r6
    1172:	32 2c       	mov	r3, r2
    1174:	32 29       	or	r19, r2
    1176:	00 78       	andi	r16, 0x80	; 128
    1178:	3a 50       	subi	r19, 0x0A	; 10
    117a:	28 32       	cpi	r18, 0x28	; 40
    117c:	2c 32       	cpi	r18, 0x2C	; 44
    117e:	29 00       	.word	0x0029	; ????
    1180:	49 6e       	ori	r20, 0xE9	; 233
    1182:	76 53       	subi	r23, 0x36	; 54
    1184:	75 62       	ori	r23, 0x25	; 37
    1186:	42 79       	andi	r20, 0x92	; 146
    1188:	74 65       	ori	r23, 0x54	; 84
    118a:	73 3a       	cpi	r23, 0xA3	; 163
    118c:	66 28       	or	r6, r6
    118e:	30 2c       	mov	r3, r0
    1190:	34 37       	cpi	r19, 0x74	; 116
    1192:	29 00       	.word	0x0029	; ????
    1194:	6a 3a       	cpi	r22, 0xAA	; 170
    1196:	72 28       	or	r7, r2
    1198:	32 2c       	mov	r3, r2
    119a:	32 29       	or	r19, r2
    119c:	00 49       	sbci	r16, 0x90	; 144
    119e:	6e 76       	andi	r22, 0x6E	; 110
    11a0:	53 68       	ori	r21, 0x83	; 131
    11a2:	69 66       	ori	r22, 0x69	; 105
    11a4:	74 52       	subi	r23, 0x24	; 36
    11a6:	6f 77       	andi	r22, 0x7F	; 127
    11a8:	73 3a       	cpi	r23, 0xA3	; 163
    11aa:	66 28       	or	r6, r6
    11ac:	30 2c       	mov	r3, r0
    11ae:	34 37       	cpi	r19, 0x74	; 116
    11b0:	29 00       	.word	0x0029	; ????
    11b2:	53 75       	andi	r21, 0x53	; 83
    11b4:	62 42       	sbci	r22, 0x22	; 34
    11b6:	79 74       	andi	r23, 0x49	; 73
    11b8:	65 73       	andi	r22, 0x35	; 53
    11ba:	3a 66       	ori	r19, 0x6A	; 106
    11bc:	28 30       	cpi	r18, 0x08	; 8
    11be:	2c 34       	cpi	r18, 0x4C	; 76
    11c0:	37 29       	or	r19, r7
    11c2:	00 4b       	sbci	r16, 0xB0	; 176
    11c4:	65 79       	andi	r22, 0x95	; 149
    11c6:	45 78       	andi	r20, 0x85	; 133
    11c8:	70 61       	ori	r23, 0x10	; 16
    11ca:	6e 73       	andi	r22, 0x3E	; 62
    11cc:	69 6f       	ori	r22, 0xF9	; 249
    11ce:	6e 3a       	cpi	r22, 0xAE	; 174
    11d0:	66 28       	or	r6, r6
    11d2:	30 2c       	mov	r3, r0
    11d4:	34 37       	cpi	r19, 0x74	; 116
    11d6:	29 00       	.word	0x0029	; ????
    11d8:	69 3a       	cpi	r22, 0xA9	; 169
    11da:	72 28       	or	r7, r2
    11dc:	32 2c       	mov	r3, r2
    11de:	36 29       	or	r19, r6
    11e0:	00 74       	andi	r16, 0x40	; 64
    11e2:	65 6d       	ori	r22, 0xD5	; 213
    11e4:	70 61       	ori	r23, 0x10	; 16
    11e6:	3a 28       	or	r3, r10
    11e8:	30 2c       	mov	r3, r0
    11ea:	35 31       	cpi	r19, 0x15	; 21
    11ec:	29 00       	.word	0x0029	; ????
    11ee:	41 45       	sbci	r20, 0x51	; 81
    11f0:	53 31       	cpi	r21, 0x13	; 19
    11f2:	32 38       	cpi	r19, 0x82	; 130
    11f4:	5f 45       	sbci	r21, 0x5F	; 95
    11f6:	43 42       	sbci	r20, 0x23	; 35
    11f8:	5f 65       	ori	r21, 0x5F	; 95
    11fa:	6e 63       	ori	r22, 0x3E	; 62
    11fc:	72 79       	andi	r23, 0x92	; 146
    11fe:	70 74       	andi	r23, 0x40	; 64
    1200:	3a 46       	sbci	r19, 0x6A	; 106
    1202:	28 30       	cpi	r18, 0x08	; 8
    1204:	2c 34       	cpi	r18, 0x4C	; 76
    1206:	37 29       	or	r19, r7
    1208:	00 69       	ori	r16, 0x90	; 144
    120a:	6e 70       	andi	r22, 0x0E	; 14
    120c:	75 74       	andi	r23, 0x45	; 69
    120e:	3a 50       	subi	r19, 0x0A	; 10
    1210:	28 30       	cpi	r18, 0x08	; 8
    1212:	2c 35       	cpi	r18, 0x5C	; 92
    1214:	32 29       	or	r19, r2
    1216:	3d 2a       	or	r3, r29
    1218:	28 30       	cpi	r18, 0x08	; 8
    121a:	2c 35       	cpi	r18, 0x5C	; 92
    121c:	33 29       	or	r19, r3
    121e:	3d 6b       	ori	r19, 0xBD	; 189
    1220:	28 32       	cpi	r18, 0x28	; 40
    1222:	2c 32       	cpi	r18, 0x2C	; 44
    1224:	29 00       	.word	0x0029	; ????
    1226:	6b 65       	ori	r22, 0x5B	; 91
    1228:	79 3a       	cpi	r23, 0xA9	; 169
    122a:	50 28       	or	r5, r0
    122c:	30 2c       	mov	r3, r0
    122e:	35 32       	cpi	r19, 0x25	; 37
    1230:	29 00       	.word	0x0029	; ????
    1232:	6f 75       	andi	r22, 0x5F	; 95
    1234:	74 70       	andi	r23, 0x04	; 4
    1236:	75 74       	andi	r23, 0x45	; 69
    1238:	3a 70       	andi	r19, 0x0A	; 10
    123a:	28 30       	cpi	r18, 0x08	; 8
    123c:	2c 35       	cpi	r18, 0x5C	; 92
    123e:	34 29       	or	r19, r4
    1240:	3d 2a       	or	r3, r29
    1242:	28 32       	cpi	r18, 0x28	; 40
    1244:	2c 32       	cpi	r18, 0x2C	; 44
    1246:	29 00       	.word	0x0029	; ????
    1248:	72 6f       	ori	r23, 0xF2	; 242
    124a:	75 6e       	ori	r23, 0xE5	; 229
    124c:	64 3a       	cpi	r22, 0xA4	; 164
    124e:	28 32       	cpi	r18, 0x28	; 40
    1250:	2c 32       	cpi	r18, 0x2C	; 44
    1252:	29 00       	.word	0x0029	; ????
    1254:	54 6d       	ori	r21, 0xD4	; 212
    1256:	70 3a       	cpi	r23, 0xA0	; 160
    1258:	72 28       	or	r7, r2
    125a:	32 2c       	mov	r3, r2
    125c:	32 29       	or	r19, r2
    125e:	00 74       	andi	r16, 0x40	; 64
    1260:	3a 72       	andi	r19, 0x2A	; 42
    1262:	28 32       	cpi	r18, 0x28	; 40
    1264:	2c 32       	cpi	r18, 0x2C	; 44
    1266:	29 00       	.word	0x0029	; ????
    1268:	41 45       	sbci	r20, 0x51	; 81
    126a:	53 31       	cpi	r21, 0x13	; 19
    126c:	32 38       	cpi	r19, 0x82	; 130
    126e:	5f 45       	sbci	r21, 0x5F	; 95
    1270:	43 42       	sbci	r20, 0x23	; 35
    1272:	5f 64       	ori	r21, 0x4F	; 79
    1274:	65 63       	ori	r22, 0x35	; 53
    1276:	72 79       	andi	r23, 0x92	; 146
    1278:	70 74       	andi	r23, 0x40	; 64
    127a:	3a 46       	sbci	r19, 0x6A	; 106
    127c:	28 30       	cpi	r18, 0x08	; 8
    127e:	2c 34       	cpi	r18, 0x4C	; 76
    1280:	37 29       	or	r19, r7
    1282:	00 69       	ori	r16, 0x90	; 144
    1284:	6e 70       	andi	r22, 0x0E	; 14
    1286:	75 74       	andi	r23, 0x45	; 69
    1288:	3a 50       	subi	r19, 0x0A	; 10
    128a:	28 30       	cpi	r18, 0x08	; 8
    128c:	2c 35       	cpi	r18, 0x5C	; 92
    128e:	32 29       	or	r19, r2
    1290:	00 6f       	ori	r16, 0xF0	; 240
    1292:	75 74       	andi	r23, 0x45	; 69
    1294:	70 75       	andi	r23, 0x50	; 80
    1296:	74 3a       	cpi	r23, 0xA4	; 164
    1298:	50 28       	or	r5, r0
    129a:	30 2c       	mov	r3, r0
    129c:	35 34       	cpi	r19, 0x45	; 69
    129e:	29 00       	.word	0x0029	; ????
    12a0:	72 6f       	ori	r23, 0xF2	; 242
    12a2:	75 6e       	ori	r23, 0xE5	; 229
    12a4:	64 3a       	cpi	r22, 0xA4	; 164
    12a6:	72 28       	or	r7, r2
    12a8:	32 2c       	mov	r3, r2
    12aa:	32 29       	or	r19, r2
    12ac:	00 61       	ori	r16, 0x10	; 16
    12ae:	3a 72       	andi	r19, 0x2A	; 42
    12b0:	28 32       	cpi	r18, 0x28	; 40
    12b2:	2c 32       	cpi	r18, 0x2C	; 44
    12b4:	29 00       	.word	0x0029	; ????
    12b6:	62 3a       	cpi	r22, 0xA2	; 162
    12b8:	72 28       	or	r7, r2
    12ba:	32 2c       	mov	r3, r2
    12bc:	32 29       	or	r19, r2
    12be:	00 63       	ori	r16, 0x30	; 48
    12c0:	3a 72       	andi	r19, 0x2A	; 42
    12c2:	28 32       	cpi	r18, 0x28	; 40
    12c4:	2c 32       	cpi	r18, 0x2C	; 44
    12c6:	29 00       	.word	0x0029	; ????
    12c8:	64 3a       	cpi	r22, 0xA4	; 164
    12ca:	72 28       	or	r7, r2
    12cc:	32 2c       	mov	r3, r2
    12ce:	32 29       	or	r19, r2
    12d0:	00 73       	andi	r16, 0x30	; 48
    12d2:	74 61       	ori	r23, 0x14	; 20
    12d4:	74 65       	ori	r23, 0x54	; 84
    12d6:	3a 53       	subi	r19, 0x3A	; 58
    12d8:	28 30       	cpi	r18, 0x08	; 8
    12da:	2c 35       	cpi	r18, 0x5C	; 92
    12dc:	35 29       	or	r19, r5
    12de:	3d 2a       	or	r3, r29
    12e0:	28 30       	cpi	r18, 0x08	; 8
    12e2:	2c 34       	cpi	r18, 0x4C	; 76
    12e4:	38 29       	or	r19, r8
    12e6:	00 52       	subi	r16, 0x20	; 32
    12e8:	6f 75       	andi	r22, 0x5F	; 95
    12ea:	6e 64       	ori	r22, 0x4E	; 78
    12ec:	4b 65       	ori	r20, 0x5B	; 91
    12ee:	79 3a       	cpi	r23, 0xA9	; 169
    12f0:	53 28       	or	r5, r3
    12f2:	30 2c       	mov	r3, r0
    12f4:	35 36       	cpi	r19, 0x65	; 101
    12f6:	29 3d       	cpi	r18, 0xD9	; 217
    12f8:	61 72       	andi	r22, 0x21	; 33
    12fa:	28 30       	cpi	r18, 0x08	; 8
    12fc:	2c 35       	cpi	r18, 0x5C	; 92
    12fe:	30 29       	or	r19, r0
    1300:	3b 30       	cpi	r19, 0x0B	; 11
    1302:	3b 31       	cpi	r19, 0x1B	; 27
    1304:	37 35       	cpi	r19, 0x57	; 87
    1306:	3b 28       	or	r3, r11
    1308:	32 2c       	mov	r3, r2
    130a:	32 29       	or	r19, r2
    130c:	00 4b       	sbci	r16, 0xB0	; 176
    130e:	65 79       	andi	r22, 0x95	; 149
    1310:	3a 53       	subi	r19, 0x3A	; 58
    1312:	28 30       	cpi	r18, 0x08	; 8
    1314:	2c 35       	cpi	r18, 0x5C	; 92
    1316:	32 29       	or	r19, r2
    1318:	00 53       	subi	r16, 0x30	; 48
    131a:	62 6f       	ori	r22, 0xF2	; 242
    131c:	78 3a       	cpi	r23, 0xA8	; 168
    131e:	53 28       	or	r5, r3
    1320:	30 2c       	mov	r3, r0
    1322:	35 37       	cpi	r19, 0x75	; 117
    1324:	29 3d       	cpi	r18, 0xD9	; 217
    1326:	61 72       	andi	r22, 0x21	; 33
    1328:	28 30       	cpi	r18, 0x08	; 8
    132a:	2c 35       	cpi	r18, 0x5C	; 92
    132c:	30 29       	or	r19, r0
    132e:	3b 30       	cpi	r19, 0x0B	; 11
    1330:	3b 32       	cpi	r19, 0x2B	; 43
    1332:	35 35       	cpi	r19, 0x55	; 85
    1334:	3b 28       	or	r3, r11
    1336:	30 2c       	mov	r3, r0
    1338:	35 33       	cpi	r19, 0x35	; 53
    133a:	29 00       	.word	0x0029	; ????
    133c:	52 73       	andi	r21, 0x32	; 50
    133e:	62 6f       	ori	r22, 0xF2	; 242
    1340:	78 3a       	cpi	r23, 0xA8	; 168
    1342:	53 28       	or	r5, r3
    1344:	30 2c       	mov	r3, r0
    1346:	35 37       	cpi	r19, 0x75	; 117
    1348:	29 00       	.word	0x0029	; ????
    134a:	72 63       	ori	r23, 0x32	; 50
    134c:	6f 6e       	ori	r22, 0xEF	; 239
    134e:	3a 53       	subi	r19, 0x3A	; 58
    1350:	28 30       	cpi	r18, 0x08	; 8
    1352:	2c 35       	cpi	r18, 0x5C	; 92
    1354:	38 29       	or	r19, r8
    1356:	3d 61       	ori	r19, 0x1D	; 29
    1358:	72 28       	or	r7, r2
    135a:	30 2c       	mov	r3, r0
    135c:	35 30       	cpi	r19, 0x05	; 5
    135e:	29 3b       	cpi	r18, 0xB9	; 185
    1360:	30 3b       	cpi	r19, 0xB0	; 176
    1362:	32 35       	cpi	r19, 0x52	; 82
    1364:	34 3b       	cpi	r19, 0xB4	; 180
    1366:	28 30       	cpi	r18, 0x08	; 8
    1368:	2c 35       	cpi	r18, 0x5C	; 92
    136a:	33 29       	or	r19, r3
    136c:	00 73       	andi	r16, 0x30	; 48
    136e:	62 6f       	ori	r22, 0xF2	; 242
    1370:	78 3a       	cpi	r23, 0xA8	; 168
    1372:	47 28       	or	r4, r7
    1374:	30 2c       	mov	r3, r0
    1376:	35 39       	cpi	r19, 0x95	; 149
    1378:	29 3d       	cpi	r18, 0xD9	; 217
    137a:	61 72       	andi	r22, 0x21	; 33
    137c:	28 30       	cpi	r18, 0x08	; 8
    137e:	2c 35       	cpi	r18, 0x5C	; 92
    1380:	30 29       	or	r19, r0
    1382:	3b 30       	cpi	r19, 0x0B	; 11
    1384:	3b 32       	cpi	r19, 0x2B	; 43
    1386:	35 35       	cpi	r19, 0x55	; 85
    1388:	3b 28       	or	r3, r11
    138a:	32 2c       	mov	r3, r2
    138c:	32 29       	or	r19, r2
    138e:	00 72       	andi	r16, 0x20	; 32
    1390:	73 62       	ori	r23, 0x23	; 35
    1392:	6f 78       	andi	r22, 0x8F	; 143
    1394:	3a 47       	sbci	r19, 0x7A	; 122
    1396:	28 30       	cpi	r18, 0x08	; 8
    1398:	2c 35       	cpi	r18, 0x5C	; 92
    139a:	39 29       	or	r19, r9
    139c:	00 52       	subi	r16, 0x20	; 32
    139e:	63 6f       	ori	r22, 0xF3	; 243
    13a0:	6e 3a       	cpi	r22, 0xAE	; 174
    13a2:	47 28       	or	r4, r7
    13a4:	30 2c       	mov	r3, r0
    13a6:	36 30       	cpi	r19, 0x06	; 6
    13a8:	29 3d       	cpi	r18, 0xD9	; 217
    13aa:	61 72       	andi	r22, 0x21	; 33
    13ac:	28 30       	cpi	r18, 0x08	; 8
    13ae:	2c 35       	cpi	r18, 0x5C	; 92
    13b0:	30 29       	or	r19, r0
    13b2:	3b 30       	cpi	r19, 0x0B	; 11
    13b4:	3b 32       	cpi	r19, 0x2B	; 43
    13b6:	35 34       	cpi	r19, 0x45	; 69
    13b8:	3b 28       	or	r3, r11
    13ba:	32 2c       	mov	r3, r2
    13bc:	32 29       	or	r19, r2
	...

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
