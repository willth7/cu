//   Copyright 2025 Will Thomas
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0;
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

//   sub umbra alarum suarum

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "inst.h"

struct au_sym_s {
	uint8_t* str;
	uint8_t len;
	uint64_t addr;
	uint8_t typ;
};

uint8_t x86_64_inc_reg(uint8_t reg) {
	if (reg >= 4) {
		reg = reg + 4;
	}
	return reg;
}

/*	function stack structure

calling a function, 	return address on top of the stack
						nth parameter
						...
						3rd parameter
						2nd parameter
						1st parameter

returning a function,	return address on top of the stack
						return value

the return operation will pop the return address off the stack, leaving the return value on top

*/

/*	registers

rax, rcx, rdx, rbx, and r8 - r15 are general purpose registers

rsp, the stack pointer

rbp, the base pointer, can't actually use this as a pointer because of rip, will be used as an exchange register

rsi, the source index, will be used as an exchange register

rdi, the destination index

rip, the instruction pointer

*/

void x86_64_enc_ent(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln) {
	rel[*reln].str = malloc(5);
	memcpy(rel[*reln].str, "main", 5);
	rel[*reln].len = 5;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = 1;
	
	x86_64_enc_call(bin, bn, 0);
}

void x86_64_enc_exit(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_reg_imm(bin, bn, 55, 0); //mov rdi, 0
	x86_64_enc_mov_reg_imm(bin, bn, 48, 60); //mov rax, 60
	x86_64_enc_syscall(bin, bn); //syscall
}

void x86_64_enc_loc_ref(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_lea_reg_addr(bin, bn, reg | 48, 52, indx, 0, 0); //lea [reg], (rsp, [indx])
}

void x86_64_enc_loc_dec_8(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_add_reg_imm(bin, bn, 52, 1); //add rsp, 1
}

void x86_64_enc_loc_dec_16(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_add_reg_imm(bin, bn, 52, 2); //add rsp, 2
}

void x86_64_enc_loc_dec_32(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_add_reg_imm(bin, bn, 52, 4); //add rsp, 4
}

void x86_64_enc_loc_dec_64(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_add_reg_imm(bin, bn, 52, 8); //add rsp, 8
}

void x86_64_enc_loc_load_8(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_load_16(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg | 16, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_load_32(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg | 32, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_load_64(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_mov_reg_addr(bin, bn, reg | 48, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_str_8(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_addr_reg(bin, bn, 52, 0, 0, indx, 0); //mov (rsp, [indx]), al
}

void x86_64_enc_loc_str_16(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_addr_reg(bin, bn, 52, 0, 0, indx, 16); //mov (rsp, [indx]), ax
}

void x86_64_enc_loc_str_32(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_addr_reg(bin, bn, 52, 0, 0, indx, 32); //mov (rsp, [indx]), eax
}

void x86_64_enc_loc_str_64(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_addr_reg(bin, bn, 52, 0, 0, indx, 48); //mov (rsp, [indx]), rax
}

void x86_64_enc_loc_dref_8(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr(bin, bn, 54, 52, 0, 0, indx); //mov rsi, (rsp, [indx])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 55, 0, 0, 0); //mov (rsi, (rdi)), al
}

void x86_64_enc_loc_dref_16(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr(bin, bn, 54, 52, 0, 0, indx); //mov rsi, (rsp, [indx])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 55, 0, 0, 16); //mov (rsi, (rdi)), ax
}

void x86_64_enc_loc_dref_32(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr(bin, bn, 54, 52, 0, 0, indx); //mov rsi, (rsp, [indx])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 55, 0, 0, 32); //mov (rsi, (rdi)), eax
}

void x86_64_enc_loc_dref_64(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr(bin, bn, 54, 52, 0, 0, indx); //mov rsi, (rsp, [indx])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 55, 0, 0, 48); //mov (rsi, (rdi)), rax
}

void x86_64_enc_glo_ref(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t reg, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_lea_reg_addr(bin, bn, reg | 48, 117, 0, 0, 0); //lea reg, (rip, [rel])
}

void x86_64_enc_glo_dec_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t strn) {
	sym[*symn].str = malloc(strn);
	memcpy(sym[*symn].str, str, strn);
	sym[*symn].len = strn;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 0;
	*symn = *symn + 1;
	
	x86_64_inst_byt(bin, bn, 0);
}

void x86_64_enc_glo_dec_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t strn) {
	sym[*symn].str = malloc(strn);
	memcpy(sym[*symn].str, str, strn);
	sym[*symn].len = strn;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 0;
	*symn = *symn + 1;
	
	x86_64_inst_k16(bin, bn, 0);
}

void x86_64_enc_glo_dec_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t strn) {
	sym[*symn].str = malloc(strn);
	memcpy(sym[*symn].str, str, strn);
	sym[*symn].len = strn;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 0;
	*symn = *symn + 1;
	
	x86_64_inst_k32(bin, bn, 0);
}

void x86_64_enc_glo_dec_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t strn) {
	sym[*symn].str = malloc(strn);
	memcpy(sym[*symn].str, str, strn);
	sym[*symn].len = strn;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 3;
	*symn = *symn + 1;
	
	x86_64_inst_k64(bin, bn, 0);
}

void x86_64_enc_glo_load_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t reg, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg, 54, 0, 0, 0); //mov [reg], (rsi)
}

void x86_64_enc_glo_load_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t reg, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg | 16, 54, 0, 0, 0); //mov [reg], (rsi)
}

void x86_64_enc_glo_load_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t reg, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg | 32, 54, 0, 0, 0); //mov [reg], (rsi)
}

void x86_64_enc_glo_load_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t reg, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_mov_reg_addr(bin, bn, reg | 48, 54, 0, 0, 0); //mov [reg], (rsi)
}

void x86_64_enc_glo_str_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 0); //mov (rsi), al
}

void x86_64_enc_glo_str_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 16); //mov (rsi), ax
}

void x86_64_enc_glo_str_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 32); //mov (rsi), eax
}

void x86_64_enc_glo_str_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 54, 117, 0, 0, 0); //lea rsi, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 48); //mov (rsi), rax
}

void x86_64_enc_glo_dref_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 55, 117, 0, 0, 0); //lea rdi, (rip, [rel])
	x86_64_enc_lea_reg_addr(bin, bn, 54, 55, 0, 0, 0); //mov rsi, (rdi)
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 0); //mov (rsi), al
}

void x86_64_enc_glo_dref_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 55, 117, 0, 0, 0); //lea rdi, (rip, [rel])
	x86_64_enc_lea_reg_addr(bin, bn, 54, 55, 0, 0, 0); //mov rsi, (rdi)
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 16); //mov (rsi), ax
}

void x86_64_enc_glo_dref_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 55, 117, 0, 0, 0); //lea rdi, (rip, [rel])
	x86_64_enc_lea_reg_addr(bin, bn, 54, 55, 0, 0, 0); //mov rsi, (rdi)
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 32); //mov (rsi), eax
}

void x86_64_enc_glo_dref_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 55, 117, 0, 0, 0); //lea rdi, (rip, [rel])
	x86_64_enc_lea_reg_addr(bin, bn, 54, 55, 0, 0, 0); //mov rsi, (rdi)
	x86_64_enc_mov_addr_reg(bin, bn, 54, 0, 0, 0, 48); //mov (rsi), rax
}

void x86_64_enc_load_imm(uint8_t* bin, uint64_t* bn, uint8_t reg, uint64_t k) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_mov_reg_imm(bin, bn, reg | 48, k); //mov [reg], [imm]
}

void x86_64_enc_add(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_add_reg_reg(bin, bn, r0 | 48, r1 | 48); //add [r0], [r1]
}

void x86_64_enc_sub(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_sub_reg_reg(bin, bn, r0 | 48, r1 | 48); //sub [r0], [r1]
}

void x86_64_enc_inc(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	reg = x86_64_inc_reg(reg);
	
	//x86_64_enc_inc_reg(bin, bn, reg | 48); //inc [reg]
	x86_64_enc_add_reg_imm(bin, bn, reg | 48, 1); //add [reg], 1
}

void x86_64_enc_dec(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	reg = x86_64_inc_reg(reg);
	
	//x86_64_enc_dec_reg(bin, bn, reg | 48); //dec [reg]
	x86_64_enc_sub_reg_imm(bin, bn, reg | 48, 1); //sub [reg], 1
}

void x86_64_enc_bit_not(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_not_reg(bin, bn, reg | 48); //not [reg]
}

void x86_64_enc_bit_and(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_and_reg_reg(bin, bn, r0 | 48, r1 | 48); //and [r0], [r1]
}

void x86_64_enc_bit_or(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_or_reg_reg(bin, bn, r0 | 48, r1 | 48); //or [r0], [r1]
}

void x86_64_enc_bit_xor(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r1 | 48); //xor [r0], [r1]
}

void x86_64_enc_bit_shl(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	if (r1 != 1) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 49); //mov rbp, rcx
		x86_64_enc_mov_reg_reg(bin, bn, 49, r1 | 48); //mov rcx, [r1]
		x86_64_enc_shl_reg_cl(bin, bn, r0 | 48); //shl [r0], cl
		x86_64_enc_mov_reg_reg(bin, bn, 49, 53); //mov rcx, rbp
	}
	else {
		x86_64_enc_shl_reg_cl(bin, bn, r0 | 48); //shl [r0], cl
	}
}

void x86_64_enc_bit_shr(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	if (r1 != 1) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 49); //mov rbp, rcx
		x86_64_enc_mov_reg_reg(bin, bn, 49, r1 | 48); //mov rcx, [r1]
		x86_64_enc_shr_reg_cl(bin, bn, r0 | 48); //shr [r0], cl
		x86_64_enc_mov_reg_reg(bin, bn, 49, 53); //mov rcx, rbp
	}
	else {
		x86_64_enc_shr_reg_cl(bin, bn, r0 | 48); //shr [r0], cl
	}
}

void x86_64_enc_log_not(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_or_reg_reg(bin, bn, reg | 48, reg | 48); //or [reg], [reg]
	x86_64_enc_mov_reg_imm(bin, bn, reg | 48, 1); //mov [reg], 1
	x86_64_enc_je_imm(bin, bn, 3); //je 3
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
}

void x86_64_enc_log_and(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_or_reg_reg(bin, bn, r0 | 48, r0 | 48); //or [r0], [r0]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_or_reg_reg(bin, bn, r1 | 48, r1 | 48); //or [r1], [r1]
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_or(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_or_reg_reg(bin, bn, r0 | 48, r0 | 48); //or [r0], [r0]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jne_imm(bin, bn, 8); ///jne 8
	x86_64_enc_or_reg_reg(bin, bn, r1 | 48, r1 | 48); //or [r1], [r1]
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_eq(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_je_imm(bin, bn, 3); ///je 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_neq(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_lt(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jl_imm(bin, bn, 3); ///jl 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_leq(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jle_imm(bin, bn, 3); ///j;e 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_gt(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jg_imm(bin, bn, 3); ///jg 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_log_geq(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jge_imm(bin, bn, 3); ///jge 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
}

void x86_64_enc_mult(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	if (r0 != 0) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 48); //mov rbp, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, r0 | 48); //mov rax, [r0]
	}
	if (r1 != 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 54, 50); //mov rsi, rdx
	}
	x86_64_enc_mul_rax_reg(bin, bn, r1 | 48); //mul rax, [r1]
	if (r0 != 0) {
		x86_64_enc_mov_reg_reg(bin, bn, r0 | 48, 48); //mov [r0], rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, 53); //mov rax, rbp
	}
	if (r1 != 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 50, 54); //mov rdx, rsi
	}
}

void x86_64_enc_div(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	if (r0 != 0) {
		x86_64_enc_mov_reg_reg(bin, bn, 54, 48); //mov rsi, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, r0 | 48); //mov rax, [r0]
	}
	if (r1 == 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 50); //mov rbp, rdx
		x86_64_enc_mov_reg_imm(bin, bn, 50, 0); //mov rdx, 0
		x86_64_enc_div_rax_reg(bin, bn, 53); //div rax, rbp
	}
	else {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 50); //mov rbp, rdx
		x86_64_enc_mov_reg_imm(bin, bn, 50, 0); //mov rdx, 0
		x86_64_enc_div_rax_reg(bin, bn, r1 | 48); //div rax, [r1]
		x86_64_enc_mov_reg_reg(bin, bn, 50, 53); //mov rdx, rbp
	}
	if (r0 != 0) {
		x86_64_enc_mov_reg_reg(bin, bn, r0 | 48, 48); //mov [r0], rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, 54); //mov rax, rsi
	}
}

void x86_64_enc_mod(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	r0 = x86_64_inc_reg(r0);
	r1 = x86_64_inc_reg(r1);
	
	if (r0 != 0) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 48); //mov rbp, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, r0 | 48); //mov rax, [r0]
	}
	if (r1 == 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 54, 50); //mov rsi, rdx
		x86_64_enc_mov_reg_imm(bin, bn, 50, 0); //mov rdx, 0
		x86_64_enc_div_rax_reg(bin, bn, 54); //div rax, rsi
	}
	else {
		x86_64_enc_mov_reg_reg(bin, bn, 54, 50); //mov rsi, rdx
		x86_64_enc_mov_reg_imm(bin, bn, 50, 0); //mov rdx, 0
		x86_64_enc_div_rax_reg(bin, bn, r1 | 48); //div rax, [r1]
	}
	if (r0 != 2) {
		x86_64_enc_mov_reg_reg(bin, bn, r0 | 48, 50); //mov [r0], rdx
	}
	if (r0 != 0) {
		x86_64_enc_mov_reg_reg(bin, bn, 48, 53); //mov rax, rbp
	}
	if (r1 != 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 50, 54); //mov rdx, rsi;
	}
}
