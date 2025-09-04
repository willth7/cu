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
	if (reg >= 94) {
		reg = reg + 7;
	}
	else if (reg >= 79) {
		reg = reg + 6;
	}
	else if (reg >= 64) {
		reg = reg + 5;
	}
	else if (reg >= 49) {
		reg = reg + 4;
	}
	else if (reg >= 34) {
		reg = reg + 3;
	}
	else if (reg >= 19) {
		reg = reg + 2;
	}
	else if (reg >= 4) {
		reg = reg + 1;
	}
	return reg;
}

/*	function stack structure

calling a function,8return address on top of the stack
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

rax - rbx, and rbp - r15 are general purpose registers

rsp, the stack pointer

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

void x86_64_enc_loc_ref(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	x86_64_enc_lea_reg_addr(bin, bn, reg | 48, 52, 0, 0, indx); //lea [reg], (rsp, [indx])
}

void x86_64_enc_loc_dec_8(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_sub_reg_imm(bin, bn, 52, 1); //sub rsp, 1
}

void x86_64_enc_loc_dec_16(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_sub_reg_imm(bin, bn, 52, 2); //sub rsp, 2
}

void x86_64_enc_loc_dec_32(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_sub_reg_imm(bin, bn, 52, 4); //sub rsp, 4
}

void x86_64_enc_loc_dec_64(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_sub_reg_imm(bin, bn, 52, 8); //sub rsp, 8
}

void x86_64_enc_loc_load_8(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_load_16(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg | 16, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_load_32(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
	x86_64_enc_mov_reg_addr(bin, bn, reg | 32, 52, 0, 0, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_load_64(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint32_t indx) {
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
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

void x86_64_enc_glo_ref(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*inc_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len) {
	reg = x86_64_inc_reg(reg);
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	x86_64_enc_lea_reg_addr(bin, bn, reg | 48, 117, 0, 0, 0); //lea [reg], (rip, [rel])
}

void x86_64_enc_glo_dec_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t len) {
	sym[*symn].str = malloc(len);
	memcpy(sym[*symn].str, str, len);
	sym[*symn].len = len;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 0;
	*symn = *symn + 1;
	
	x86_64_inst_byt(bin, bn, 0);
}

void x86_64_enc_glo_dec_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t len) {
	sym[*symn].str = malloc(len);
	memcpy(sym[*symn].str, str, len);
	sym[*symn].len = len;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 0;
	*symn = *symn + 1;
	
	x86_64_inst_k16(bin, bn, 0);
}

void x86_64_enc_glo_dec_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t len) {
	sym[*symn].str = malloc(len);
	memcpy(sym[*symn].str, str, len);
	sym[*symn].len = len;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 0;
	*symn = *symn + 1;
	
	x86_64_inst_k32(bin, bn, 0);
}

void x86_64_enc_glo_dec_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, uint8_t* str, uint8_t len) {
	sym[*symn].str = malloc(len);
	memcpy(sym[*symn].str, str, len);
	sym[*symn].len = len;
	sym[*symn].addr = *bn;
	sym[*symn].typ = 3;
	*symn = *symn + 1;
	
	x86_64_inst_k64(bin, bn, 0);
}

void x86_64_enc_glo_load_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*inc_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	uint8_t r0 = x86_64_inc_reg(reg);
	uint8_t rbp = x86_64_inc_reg(reg + 1);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, r0 | 48); //push [r0]
		inc_stack(8);
	}
	if (rbp > 15) {
		x86_64_enc_push_reg(bin, bn, rbp | 48); //push [rbp]
	}
	x86_64_enc_lea_reg_addr(bin, bn, rbp | 48, 117, 0, 0, 0); //lea [rbp], (rip, [rel])
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_mov_reg_addr(bin, bn, r0, rbp | 48, 0, 0, 0); //mov [r0], ([rbp])
	if (rbp > 15) {
		x86_64_enc_pop_reg(bin, bn, rbp | 48); //pop [rbp]
	}
}

void x86_64_enc_glo_load_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*inc_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	uint8_t r0 = x86_64_inc_reg(reg);
	uint8_t rbp = x86_64_inc_reg(reg + 1);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, r0 | 48); //push [r0]
		inc_stack(8);
	}
	if (rbp > 15) {
		x86_64_enc_push_reg(bin, bn, rbp | 48); //push [rbp]
	}
	x86_64_enc_lea_reg_addr(bin, bn, rbp | 48, 117, 0, 0, 0); //lea [rbp], (rip, [rel])
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_mov_reg_addr(bin, bn, r0 | 16, rbp | 48, 0, 0, 0); //mov [r0], ([rbp])
	if (rbp > 15) {
		x86_64_enc_pop_reg(bin, bn, rbp | 48); //pop [rbp]
	}
}

void x86_64_enc_glo_load_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*inc_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	uint8_t r0 = x86_64_inc_reg(reg);
	uint8_t rbp = x86_64_inc_reg(reg + 1);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, r0 | 48); //push [r0]
		inc_stack(8);
	}
	if (rbp > 15) {
		x86_64_enc_push_reg(bin, bn, rbp | 48); //push [rbp]
	}
	x86_64_enc_lea_reg_addr(bin, bn, rbp | 48, 117, 0, 0, 0); //lea [rbp], (rip, [rel])
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_mov_reg_addr(bin, bn, r0 | 32, rbp | 48, 0, 0, 0); //mov [r0], ([rbp])
	if (rbp > 15) {
		x86_64_enc_pop_reg(bin, bn, rbp | 48); //pop [rbp]
	}
}

void x86_64_enc_glo_load_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*inc_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	x86_64_enc_lea_reg_addr(bin, bn, reg | 48, 117, 0, 0, 0); //lea [reg], (rip, [rel])
	x86_64_enc_mov_reg_addr(bin, bn, reg | 48, reg | 48, 0, 0, 0); //mov [reg], ([reg])
}

void x86_64_enc_glo_str_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 49, 117, 0, 0, 0); //lea rcx, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 49, 0, 0, 0, 0); //mov (rcx), al
}

void x86_64_enc_glo_str_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 49, 117, 0, 0, 0); //lea rcx, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 49, 0, 0, 0, 16); //mov (rcx), ax
}

void x86_64_enc_glo_str_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 49, 117, 0, 0, 0); //lea rcx, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 49, 0, 0, 0, 32); //mov (rcx), eax
}

void x86_64_enc_glo_str_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t len) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	x86_64_enc_lea_reg_addr(bin, bn, 49, 117, 0, 0, 0); //lea rcx, (rip, [rel])
	x86_64_enc_mov_addr_reg(bin, bn, 49, 0, 0, 0, 48); //mov (rcx), rax
}

void x86_64_enc_load_dref_8(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg);
	uint8_t rbp = x86_64_inc_reg(reg + 1);
	
	if (rbp > 15) {
		x86_64_enc_push_reg(bin, bn, rbp | 48); //push [rbp]
	}
	x86_64_enc_mov_reg_reg(bin, bn, rbp | 48, r0 | 48); //mov [rbp], [r0]
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_mov_reg_addr(bin, bn, r0, rbp | 48, 0, 0, 0); //mov [r0], ([rbp])
	if (rbp > 15) {
		x86_64_enc_pop_reg(bin, bn, rbp | 48); //pop [rbp]
	}
}

void x86_64_enc_load_dref_16(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg);
	uint8_t rbp = x86_64_inc_reg(reg + 1);
	
	if (rbp > 15) {
		x86_64_enc_push_reg(bin, bn, rbp | 48); //push [rbp]
	}
	x86_64_enc_mov_reg_reg(bin, bn, rbp | 48, r0 | 48); //mov [rbp], [r0]
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_mov_reg_addr(bin, bn, r0 | 16, rbp | 48, 0, 0, 0); //mov [r0], ([rbp])
	if (rbp > 15) {
		x86_64_enc_pop_reg(bin, bn, rbp | 48); //pop [rbp]
	}
}

void x86_64_enc_load_dref_32(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg);
	uint8_t rbp = x86_64_inc_reg(reg + 1);
	
	if (rbp > 15) {
		x86_64_enc_push_reg(bin, bn, rbp | 48); //push [rbp]
	}
	x86_64_enc_mov_reg_reg(bin, bn, rbp | 48, r0 | 48); //mov [rbp], [r0]
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_mov_reg_addr(bin, bn, r0 | 32, rbp | 48, 0, 0, 0); //mov [r0], ([rbp])
	if (rbp > 15) {
		x86_64_enc_pop_reg(bin, bn, rbp | 48); //pop [rbp]
	}
}

void x86_64_enc_load_dref_64(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_mov_reg_addr(bin, bn, reg | 48, reg | 48, 0, 0, 0); //mov [reg], ([reg])
}

void x86_64_enc_str_dref_8(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_addr_reg(bin, bn, 48, 0, 0, 0, 1); //mov (rax), cl
}

void x86_64_enc_str_dref_16(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_addr_reg(bin, bn, 48, 0, 0, 0, 17); //mov (rax), cx
}

void x86_64_enc_str_dref_32(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_addr_reg(bin, bn, 48, 0, 0, 0, 33); //mov (rax), ecx
}

void x86_64_enc_str_dref_64(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_addr_reg(bin, bn, 48, 0, 0, 0, 49); //mov (rax), rcx
}

void x86_64_enc_load_dref_8_inc(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_xor_reg_reg(bin, bn, 49, 49); //xor rcx, rcx
	x86_64_enc_mov_reg_addr(bin, bn, 1, 48, 0, 0, 0); //mov cl, (rax)
}

void x86_64_enc_load_dref_16_inc(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_xor_reg_reg(bin, bn, 49, 49); //xor rcx, rcx
	x86_64_enc_mov_reg_addr(bin, bn, 17, 48, 0, 0, 0); //mov cc, (rax)
}

void x86_64_enc_load_dref_32_inc(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_xor_reg_reg(bin, bn, 49, 49); //xor rcx, rcx
	x86_64_enc_mov_reg_addr(bin, bn, 33, 48, 0, 0, 0); //mov ecx, (rax)
}

void x86_64_enc_load_dref_64_inc(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_reg_addr(bin, bn, 49, 48, 0, 0, 0); //mov rcx, (rax)
}

void x86_64_enc_load_imm(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint64_t k) {
	reg = x86_64_inc_reg(reg);
	
	if (reg > 15) {
		x86_64_enc_push_reg(bin, bn, reg | 48); //push [reg]
		inc_stack(8);
	}
	x86_64_enc_mov_reg_imm(bin, bn, reg | 48, k); //mov [reg], [imm]
}

void x86_64_enc_func_pre_call(uint8_t* bin, uint64_t* bn, void (*inc_stack) (uint8_t), uint8_t reg, uint16_t sz) {
	reg = x86_64_inc_reg(reg);
	
	for (uint8_t i = 0; i < (reg & 15); i++) { //preserves registers
		x86_64_enc_push_reg(bin, bn, i | 48); //push [i]
		inc_stack(8);
	}
	if (sz) { //creates argument stack
		x86_64_enc_sub_reg_imm(bin, bn, 52, sz); //sub rsp, [sz]
		inc_stack(sz);
	}
}

void x86_64_enc_func_call_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*dec_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len, uint16_t sz) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_call(bin, bn, 0); //call [func]
	if (sz) { //removes argument stack
		x86_64_enc_add_reg_imm(bin, bn, 52, sz); //add rsp, [sz]
		dec_stack(sz);
	}
	if (reg & 15) { //moves return value into register
		x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
		x86_64_enc_mov_reg_reg(bin, bn, reg & 15, 0); //mov [reg], al
	}
	else {
		x86_64_enc_and_reg_imm(bin, bn, reg | 48, 255); //and rax, 255
	}
	for (uint8_t i = reg & 15; i > 0; i--) { //restores preserved registers
		x86_64_enc_pop_reg(bin, bn, (i - 1) | 48); //pop [i - 1]
		dec_stack(8);
	}
}

void x86_64_enc_func_call_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*dec_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len, uint16_t sz) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_call(bin, bn, 0); //call [func]
	if (sz) { //removes argument stack
		x86_64_enc_add_reg_imm(bin, bn, 52, sz); //add rsp, [sz]
		dec_stack(sz);
	}
	if (reg & 15) { //moves return value into register
		x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
		x86_64_enc_mov_reg_reg(bin, bn, reg | 16, 16); //mov [reg], rax
	}
	else {
		x86_64_enc_and_reg_imm(bin, bn, reg | 48, 65535); //and rax, 65535
	}
	for (uint8_t i = reg & 15; i > 0; i--) { //restores preserved registers
		x86_64_enc_pop_reg(bin, bn, (i - 1) | 48); //pop [i - 1]
		dec_stack(8);
	}
}

void x86_64_enc_func_call_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*dec_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len, uint16_t sz) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_call(bin, bn, 0); //call [func]
	if (sz) { //removes argument stack
		x86_64_enc_add_reg_imm(bin, bn, 52, sz); //add rsp, [sz]
		dec_stack(sz);
	}
	if (reg & 15) { //moves return value into register
		x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
		x86_64_enc_mov_reg_reg(bin, bn, reg | 32, 32); //mov [reg], rax
	}
	else {
		x86_64_enc_and_reg_imm(bin, bn, reg | 48, 4294967295); //and rax, 4294967295
	}
	for (uint8_t i = reg & 15; i > 0; i--) { //restores preserved registers
		x86_64_enc_pop_reg(bin, bn, (i - 1) | 48); //pop [i - 1]
		dec_stack(8);
	}
}

void x86_64_enc_func_call_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*dec_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len, uint16_t sz) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_call(bin, bn, 0); //call [func]
	if (sz) { //removes argument stack
		x86_64_enc_add_reg_imm(bin, bn, 52, sz); //add rsp, [sz]
		dec_stack(sz);
	}
	if (reg & 15) { //moves return value into register
		x86_64_enc_mov_reg_reg(bin, bn, reg | 48, 48); //mov [reg], rax
	}
	for (uint8_t i = reg & 15; i > 0; i--) { //restores preserved registers
		x86_64_enc_pop_reg(bin, bn, (i - 1) | 48); //pop [i - 1]
		dec_stack(8);
	}
}

void x86_64_enc_func_call_void(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, void (*dec_stack) (uint8_t), uint8_t reg, uint8_t* str, uint8_t len, uint16_t sz) {
	rel[*reln].str = malloc(len);
	memcpy(rel[*reln].str, str, len);
	rel[*reln].len = len;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_call(bin, bn, 0); //call [func]
	if (sz) { //removes argument stack
		x86_64_enc_add_reg_imm(bin, bn, 52, sz); //add rsp, [sz]
		dec_stack(sz);
	}
	for (uint8_t i = reg & 15; i > 0; i--) { //restores preserved registers
		x86_64_enc_pop_reg(bin, bn, (i - 1) | 48); //pop [i - 1]
		dec_stack(8);
	}
}

void x86_64_enc_func_ret(uint8_t* bin, uint64_t* bn, uint16_t sz) {
	if (sz) { //removes argument stack
		x86_64_enc_add_reg_imm(bin, bn, 52, sz); //add rsp, [sz]
	}
	x86_64_enc_ret(bin, bn);
}

void x86_64_enc_cond_if(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln) {
	x86_64_enc_cmp_reg_imm(bin, bn, 48, 0); //cmp rax, 0
	x86_64_enc_je_imm(bin, bn, 10); //je 10
	
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	
	x86_64_enc_call(bin, bn, 0); //call [cond]
	
	rel[*reln + 1].addr = *bn;
	rel[*reln + 1].typ = 3;
	*reln = *reln + 2;
	
	x86_64_enc_jmp(bin, bn, 256); //jmp [end]
}

void x86_64_enc_cond_else(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln) {
	x86_64_enc_jne_imm(bin, bn, 5); //jne 5
	
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	x86_64_enc_call(bin, bn, 0); //call [str]
}

void x86_64_enc_cond_pre_while(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, struct au_sym_s* rel, uint64_t* reln) {
	x86_64_enc_jmp(bin, bn, 5); //jmp 5
	
	sym[*symn].addr = *bn;
	*symn = *symn + 1;
	
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	x86_64_enc_call(bin, bn, 0); //call [cond]
}

void x86_64_enc_cond_while(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln) {
	x86_64_enc_cmp_reg_imm(bin, bn, 48, 0); //cmp rax, 0
	
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = *reln + 1;
	
	x86_64_enc_jne_imm(bin, bn, 256); //jne -[init]
}

void x86_64_enc_add(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_add_reg_reg(bin, bn, r0 | 48, r1 | 48); //add [r0], [r1]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_sub(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_sub_reg_reg(bin, bn, r0 | 48, r1 | 48); //sub [r0], [r1]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
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

void x86_64_enc_bit_and(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_and_reg_reg(bin, bn, r0 | 48, r1 | 48); //and [r0], [r1]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_bit_or(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_or_reg_reg(bin, bn, r0 | 48, r1 | 48); //or [r0], [r1]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_bit_xor(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r1 | 48); //xor [r0], [r1]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_bit_shl(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	if ((r1 & 15) != 1) {
		uint8_t r2 = x86_64_inc_reg(reg + 1);
		if (r2 > 15) {
			x86_64_enc_push_reg(bin, bn, 49); //push rcx
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r2 | 48, 49); //mov [r2], rcx
		}
		x86_64_enc_mov_reg_reg(bin, bn, 49, r1 | 48); //mov rcx, [r1]
		x86_64_enc_shl_reg_cl(bin, bn, r0 | 48); //shl [r0], cl
		if (r2 > 15) {
			x86_64_enc_pop_reg(bin, bn, 49); //pop rcx
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 49, r2 | 48); //mov rcx, [r2]
		}
	}
	else {
		x86_64_enc_shl_reg_cl(bin, bn, r0 | 48); //shl [r0], cl
	}
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_bit_shr(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	if ((r1 & 15) != 1) {
		uint8_t r2 = x86_64_inc_reg(reg + 1);
		if (r2 > 15) {
			x86_64_enc_push_reg(bin, bn, 49); //push rcx
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r2 | 48, 49); //mov [r2], rcx
		}
		x86_64_enc_mov_reg_reg(bin, bn, 49, r1 | 48); //mov rcx, [r1]
		x86_64_enc_shr_reg_cl(bin, bn, r0 | 48); //shl [r0], cl
		if (r2 > 15) {
			x86_64_enc_pop_reg(bin, bn, 49); //pop rcx
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 49, r2 | 48); //mov rcx, [r2]
		}
	}
	else {
		x86_64_enc_shr_reg_cl(bin, bn, r0 | 48); //shr [r0], cl
	}
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_not(uint8_t* bin, uint64_t* bn, uint8_t reg) {
	reg = x86_64_inc_reg(reg);
	
	x86_64_enc_or_reg_reg(bin, bn, reg | 48, reg | 48); //or [reg], [reg]
	x86_64_enc_mov_reg_imm(bin, bn, reg | 48, 1); //mov [reg], 1
	x86_64_enc_je_imm(bin, bn, 3); //je 3
	x86_64_enc_xor_reg_reg(bin, bn, reg | 48, reg | 48); //xor [reg], [reg]
}

void x86_64_enc_log_and(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_or_reg_reg(bin, bn, r0 | 48, r0 | 48); //or [r0], [r0]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	x86_64_enc_or_reg_reg(bin, bn, r1 | 48, r1 | 48); //or [r1], [r1]
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_or(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_or_reg_reg(bin, bn, r0 | 48, r0 | 48); //or [r0], [r0]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jne_imm(bin, bn, 8); ///jne 8
	x86_64_enc_or_reg_reg(bin, bn, r1 | 48, r1 | 48); //or [r1], [r1]
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_eq(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_je_imm(bin, bn, 3); ///je 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_neq(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jne_imm(bin, bn, 3); ///jne 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_lt(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jl_imm(bin, bn, 3); ///jl 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_leq(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jle_imm(bin, bn, 3); ///j;e 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_gt(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jg_imm(bin, bn, 3); ///jg 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_log_geq(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	x86_64_enc_cmp_reg_reg(bin, bn, r0 | 48, r1 | 48); //cmp [r0], [r1]
	x86_64_enc_mov_reg_imm(bin, bn, r0 | 48, 1); //mov [r0], 1
	x86_64_enc_jge_imm(bin, bn, 3); ///jge 3
	x86_64_enc_xor_reg_reg(bin, bn, r0 | 48, r0 | 48); //xor [r0], [r0]
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_mult(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	if (r0 != 0) {
		uint8_t r2 = x86_64_inc_reg(reg + 1);
		if (r2 > 15) {
			x86_64_enc_push_reg(bin, bn, 48); //push rax
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r2 | 48, 48); //mov [r2], rax
		}
		x86_64_enc_mov_reg_reg(bin, bn, 48, r0 | 48); //mov rax, [r0]
		x86_64_enc_mul_rax_reg(bin, bn, r1 | 48); //mul rax, [r1]
		x86_64_enc_mov_reg_reg(bin, bn, r0 | 48, 48); //mov [r0], rax
		if (r2 > 15) {
			x86_64_enc_pop_reg(bin, bn, 48); //pop rax
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 48, r2 | 48); //mov rax, [r2]
		}
	}
	else {
		x86_64_enc_mul_rax_reg(bin, bn, 49); //mul rax, rcx
	}
	if (r1 > 15) {
		x86_64_enc_pop_reg(bin, bn, r1 | 48); //pop [r1]
		dec_stack(8);
	}
}

void x86_64_enc_div(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	if (r0 == 0) {
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, 49); //div rax, rcx
	}
	else if (r0 == 1) {
		x86_64_enc_mov_reg_reg(bin, bn, 51, 48); //mov rbx, rax
		x86_64_enc_mov_reg_reg(bin, bn, 53, 50); //mov rbp, rdx
		x86_64_enc_mov_reg_reg(bin, bn, 48, 49); //mov rax, rcx
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, 53); //div rax, rbp
		x86_64_enc_mov_reg_reg(bin, bn, 49, 48); //mov rcx, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, 51); //mov rax, rbx
	}
	else if (r0 == 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 48); //mov rbp, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, 50); //mov rax, rdx
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, 51); //div rax, rbx
		x86_64_enc_mov_reg_reg(bin, bn, 50, 48); //mov rdx, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, 53); //mov rax, rbp
	}
	else {
		uint8_t r2 = x86_64_inc_reg(reg + 1);
		uint8_t r3 = x86_64_inc_reg(reg + 2);
		if (r2 > 15) {
			x86_64_enc_push_reg(bin, bn, r2 | 48); //push [r2]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r2 | 48, 48); //mov [r2], rax
		}
		if (r3 > 15) {
			x86_64_enc_push_reg(bin, bn, r3 | 48); //push [r3]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r3 | 48, 50); //mov [r3], rdx
		}
		x86_64_enc_mov_reg_reg(bin, bn, 48, r0 | 48); //mov rax, [r0]
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, r1 | 48); //div rax, [r1]
		x86_64_enc_mov_reg_reg(bin, bn, r0 | 48, 48); //mov [r0], rax
		if (r3 > 15) {
			x86_64_enc_pop_reg(bin, bn, r3 | 48); //pop [r3]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 50, r3 | 48); //mov rdx, [r3]
		}
		if (r2 > 15) {
			x86_64_enc_pop_reg(bin, bn, r2 | 48); //pop [r2]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 48, r2 | 48); //mov rax, [r2]
		}
	}
	if (r1 > 15) {
		x86_64_enc_push_reg(bin, bn, r1 | 48); //push [r1]
		dec_stack(8);
	}
}

void x86_64_enc_mod(uint8_t* bin, uint64_t* bn, void (*dec_stack) (uint8_t), uint8_t reg) {
	uint8_t r0 = x86_64_inc_reg(reg - 1);
	uint8_t r1 = x86_64_inc_reg(reg);
	
	if (r0 == 0) {
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, 49); //div rax, rcx
		x86_64_enc_mov_reg_reg(bin, bn, 48, 50); //mov rax, rdx
	}
	else if (r0 == 1) {
		x86_64_enc_mov_reg_reg(bin, bn, 51, 48); //mov rbx, rax
		x86_64_enc_mov_reg_reg(bin, bn, 53, 50); //mov rbp, rdx
		x86_64_enc_mov_reg_reg(bin, bn, 48, 49); //mov rax, rcx
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, 53); //div rax, rbp
		x86_64_enc_mov_reg_reg(bin, bn, 49, 50); //mov rcx, rdx
		x86_64_enc_mov_reg_reg(bin, bn, 48, 51); //mov rax, rbx
	}
	else if (r0 == 2) {
		x86_64_enc_mov_reg_reg(bin, bn, 53, 48); //mov rbp, rax
		x86_64_enc_mov_reg_reg(bin, bn, 48, 50); //mov rax, rdx
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, 51); //div rax, rbx
		x86_64_enc_mov_reg_reg(bin, bn, 48, 53); //mov rax, rbp
	}
	else {
		uint8_t r2 = x86_64_inc_reg(reg + 1);
		uint8_t r3 = x86_64_inc_reg(reg + 2);
		if (r2 > 15) {
			x86_64_enc_push_reg(bin, bn, r2 | 48); //push [r2]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r2 | 48, 48); //mov [r2], rax
		}
		if (r3 > 15) {
			x86_64_enc_push_reg(bin, bn, r3 | 48); //push [r3]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, r3 | 48, 50); //mov [r3], rdx
		}
		x86_64_enc_mov_reg_reg(bin, bn, 48, r0 | 48); //mov rax, [r0]
		x86_64_enc_xor_reg_reg(bin, bn, 50, 50); //xor rdx, rdx
		x86_64_enc_div_rax_reg(bin, bn, r1 | 48); //div rax, [r1]
		x86_64_enc_mov_reg_reg(bin, bn, r0 | 48, 50); //mov [r0], rdx
		if (r3 > 15) {
			x86_64_enc_pop_reg(bin, bn, r3 | 48); //pop [r3]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 50, r3 | 48); //mov rdx, [r3]
		}
		if (r2 > 15) {
			x86_64_enc_pop_reg(bin, bn, r2 | 48); //pop [r2]
		}
		else {
			x86_64_enc_mov_reg_reg(bin, bn, 48, r2 | 48); //mov rax, [r2]
		}
	}
	if (r1 > 15) {
		x86_64_enc_push_reg(bin, bn, r1 | 48); //push [r1]
		dec_stack(8);
	}
}
