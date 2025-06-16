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

struct au_sym_s {
	uint8_t* str;
	uint8_t len;
	uint64_t addr;
	uint8_t typ;
};

void x86_64_inst_byt(uint8_t* bin, uint64_t* bn, uint8_t a) {
	bin[*bn] = a;
	(*bn)++;
}

void x86_64_prfx_leg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t r) {
	if ((r & 48) == 16) {
		bin[*bn] = 102;
		(*bn)++;
	}
	if ((b & 48) == 32) {
		bin[*bn] = 103;
		(*bn)++;
	}
}

void x86_64_prfx_rex(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1, uint8_t r2) {
	if ((r0 & 8) || (r1 & 8) || (r2 & 8) || (r2 & 48) == 48 || (r0 & 64) || (r2 & 64)) {
		bin[*bn] = 64;
		if (r0 & 8) {
			bin[*bn] |= 1;
		}
		if (r1 & 8) {
			bin[*bn] |= 2;
		}
		if (r2 & 8) {
			bin[*bn] |= 4;
		}
		if ((r2 & 48) == 48) {
			bin[*bn] |= 8;
		}
		(*bn)++;
	}
}


void x86_64_inst_mod(uint8_t* bin, uint64_t* bn, uint8_t m, uint8_t rd, uint8_t rs) {
	bin[*bn] = (m << 6) | ((rs & 7) << 3) | (rd & 7);
	(*bn)++;
}

void x86_64_inst_k16(uint8_t* bin, uint64_t* bn, uint16_t k) {
	bin[*bn] = k;
	bin[*bn + 1] = k >> 8;
	*bn += 2;
}

void x86_64_inst_k32(uint8_t* bin, uint64_t* bn, uint32_t k) {
	bin[*bn] = k;
	bin[*bn + 1] = k >> 8;
	bin[*bn + 2] = k >> 16;
	bin[*bn + 3] = k >> 24;
	*bn += 4;
}

void x86_64_inst_k64(uint8_t* bin, uint64_t* bn, uint64_t k) {
	bin[*bn] = k;
	bin[*bn + 1] = k >> 8;
	bin[*bn + 2] = k >> 16;
	bin[*bn + 3] = k >> 24;
	bin[*bn + 4] = k >> 32;
	bin[*bn + 5] = k >> 40;
	bin[*bn + 6] = k >> 48;
	bin[*bn + 7] = k >> 56;
	*bn += 8;
}

void x86_64_inst_lcp(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
	if ((r & 48) == 0) {
		x86_64_inst_byt(bin, bn, k);
	}
	else if ((r & 48) == 16) {
		x86_64_inst_k16(bin, bn, k);
	}
	else {
		x86_64_inst_k32(bin, bn, k);
	}
}

void x86_64_inst_mvp(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
	if ((r & 48) == 0) {
		x86_64_inst_byt(bin, bn, k);
	}
	else if ((r & 48) == 16) {
		x86_64_inst_k16(bin, bn, k);
	}
	else if ((r & 48) == 32) {
		x86_64_inst_k32(bin, bn, k);
	}
	else {
		x86_64_inst_k64(bin, bn, k);
	}
}

void x86_64_enc_call_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {	//call with relocation
	x86_64_inst_byt(bin, bn, 232); //op
	x86_64_inst_k32(bin, bn, k); //imm
}

void x86_64_enc_ret(uint8_t* bin, uint64_t* bn) {	//return
	x86_64_inst_byt(bin, bn, 195); //op
}

void x86_64_enc_mov_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	x86_64_prfx_leg(bin, bn, 0, 55);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, (176 + (!!(r & 48) * 8)) | (r & 7)); //op
	x86_64_inst_mvp(bin, bn, r, k); //imm
}

void x86_64_enc_mov_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	x86_64_prfx_leg(bin, bn, 0, r1);
	x86_64_prfx_rex(bin, bn, r0, 0, r1);
	x86_64_inst_byt(bin, bn, 136 + !!(r0 & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r0, r1); //modrm
}

void x86_64_enc_mov_reg_addr_disp(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1, uint32_t d) {
	if ((r1 & 7) == 4 && d == 0) {
		x86_64_prfx_leg(bin, bn, r1, r0);
 		x86_64_prfx_rex(bin, bn, r1, 0, r0);
 		x86_64_inst_byt(bin, bn, 138 + !!(r0 & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else {
		x86_64_prfx_leg(bin, bn, r1, r0);
 		x86_64_prfx_rex(bin, bn, 0, 0, r0);
 		x86_64_inst_byt(bin, bn, 138 + !!(r0 & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_mov_addr_disp_reg(uint8_t* bin, uint64_t* bn, uint8_t r0, uint32_t d, uint8_t r1) {
	if ((r0 & 7) == 4 && d == 0) {
		x86_64_prfx_leg(bin, bn, r0, r1);
 		x86_64_prfx_rex(bin, bn, r0, 0, r1);
 		x86_64_inst_byt(bin, bn, 136 + !!(r1 & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r1); //modrm
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else {
		x86_64_prfx_leg(bin, bn, r0, r1);
 		x86_64_prfx_rex(bin, bn, 0, 0, r1);
 		x86_64_inst_byt(bin, bn, 136 + !!(r1 & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_lea_reg_addr_disp(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1, uint32_t d) {
	x86_64_prfx_leg(bin, bn, r1, r0);
 	x86_64_prfx_rex(bin, bn, 0, 0, r0);
 	x86_64_inst_byt(bin, bn, 141 + !!(r0 & 48)); //op
 	x86_64_inst_mod(bin, bn, 0, 5, r0); //modrm
 	x86_64_inst_k32(bin, bn, d); //disp
}
void x86_64_enc_shl_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t k) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
	x86_64_inst_byt(bin, bn, k); //imm
}

void x86_64_enc_add_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
	if (r & 15 == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 4 + !!(r & 48));
		x86_64_inst_lcp(bin, bn, r, k); //modrm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 131);
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48));
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_and_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
	if (r & 15 == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 36 + !!(r & 48));
		x86_64_inst_lcp(bin, bn, r, k); //modrm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 131);
		x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48));
		x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_add_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	x86_64_prfx_leg(bin, bn, 0, r1);
	x86_64_prfx_rex(bin, bn, r0, 0, r1);
	x86_64_inst_byt(bin, bn, 0 + !!(r0 & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r0, r1); //modrm
}

void x86_64_enc_or_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t r0, uint8_t r1) {
	x86_64_prfx_leg(bin, bn, 0, r1);
	x86_64_prfx_rex(bin, bn, r0, 0, r1);
	x86_64_inst_byt(bin, bn, 8 + !!(r0 & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r0, r1); //modrm
}

void x86_64_enc_push_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, 0);
	x86_64_inst_byt(bin, bn, 80 | (r & 7)); //op
}

void x86_64_enc_push_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 106); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 104); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_pop_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, 0);
	x86_64_inst_byt(bin, bn, 88 | (r & 7)); //op
}

void x86_64_enc_syscall(uint8_t* bin, uint64_t* bn) {
	x86_64_inst_byt(bin, bn, 15); //op
	x86_64_inst_byt(bin, bn, 5); //op
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

void x86_64_enc_ent(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln) {
	rel[*reln].str = malloc(5);
	memcpy(rel[*reln].str, "main", 5);
	rel[*reln].len = 5;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 3;
	*reln = 1;
	
	x86_64_enc_call_imm(bin, bn, 0);
}

void x86_64_enc_exit(uint8_t* bin, uint64_t* bn) {
	x86_64_enc_mov_reg_imm(bin, bn, 55, 0); //mov rdi, 0
	x86_64_enc_mov_reg_imm(bin, bn, 48, 60); //mov rax, 60
	x86_64_enc_syscall(bin, bn); //syscall
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

void x86_64_enc_load_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t reg, uint64_t k) {
	x86_64_enc_mov_reg_imm(bin, bn, reg | 48, k); //mov [reg], [imm]
}

void x86_64_enc_loc_load_reg_8(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, reg | 48, 52, indx); //mov [reg], (rsp, [indx])
	x86_64_enc_and_reg_imm(bin, bn, reg | 48, 255); //and [reg], 255
}

void x86_64_enc_loc_load_reg_16(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, reg | 48, 52, indx); //mov [reg], (rsp, [indx])
	x86_64_enc_and_reg_imm(bin, bn, reg | 48, 65535); //and [reg], 65535
}

void x86_64_enc_loc_load_reg_32(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, reg | 48, 52, indx); //mov [reg], (rsp, [indx])
	x86_64_enc_and_reg_imm(bin, bn, reg | 48, 4294967295); //and [reg], 4294967295
}

void x86_64_enc_loc_load_reg_64(uint8_t* bin, uint64_t* bn, uint8_t reg, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, reg | 48, 52, indx); //mov [reg], (rsp, [indx])
}

void x86_64_enc_loc_str_8(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 52, indx + 1); //mov rcx, (rsp, [indx + 1])
	x86_64_enc_shl_reg_imm(bin, bn, 49, 8); //shl rcx, 8
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, indx, 48); //mov (rsp, [indx]), rax
}

void x86_64_enc_loc_str_16(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 52, indx + 2); //mov rcx, (rsp, [indx + 2])
	x86_64_enc_shl_reg_imm(bin, bn, 49, 16); //shl rcx, 16
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, indx, 48); //mov (rsp, [indx]), rax
}

void x86_64_enc_loc_str_32(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 52, indx + 4); //mov rcx, (rsp, [indx + 4])
	x86_64_enc_shl_reg_imm(bin, bn, 49, 32); //shl rcx, 32
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, indx, 48); //mov (rsp, [indx]), rax
}

void x86_64_enc_loc_str_64(uint8_t* bin, uint64_t* bn, uint32_t indx) {
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, indx, 48); //mov (rsp, [indx]), rax
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

void x86_64_enc_glo_str_8(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	//lea rdx, (rip, [rel])
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 50, 1); //mov rcx, (rdx, 1)
	x86_64_enc_shl_reg_imm(bin, bn, 49, 8); //shl rcx, 8
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_mov_addr_disp_reg(bin, bn, 50, 0, 48); //mov (rdx), rax
}

void x86_64_enc_glo_str_16(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	//lea rdx, (rip, [rel])
	//mov rcx, (rdx, 2)
	//shl rcx, 16
	//or rax, rcx
	//mov (rdx), rax
}

void x86_64_enc_glo_str_32(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	//lea rdx, (rip, [rel])
	//mov rcx, (rdx, 4)
	//shl rcx, 32
	//or rax, rcx
	//mov (rdx), rax
}

void x86_64_enc_glo_str_64(uint8_t* bin, uint64_t* bn, struct au_sym_s* rel, uint64_t* reln, uint8_t* str, uint8_t strn) {
	rel[*reln].str = malloc(strn);
	memcpy(rel[*reln].str, str, strn);
	rel[*reln].len = strn;
	rel[*reln].addr = *bn;
	rel[*reln].typ = 4;
	*reln = *reln + 1;
	
	//lea rdx, (rip, [rel])
	//mov (rdx), rax
}
