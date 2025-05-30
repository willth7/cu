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

struct cu_func_s {
	uint8_t type;				//return type
	uint8_t* name;				//function name
	uint8_t name_n;				//name length
	
	struct cu_var_s* para;		//parameters
	uint8_t para_n;				//number of parameters
	
	struct cu_var_s* var;		//local variables
	uint64_t var_n;				//number of local variables
	
	struct cu_func_s* func;		//local functions
	uint64_t func_n;			//number of local functions
	
	struct cu_op_s* op;			//operations
	uint64_t op_n;				//number of operations
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

void x86_64_enc_call_k32(uint8_t* bin, uint64_t* bn, uint32_t k) {	//call with relocation
	x86_64_inst_byt(bin, bn, 232); //op
	x86_64_inst_k32(bin, bn, k); //imm
}

void x86_64_enc_mov_reg_k32(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
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

void x86_64_enc_shl_reg_k32(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
	x86_64_inst_byt(bin, bn, k); //imm
}

void x86_64_enc_add_reg_k32(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, 0, 0, r);
	x86_64_inst_byt(bin, bn, 128 + !!(r & 48));
	x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
	x86_64_inst_lcp(bin, bn, r, k); //imm
}

void x86_64_enc_push_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, 0);
	x86_64_inst_byt(bin, bn, 80 | (r & 7)); //op
}

void x86_64_enc_syscall(uint8_t* bin, uint64_t* bn) {
	x86_64_inst_byt(bin, bn, 15); //op
	x86_64_inst_byt(bin, bn, 5); //op
} 



void x86_64_comp(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, struct au_sym_s* rel, uint64_t* reln, struct cu_func_s** scop) {
	//entry call to the main function, insert any pre-main entry code here
	rel[0].str = malloc(5);
	memcpy(rel[0].str, "main", 5);
	rel[0].len = 5;
	rel[0].addr = *bn;
	*reln = 1;
	//x86_64_enc_call_k32(bin, bn, 0);
	
	x86_64_enc_mov_reg_k32(bin, bn, 55, 10); //mov rdi, 10
	x86_64_enc_shl_reg_k32(bin, bn, 55, 8); //shl rdi, 8
	x86_64_enc_add_reg_k32(bin, bn, 55, 36); //mov rdi, 36
	x86_64_enc_push_reg(bin, bn, 55); //push rdi 
	
	x86_64_enc_mov_reg_k32(bin, bn, 55, 1); //mov rdi, 1
	x86_64_enc_mov_reg_reg(bin, bn, 54, 52); //mov rsi, rsp
	x86_64_enc_mov_reg_k32(bin, bn, 50, 3); //mov rdx, 3
	x86_64_enc_mov_reg_k32(bin, bn, 48, 1); //mov rax, 1
	x86_64_enc_syscall(bin, bn); //syscall
	
	//exit system call
	x86_64_enc_mov_reg_k32(bin, bn, 55, 0); //mov rdi, 0
	x86_64_enc_mov_reg_k32(bin, bn, 48, 60); //mov rax, 60
	x86_64_enc_syscall(bin, bn); //syscall
}
