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

struct cu_var_s {
	uint8_t type;				//variable type
	uint8_t* name;				//variable name
	uint8_t name_n;				//name length
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

struct cu_op_s {
	uint8_t type;				//operation type
	
	struct cu_func_s* dst_scop;	//scope for destination variable
	uint64_t dst_indx;			//index for destination variable
	uint8_t dst_type;			//0 for variable, 1 for parameter, 2 for function
	
	struct cu_func_s* src_scop;	//scope for source variable
	uint64_t src_indx;			//index for source variable
	uint8_t src_type;			//0 for variable, 1 for parameter, 2 for function, 3 for immediate
	uint64_t src_imm;			//immediate
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

void x86_64_enc_mov_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
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

void x86_64_enc_shl_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint32_t k) {
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

void x86_64_comp(uint8_t* bin, uint64_t* bn, struct au_sym_s* sym, uint64_t* symn, struct au_sym_s* rel, uint64_t* reln, struct cu_func_s* scop) {
	//entry call to the main function, insert any pre-main entry code here
	rel[0].str = malloc(5);
	memcpy(rel[0].str, "main", 5);
	rel[0].len = 5;
	rel[0].addr = *bn;
	rel[0].typ = 3;
	*reln = 1;

	sym[0].str = malloc(5);
	memcpy(sym[0].str, "_ent", 5);
	sym[0].len = 5;
	sym[0].addr = *bn;
	sym[0].typ = 0;
	*symn += 1;
	
	x86_64_enc_call_imm(bin, bn, 0);
	
	sym[1].str = malloc(15);
	memcpy(sym[1].str, "_print_ret_val", 15);
	sym[1].len = 15;
	sym[1].addr = *bn;
	sym[1].typ = 0;
	*symn += 1;
	
	x86_64_enc_pop_reg(bin, bn, 48); //pop rax
	x86_64_enc_mov_reg_imm(bin, bn, 49, 10); //mov rcx, 10
	x86_64_enc_shl_reg_imm(bin, bn, 49, 8); //shl rcx, 8
	x86_64_enc_add_reg_reg(bin, bn, 49, 48); //add rcx, rax
	x86_64_enc_add_reg_imm(bin, bn, 49, 48); //add rcx, 48
	x86_64_enc_push_reg(bin, bn, 49); //push rcx 
	
	x86_64_enc_mov_reg_imm(bin, bn, 55, 1); //mov rdi, 1
	x86_64_enc_mov_reg_reg(bin, bn, 54, 52); //mov rsi, rsp
	x86_64_enc_mov_reg_imm(bin, bn, 50, 2); //mov rdx, 2
	x86_64_enc_mov_reg_imm(bin, bn, 48, 1); //mov rax, 1
	x86_64_enc_syscall(bin, bn); //syscall
	
	sym[2].str = malloc(6);
	memcpy(sym[2].str, "_exit", 6);
	sym[2].len = 6;
	sym[2].addr = *bn;
	sym[2].typ = 0;
	*symn += 1;
	
	x86_64_enc_mov_reg_imm(bin, bn, 55, 0); //mov rdi, 0
	x86_64_enc_mov_reg_imm(bin, bn, 48, 60); //mov rax, 60
	x86_64_enc_syscall(bin, bn); //syscall
	
	//functions for moving contents of register rax onto the stack

	//NOTE, these functions are not actually called, calling them would slow down execution, this is just a table for code that is regularly used throughout

	sym[3].str = malloc(7);
	memcpy(sym[3].str, "_mov_8", 7);
	sym[3].len = 7;
	sym[3].addr = *bn;
	sym[3].typ = 0;
	*symn += 1;

	x86_64_enc_pop_reg(bin, bn, 50); //pop rdx
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 52, 0); //mov rcx, (rsp)
	x86_64_enc_shl_reg_imm(bin, bn, 49, 8); //shl rcx, 8
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_add_reg_imm(bin, bn, 52, 1); //add rsp, 1
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, 0, 48); //mov (rsp), rax
	x86_64_enc_push_reg(bin, bn, 50); //push rdx
	x86_64_enc_ret(bin, bn); //ret
	
	
	sym[4].str = malloc(8);
	memcpy(sym[4].str, "_mov_16", 8);
	sym[4].len = 8;
	sym[4].addr = *bn;
	sym[4].typ = 0;
	*symn += 1;

	x86_64_enc_pop_reg(bin, bn, 50); //pop rdx
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 52, 0); //mov rcx, (rsp)
	x86_64_enc_shl_reg_imm(bin, bn, 49, 16); //shl rcx, 16
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_add_reg_imm(bin, bn, 52, 2); //add rsp, 2
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, 0, 48); //mov (rsp), rax
	x86_64_enc_push_reg(bin, bn, 50); //push rdx
	x86_64_enc_ret(bin, bn); //ret


	sym[5].str = malloc(8);
	memcpy(sym[5].str, "_mov_32", 8);
	sym[5].len = 8;
	sym[5].addr = *bn;
	sym[5].typ = 0;
	*symn += 1;
	
	x86_64_enc_pop_reg(bin, bn, 50); //pop rdx
	x86_64_enc_mov_reg_addr_disp(bin, bn, 49, 52, 0); //mov rcx, (rsp)
	x86_64_enc_shl_reg_imm(bin, bn, 49, 32); //shl rcx, 32
	x86_64_enc_or_reg_reg(bin, bn, 48, 49); //or rax, rcx
	x86_64_enc_add_reg_imm(bin, bn, 52, 4); //add rsp, 4
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, 0, 48); //mov (rsp), rax
	x86_64_enc_push_reg(bin, bn, 50); //push rdx
	x86_64_enc_ret(bin, bn); //ret
	
	sym[6].str = malloc(8);
	memcpy(sym[6].str, "_mov_64", 8);
	sym[6].len = 8;
	sym[6].addr = *bn;
	sym[6].typ = 0;
	*symn += 1;
	
	x86_64_enc_pop_reg(bin, bn, 50); //pop rdx
	x86_64_enc_add_reg_imm(bin, bn, 52, 4); //add rsp, 4
	x86_64_enc_mov_addr_disp_reg(bin, bn, 52, 0, 48); //mov (rsp), rax
	x86_64_enc_push_reg(bin, bn, 50); //push rdx
	x86_64_enc_ret(bin, bn); //ret

	
	for (uint64_t i = 0; i < scop->func_n; i++) {
		//create new symbol
		sym[*symn].str = scop->func[i].name;
		sym[*symn].len = scop->func[i].name_n;
		sym[*symn].addr = *bn;
		*symn = *symn + 1;
		
		for (uint64_t j = 0; j < scop->func[i].op_n; j++) {
			if (scop->func[i].op[j].type == 30) {
				//remove all local variables from the stack
				
				//save the return address
				x86_64_enc_pop_reg(bin, bn, 48); //pop rax
				
				//remove all parameters from the stack
				
				//push the return value onto the stack
				if (scop->func[i].op[j].src_type == 3) {
					x86_64_enc_push_imm(bin, bn, scop->func[i].op[j].src_imm); //push (return value)
				}
				
				//push the return address back onto the stack
				x86_64_enc_push_reg(bin, bn, 48); //push rax
				
				x86_64_enc_ret(bin, bn); //ret
			}
		}
		
	}
}
