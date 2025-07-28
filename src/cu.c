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

/* todo
 
 - string immediates
 - functions
 
 - array declaration
 	- single and multi dimensional
 - array loading
 - array storing
 
 - structs

*/

/* notes

 - arrays are just functions for accessing data, compiler must keep track of size of dimensions
 - structs are just arrays with irregular sized cells

*/

struct au_sym_s {
	uint8_t* str;
	uint8_t len;
	uint64_t addr;
	uint8_t typ;
};

#include "x86/x64.h"

void (*cu_writ) (uint8_t*, uint64_t, struct au_sym_s*, uint64_t, struct au_sym_s*, uint64_t, int8_t*);

void (*cu_enc_ent) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*); 

void (*cu_enc_exit) (uint8_t*, uint64_t*);

void (*cu_enc_loc_ref) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_dec_8) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_16) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_32) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_64) (uint8_t*, uint64_t*);

void (*cu_enc_loc_load_8) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_load_16) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_load_32) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_load_64) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_str_8) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_16) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_32) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_64) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_array_dec_8) (uint8_t*, uint64_t*);

void (*cu_enc_loc_array_dec_16) (uint8_t*, uint64_t*);

void (*cu_enc_loc_array_dec_32) (uint8_t*, uint64_t*);

void (*cu_enc_loc_array_dec_64) (uint8_t*, uint64_t*);

void (*cu_enc_loc_array_load_8) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_array_load_16) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_array_load_32) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_array_load_64) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_array_str_8) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_array_str_16) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_array_str_32) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_array_str_64) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_glo_ref) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_load_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_load_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_load_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_load_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_str_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_str_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_str_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_str_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_array_dec_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t, uint32_t);

void (*cu_enc_glo_array_dec_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t, uint32_t);

void (*cu_enc_glo_array_dec_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t, uint32_t);

void (*cu_enc_glo_array_dec_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t, uint32_t);

void (*cu_enc_glo_array_load_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_array_load_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_array_load_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_array_load_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_array_str_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_array_str_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_array_str_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_array_str_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_load_dref_8) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_load_dref_16) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_load_dref_32) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_load_dref_64) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_str_dref_8) (uint8_t*, uint64_t*);

void (*cu_enc_str_dref_16) (uint8_t*, uint64_t*);

void (*cu_enc_str_dref_32) (uint8_t*, uint64_t*);

void (*cu_enc_str_dref_64) (uint8_t*, uint64_t*);

void (*cu_enc_load_imm) (uint8_t*, uint64_t*, uint8_t, uint64_t);

void (*cu_enc_add) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_sub) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_inc) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_dec) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_not) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_and) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_or) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_xor) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_shl) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_shr) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_not) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_and) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_or) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_eq) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_neq) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_lt) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_leq) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_gt) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_geq) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_mult) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_div) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_mod) (uint8_t*, uint64_t*, uint8_t);

struct cu_data_s {
	uint8_t* str; 			//variable/function name
	uint8_t len; 			//string length
	uint8_t type; 			//variable/return type
	uint32_t* dim;			//size of dimensions
	uint8_t dim_n;			//number of dimensions, 0 if not array
	struct cu_data_s* mem;	//members/parameters
	uint8_t mem_n;			//number of members/parameters
	uint8_t func;			//function flag
	uint32_t indx;		 	//index into stack
	uint8_t scop;		 	//level of scope, number of braces
	uint8_t ref; 			//level of reference
};

uint64_t cu_str_int_dec(int8_t* a, int8_t* e, int8_t* path, uint64_t ln) {
	uint64_t b = 0;
	int8_t sign = 1;
	for(uint8_t i = 0; i < 20; i++) {
		if (a[i] == 0) {
			return b * sign;
		}
		b *= 10;
		if (i == 0 && a[i] == '-') {
			sign = -1;
		}
		else if (a[i] == '1') {
			b += 1;
		}
		else if (a[i] == '2') {
			b += 2;
		}
		else if (a[i] == '3') {
			b += 3;
		}
		else if (a[i] == '4') {
			b += 4;
		}
		else if (a[i] == '5') {
			b += 5;
		}
		else if (a[i] == '6') {
			b += 6;
		}
		else if (a[i] == '7') {
			b += 7;
		}
		else if (a[i] == '8') {
			b += 8;
		}
		else if (a[i] == '9') {
			b += 9;
		}
		else if (a[i] != '0') {
			printf("[%s, %lu] error: illegal character '%c'\n", path, ln, a[i]);
			*e = -1;
		}
	}
}

uint64_t cu_str_int_hex(int8_t* a, int8_t* e, int8_t* path, uint64_t ln) {
	uint64_t b = 0;
	for(uint8_t i = 0; i < 20; i++) {
		if (a[i] == 0) {
			return b;
		}
		b *= 16;
		if (a[i] == '1') {
			b += 1;
		}
		else if (a[i] == '2') {
			b += 2;
		}
		else if (a[i] == '3') {
			b += 3;
		}
		else if (a[i] == '4') {
			b += 4;
		}
		else if (a[i] == '5') {
			b += 5;
		}
		else if (a[i] == '6') {
			b += 6;
		}
		else if (a[i] == '7') {
			b += 7;
		}
		else if (a[i] == '8') {
			b += 8;
		}
		else if (a[i] == '9') {
			b += 9;
		}
		else if (a[i] == 'a') {
			b += 10;
		}
		else if (a[i] == 'b') {
			b += 11;
		}
		else if (a[i] == 'c') {
			b += 12;
		}
		else if (a[i] == 'd') {
			b += 13;
		}
		else if (a[i] == 'e') {
			b += 14;
		}
		else if (a[i] == 'f') {
			b += 15;
		}
		else if (a[i] != '0') {
			printf("[%s, %lu] error: illegal character '%c'\n", path, ln, a[i]);
			*e = -1;
		}
	}
}

uint64_t cu_str_int_char(int8_t* a, int8_t* e, int8_t* path, uint64_t ln) {
	if (a[0] == '\'' && a[1] >= 32 && a[1] <= 126 && a[1] != '\'' && a[1] != '\\' && a[2] == '\'' && a[3] == 0) {
		return a[1];
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == '0' && a[3] == '\'' && a[4] == 0) {
		return 0;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'a' && a[3] == '\'' && a[4] == 0) {
		return 7;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'b' && a[3] == '\'' && a[4] == 0) {
		return 8;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 't' && a[3] == '\'' && a[4] == 0) {
		return 9;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'n' && a[3] == '\'' && a[4] == 0) {
		return 10;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'v' && a[3] == '\'' && a[4] == 0) {
		return 11;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'f' && a[3] == '\'' && a[4] == 0) {
		return 12;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'r' && a[3] == '\'' && a[4] == 0) {
		return 13;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == 'e' && a[3] == '\'' && a[4] == 0) {
		return 27;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == '\'' && a[3] == '\'' && a[4] == 0) {
		return 39;
	}
	else if (a[0] == '\'' && a[1] == '\\' && a[2] == '\\' && a[3] == '\'' && a[4] == 0) {
		return 92;
	}
	else {
		printf("[%s, %lu] error: illegal character '%s'\n", path, ln, a);
		*e = -1;
	}
}

uint8_t cu_str_key(uint8_t* str) {
	if (!strcmp(str, "uint8_t")) {
		return 1;
	}
	else if (!strcmp(str, "uint16_t")) {
		return 2;
	}
	else if (!strcmp(str, "uint32_t")) {
		return 3;
	}
	else if (!strcmp(str, "uint64_t")) {
		return 4;
	}
	
	else if (!strcmp(str, "int8_t")) {
		return 5;
	}
	else if (!strcmp(str, "int16_t")) {
		return 6;
	}
	else if (!strcmp(str, "int32_t")) {
		return 7;
	}
	else if (!strcmp(str, "int64_t")) {
		return 8;
	}
	
	else if (!strcmp(str, "void")) {
		return 9;
	}
	
	else if (!strcmp(str, "if")) {
		return 10;
	}
	else if (!strcmp(str, "while")) {
		return 11;
	}
	else if (!strcmp(str, "for")) {
		return 12;
	}
	else if (!strcmp(str, "else")) {
		return 13;
	}
	
	else if (!strcmp(str, "break")) {
		return 14;
	}
	else if (!strcmp(str, "return")) {
		return 15;
	}

	else {
		return 0;
	}
}

void cu_lex(uint8_t* bin, uint64_t* bn, int8_t* path, struct au_sym_s* sym, uint64_t* symn, struct au_sym_s* rel, uint64_t* reln, int8_t* e) {
	int32_t fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("error: failed to open file '%s'\n", path);
		*e = -1;
        return;
    }
	
    struct stat fs;
    fstat(fd, &fs);
	
    uint8_t* fx = mmap(0, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
	
	int8_t lex[64];
	uint8_t li = 0;
	uint64_t ln = 1;
	
	uint8_t c = 0;			//comment flag
	uint8_t ch = 0;			//character flag
	
	uint8_t mod = 0;		//current mode
	// 0 - declaration
	// 1 - assignment
	uint8_t key = 0;		//current keyword
	uint8_t reg = 0;		//register
	uint8_t op[12] = {};	//operation
	uint8_t ref = 0;		//reference level
	
	uint8_t prnths_n = 0;	//level inside of parentheses
	uint8_t brackt_n = 0;	//level inside of brackets
	uint8_t braces_n = 0;	//level inside of braces
	
	struct cu_data_s stack[65536];
	uint16_t stack_n = 1;
	
	uint16_t stack_dst = 0;	//variable assignment
	uint16_t stack_ref = 0; //variable dereference
	uint8_t dref_dst = 0;	//dereference destination flag
	uint8_t dref_src = 0;	//dereference source flag
	uint8_t ref_src = 0;	//reference flag
	
	uint8_t func_dec = 0;	//function declaration flag
	uint8_t array_dec = 0;	//array declaration flag
	
	cu_enc_ent(bin, bn, rel, reln); 
	cu_enc_exit(bin, bn);
	
	void inc_stack(uint8_t sz) {
		for (uint16_t i = 1; i < stack_n; i++) {
			stack[i].indx = stack[i].indx + sz;
		}
	}
	
	void dec_stack(uint8_t scop) {
		for (uint16_t i = stack_n - 1; i > 0; i--) {
			if (stack[i].scop != scop) {
				break;
			}
			else {
				for (uint16_t j = 0; j < stack_n; j++) {
					if (stack[i].type == 1 || stack[i].type == 5) {
						stack[j].indx = stack[j].indx - 1;
					}
					else if (stack[i].type == 2 || stack[i].type == 6) {
						stack[j].indx = stack[j].indx - 2;
					}
					else if (stack[i].type == 3 || stack[i].type == 7) {
						stack[j].indx = stack[j].indx - 4;
					}
					else if (stack[i].type == 4 || stack[i].type == 8) {
						stack[j].indx = stack[j].indx - 8;
					}
				}
				free(stack[i].str);
				stack_n = stack_n - 1;
			}
		}
	}
	
	uint16_t fnd_stack(uint8_t* str) {
		for (uint16_t i = stack_n - 1; i > 0; i--) {
			if (!strcmp(stack[i].str, str)) {
				return i;
			}
		}
		return 0;
	}
	
	void load_src(uint16_t stack_src) {
		if (stack_src) {
			if (!stack[stack_src].scop && ref_src) {
				cu_enc_glo_ref(bin, bn, rel, reln, reg, stack[stack_src].str, stack[stack_src].len);
				ref_src;
			}
			else if (!stack[stack_src].scop) {
				if (stack[stack_src].ref) {
					cu_enc_glo_load_64(bin, bn, rel, reln, reg, stack[stack_src].str, stack[stack_src].len);
					if (mod == 0 && dref_dst && !stack_dst) {
						stack_dst = stack_src;
					}
					else if (dref_src && !stack_ref) {
						stack_ref = stack_src;
						dref_src = 0;
					}
				}
				else if (stack[stack_src].type == 1 || stack[stack_src].type == 5) {
					cu_enc_glo_load_8(bin, bn, rel, reln, reg, stack[stack_src].str, stack[stack_src].len);
				}
				else if (stack[stack_src].type == 2 || stack[stack_src].type == 6) {
					cu_enc_glo_load_16(bin, bn, rel, reln, reg, stack[stack_src].str, stack[stack_src].len);
				}
				else if (stack[stack_src].type == 3 || stack[stack_src].type == 7) {
					cu_enc_glo_load_32(bin, bn, rel, reln, reg, stack[stack_src].str, stack[stack_src].len);
				}
				else if (stack[stack_src].type == 4 || stack[stack_src].type == 8) {
					cu_enc_glo_load_64(bin, bn, rel, reln, reg, stack[stack_src].str, stack[stack_src].len);
				}
				
			}
			else if (ref_src) {
				cu_enc_loc_ref(bin, bn, reg, stack[stack_src].indx);
				ref_src = 0;
			}
			else {
				if (stack[stack_src].ref) {
					cu_enc_loc_load_64(bin, bn, reg, stack[stack_src].indx);
					if (mod == 0 && dref_dst && !stack_dst) {
						stack_dst = stack_src;
					}
					else if (dref_src && !stack_ref) {
						stack_ref = stack_src;
						dref_src = 0;
					}
				}
				else if (stack[stack_src].type == 1 || stack[stack_src].type == 5) {
					cu_enc_loc_load_8(bin, bn, reg, stack[stack_src].indx);
				}
				else if (stack[stack_src].type == 2 || stack[stack_src].type == 6) {
					cu_enc_loc_load_16(bin, bn, reg, stack[stack_src].indx);
				}
				else if (stack[stack_src].type == 3 || stack[stack_src].type == 7) {
					cu_enc_loc_load_32(bin, bn, reg, stack[stack_src].indx);
				}
				else if (stack[stack_src].type == 4 || stack[stack_src].type == 8) {
					cu_enc_loc_load_64(bin, bn, reg, stack[stack_src].indx);
				}
			}
		}
		else if (lex[0] == '\'') {
			uint8_t k = cu_str_int_char(lex, e, path, ln);
			cu_enc_load_imm(bin, bn, reg, k);
		}
		else {
			uint64_t k = cu_str_int_dec(lex, e, path, ln);
			cu_enc_load_imm(bin, bn, reg, k);
		}
	}
	
	void adv_assign() {
		if (op[prnths_n]) {
			if (op[prnths_n] == 1) {
				cu_enc_add(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 2) {
				cu_enc_sub(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 3) {
				load_src(stack_dst);
				cu_enc_inc(bin, bn, reg);
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 4) {
				load_src(stack_dst);
				cu_enc_dec(bin, bn, reg);
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 5) {
				cu_enc_bit_not(bin, bn, reg);
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (op[prnths_n] == 6) {
				cu_enc_bit_and(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 7) {
				cu_enc_bit_or(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 8) {
				cu_enc_bit_xor(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 9) {
				cu_enc_bit_shl(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 10) {
				cu_enc_bit_shr(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 11) {
				cu_enc_log_not(bin, bn, reg);
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (op[prnths_n] == 12) {
				cu_enc_log_and(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 13) {
				cu_enc_log_or(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 14) {
				cu_enc_log_eq(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 15) {
				cu_enc_log_neq(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 16) {
				cu_enc_log_lt(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 17) {
				cu_enc_log_leq(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 18) {
				cu_enc_log_gt(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 19) {
				cu_enc_log_geq(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 20) {
				cu_enc_mult(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 21) {
				cu_enc_div(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 22) {
				cu_enc_mod(bin, bn, reg);
				reg = reg - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 23) {
				if (!stack_ref) {
					cu_enc_load_dref_64(bin, bn, ref);
				}
				else if (stack[stack_ref].type == 1 || stack[stack_ref].type == 5) {
					cu_enc_load_dref_8(bin, bn, reg);
				}
				else if (stack[stack_ref].type == 2 || stack[stack_ref].type == 6) {
					cu_enc_load_dref_16(bin, bn, reg);
				}
				else if (stack[stack_ref].type == 3 || stack[stack_ref].type == 7) {
					cu_enc_load_dref_32(bin, bn, reg);
				}
				else if (stack[stack_ref].type == 4 || stack[stack_ref].type == 8) {
					cu_enc_load_dref_64(bin, bn, reg);
				}
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (op[prnths_n] == 24) {
				reg = reg + 1;
				op[prnths_n] = 0;
			}
		}
	}
	
	void end_assign() {
		if (op[prnths_n]) {
			adv_assign();
		}
		else if (dref_dst) {
			if (!stack_dst) {
				cu_enc_str_dref_64(bin, bn);
			}
			else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_str_dref_8(bin, bn);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_str_dref_16(bin, bn);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_str_dref_32(bin, bn);
			}
			else if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8) {
				cu_enc_str_dref_64(bin, bn);
			}
			reg = 0;
			dref_dst = 0;
		}
		else if (!stack[stack_dst].scop) {
			if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8 || stack[stack_dst].ref) {
				cu_enc_glo_str_64(bin, bn, rel, reln, stack[stack_dst].str, stack[stack_dst].len);
			}
			else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_glo_str_8(bin, bn, rel, reln, stack[stack_dst].str, stack[stack_dst].len);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_glo_str_16(bin, bn, rel, reln, stack[stack_dst].str, stack[stack_dst].len);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_glo_str_32(bin, bn, rel, reln, stack[stack_dst].str, stack[stack_dst].len);
			} 
		}
		else {
			if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8 || stack[stack_dst].ref) {
				cu_enc_loc_str_64(bin, bn, stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_loc_str_8(bin, bn, stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_loc_str_16(bin, bn, stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_loc_str_32(bin, bn, stack[stack_dst].indx);
			}
			reg = 0;
		}
		mod = 0;
	}
	
	void next_str() {
		if (mod == 1 || dref_dst) {
			load_src(fnd_stack(lex));
			adv_assign();
		}
		else if (!key && !stack_dst) {
			key = cu_str_key(lex);
			if (!key) {
				stack_dst = fnd_stack(lex);
			}
			if (!key && !stack_dst) {
				printf("[%s, %lu] error: undeclared variable  '%s'\n", path, ln, lex);
				//*e = -1;
			}
		}
		else if (key) {
			if (key == 4 || key == 8 || ref) {
				if (braces_n) {
					cu_enc_loc_dec_64(bin, bn);
				}
				else {
					cu_enc_glo_dec_64(bin, bn, sym, symn, lex, li);
				}
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n;
				stack[stack_n].ref = ref;
				inc_stack(8);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 1 || key == 5) {
				if (braces_n) {
					cu_enc_loc_dec_8(bin, bn);
				}
				else {
					cu_enc_glo_dec_8(bin, bn, sym, symn, lex, li);
				}
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n;
				stack[stack_n].ref = 0;
				inc_stack(1);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 2 || key == 6) {
				if (braces_n) {
					cu_enc_loc_dec_16(bin, bn);
				}
				else {
					cu_enc_glo_dec_16(bin, bn, sym, symn, lex, li);
				}
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n;
				stack[stack_n].ref = 0;
				inc_stack(2);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 3 || key == 7) {
				if (braces_n) {
					cu_enc_loc_dec_32(bin, bn);
				}
				else {
					cu_enc_glo_dec_32(bin, bn, sym, symn, lex, li);
				}
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n;
				stack[stack_n].ref = 0;
				inc_stack(4);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			ref = 0;
			key = 0;
		}
		lex[0] = 0;
		li = 0;
	}
	
	for (uint64_t fi = 0; fi < fs.st_size; fi++) {
		//printf("%c, %u, %u\n", fx[fi], mod, key);
		
		if (((fx[fi] >= 97 && fx[fi] <= 122) || (fx[fi] >= 48 && fx[fi] <= 57)  || (fx[fi] >= 65 && fx[fi] <= 90) || fx[fi] == '_' || (fx[fi] == '-' && fx[fi + 1] != ' ' && fx[fi + 1] != '-' && fx[fi + 1] != '-')) && !c && !ch) { //string
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == '\'') && !c) { //character
			if (ch) {
				lex[li] = fx[fi];
				lex[li + 1] = 0;
				li++;
				ch = 0;
				next_str();
			}
			else {
				if (li) {
					next_str();
				}
				lex[li] = fx[fi];
				lex[li + 1] = 0;
				li++;
				ch = 1;
			}
		}
		else if (ch) { //character
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == '"') && !c) { //string
			
		}
		else if ((fx[fi] == '+') && (fx[fi + 1] == '+') && !c && !ch) { //increment
			if (li) {
				next_str();
			}
			if (mod == 0) {
				op[prnths_n] = 3;
				mod = 1;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '+') && !c && !ch) { //addition
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) { 
				reg = reg + 1;
				op[prnths_n] = 1;
			}
			else if (mod == 2) {
				op[prnths_n] = 1;
			}
		}
		else if ((fx[fi] == '-' && fx[fi + 1] == '>') && li && !c && !ch) { //struct access (pointer)
			fi = fi + 1;
		}
		else if ((fx[fi] == '-') && (fx[fi + 1] == '-') && !c && !ch) { //decrement
			if (li) {
				next_str();
			}
			if (mod == 0) {
				//prnths_n = prnths_n + 1;
				op[prnths_n] = 4;
				mod = 1;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '-') && !c && !ch) { //subtraction
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 2;
			}
		}
		else if ((fx[fi] == '!') && (fx[fi + 1] == '=') && !c && !ch) { //logical not equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 15;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '!') && !c && !ch) { //logical not
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				prnths_n = prnths_n + 1;
				op[prnths_n] = 11;
			}	
		}
		else if ((fx[fi] == '~') && !c && !ch) { //bitwise not
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				prnths_n = prnths_n + 1;
				op[prnths_n] = 5;
			}
		}
		else if ((fx[fi] == '&') && (fx[fi + 1] == '&') && !c && !ch) { //logical and
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 12;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '&') && !c && !ch) { //reference or bitwise and
			if (li) {
				next_str();
			}
			if (mod == 1 && fx[fi + 1] != ' ' && fx[fi + 1] != '(') { //reference
				ref_src = 1;
			}
			else if (mod == 1 || dref_dst) { //bitwise and
				reg = reg + 1;
				op[prnths_n] = 6;
			}
		}
		else if ((fx[fi] == '|') && (fx[fi + 1] == '|') && !c && !ch) { //logical or
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 13;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '|') && !c && !ch) { //bitwise or
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 7;
			}
		}
		else if ((fx[fi] == '^') && !c && !ch) { //bitwise exclusive or
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 8;
			}
		}
		else if ((fx[fi] == '<') && (fx[fi + 1] == '<') && !c && !ch) { //bitwise left shift
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 9;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '<') && (fx[fi + 1] == '=') && !c && !ch) { //logical less than or equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 17;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '<') && !c && !ch) { //logical less than
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 16;
			}
		}
		else if ((fx[fi] == '>') && (fx[fi + 1] == '>') && !c && !ch) { //bitwise right shift
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 10;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '>') && (fx[fi + 1] == '=') && !c && !ch) { //logical greater than or equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 19;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '>') && !c && !ch) { //logical greater than
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 18;
			}
		}
		else if ((fx[fi] == '=') && (fx[fi + 1] == '=') && !c && !ch) { //logical equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 14;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '=') && !c && !ch) { //assignment
			if (li) {
				next_str();
			}
			mod = 1;
		}
		else if (fx[fi] == '*' && fx[fi + 1] == '/' && c == 2 && !ch) {
			c = 0;
		}
		else if ((fx[fi] == '*') && !c && !ch) { //dereference or multiplication
			if (li) {
				next_str();
			}
			if (key >= 1 && key <= 8) { //pointer declaration
				ref = ref + 1;
			}
			else if (mod == 0 && fx[fi + 1] != ' ') { //dereference destination
				prnths_n = prnths_n + 1;
				op[prnths_n] = 24;
				dref_dst = 1;
			}
			else if (mod == 1 && fx[fi + 1] != ' ') { //dereference source
				prnths_n = prnths_n + 1;
				op[prnths_n] = 23;
				dref_src = 1;
			}
			else if (mod == 1 || dref_dst) { //multiplication
				reg = reg + 1;
				op[prnths_n] = 20;
			}
		}
		else if ((fx[fi] == '/') && (fx[fi + 1] == '/') && !c && !ch) { //line comment
			c = 1;
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '/') && (fx[fi + 1] == '*') && !c && !ch) { //block comment
			c = 2;
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '/') && !c && !ch) { //division
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 21;
			}
		}
		else if ((fx[fi] == '%') && !li && !c && !ch) { //modulo
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst) {
				reg = reg + 1;
				op[prnths_n] = 22;
			}
		}
		else if (fx[fi] == '\n' && !ch) {
			if (c == 1) {
				c = 0;
			}
			ln = ln + 1;
		}
		else if ((fx[fi] == '.') && li && !c && !ch) { //struct access
			
		}
		else if ((fx[fi] == ' ') && li && !c && !ch) { //next string
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == ',') && li && !c && !ch) { //next string (parameter)
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ';') && !c && !ch) {
			if (li) {
				next_str();
			}
			if (mod == 1) {
				end_assign();
			}
			stack_dst = 0;
		}
		else if ((fx[fi] == '(') && !c && !ch) {
			if (key) {
				func_dec = 1;
			}
			if (li) {
				next_str();
			}
			prnths_n = prnths_n + 1;
		}
		else if ((fx[fi] == ')') && !c && !ch) { 
			if (li) {
				next_str();
			}
			prnths_n = prnths_n - 1;
			adv_assign();
		}
		else if ((fx[fi] == '[') && !c && !ch) { //next string (begin indexing)
			if (key) {
				array_dec = 1;
			}
			if (li) {
				next_str();
			}
			brackt_n = brackt_n + 1;
		}
		else if ((fx[fi] == ']') && !c && !ch) { //next string (end indexing)
			if (li) {
				next_str();
			}
			brackt_n = brackt_n - 1;
			adv_assign();
		}
		else if ((fx[fi] == '{') && !c && !ch) { //next string (begin function content)
			if (li) {
				next_str();
			}
			braces_n = braces_n + 1;
		}
		else if ((fx[fi] == '}') && !c && !ch) { //next string (end function content)
			if (li) {
				next_str();
			}
			if (key || stack_dst) {
				//error
			}
			else {
				dec_stack(braces_n);
			}
			braces_n = braces_n - 1;
		}
	}
	munmap(fx, fs.st_size);
}

void cu_writ_bin(uint8_t* bin, uint64_t bn, struct au_sym_s* sym, uint64_t symn, struct au_sym_s* rel, uint64_t reln, int8_t* path) {
	int32_t fd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        printf("error: failed to create file '%s'\n", path);
        return;
    }
    ftruncate(fd, bn);
    uint8_t* mem = mmap(0, bn, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	memcpy(mem, bin, bn);
	munmap(mem, bn);
	close(fd);
}

void cu_writ_zn(uint8_t* bin, uint64_t bn, struct au_sym_s* sym, uint64_t symn, struct au_sym_s* rel, uint64_t reln, int8_t* path) {
	uint64_t strsz = 0;
	for (uint8_t i = 0; i < symn; i++) {
		strsz = strsz + sym[i].len;
	}
	for (uint8_t i = 0; i < reln; i++) {
		strsz = strsz + rel[i].len;
	}
	
	uint64_t memsz = 52 + bn + (symn * 18) + (reln * 18) + strsz;
	
	int32_t fd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        printf("error: failed to create file '%s'\n", path);
        return;
    }
    ftruncate(fd, memsz);
    uint8_t* mem = mmap(0, memsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	
	uint64_t binoff = 52;
	uint64_t symoff = 52 + bn;
	uint64_t reloff = 52 + bn + (symn * 18);
	uint64_t stroff = 52 + bn + (symn * 18) + (reln * 18);
	
	memcpy(mem, "zinc", 4);
	memcpy(mem + 4, &binoff, 8);
	memcpy(mem + 12, &bn, 8);
	memcpy(mem + 20, &symoff, 8);
	memcpy(mem + 28, &symn, 8);
	memcpy(mem + 36, &reloff, 8);
	memcpy(mem + 44, &reln, 8);
	
	
	memcpy(mem + binoff, bin, bn);
	for (uint64_t i = 0; i < symn; i++) {
		memcpy(mem + symoff + (18 * i), &stroff, 8);
		memcpy(mem + symoff + (18 * i) + 8, &(sym[i].len), 1);
		memcpy(mem + symoff + (18 * i) + 9, &(sym[i].addr), 8);
		memcpy(mem + symoff + (18 * i) + 17, &(sym[i].typ), 1);
		
		memcpy(mem + stroff, sym[i].str, sym[i].len);
		stroff = stroff + sym[i].len;
	}
	
	for (uint64_t i = 0; i < reln; i++) {
		memcpy(mem + reloff + (18 * i), &stroff, 8);
		memcpy(mem + reloff + (18 * i) + 8, &(rel[i].len), 1);
		memcpy(mem + reloff + (18 * i) + 9, &(rel[i].addr), 8);
		memcpy(mem + reloff + (18 * i) + 17, &(rel[i].typ), 1);
		
		memcpy(mem + stroff, rel[i].str, rel[i].len);
		stroff = stroff + rel[i].len;
	}
	
	munmap(mem, memsz);
	close(fd);
}

int8_t main(int32_t argc, int8_t** argv) {
	if (argc != 4) {
		printf("usage: cu [architecture] [source.c] [binary.bin or link.zn]\n");
		return -1;
	}
	
	if (!strcmp(argv[1], "arm32-m")) {
		
	}
	else if (!strcmp(argv[1], "arm32-a")) {
		
	}
	else if (!strcmp(argv[1], "x86")) {
		
	}
	else if (!strcmp(argv[1], "i386")) {
		
	}
	else if (!strcmp(argv[1], "x86-64")) {
		cu_enc_ent = x86_64_enc_ent;
		cu_enc_exit = x86_64_enc_exit;
		cu_enc_loc_ref = x86_64_enc_loc_ref;
		cu_enc_loc_dec_8 = x86_64_enc_loc_dec_8;
		cu_enc_loc_dec_16 = x86_64_enc_loc_dec_16;
		cu_enc_loc_dec_32 = x86_64_enc_loc_dec_32;
		cu_enc_loc_dec_64 = x86_64_enc_loc_dec_64;
		cu_enc_loc_load_8 = x86_64_enc_loc_load_8;
		cu_enc_loc_load_16 = x86_64_enc_loc_load_16;
		cu_enc_loc_load_32 = x86_64_enc_loc_load_32;
		cu_enc_loc_load_64 = x86_64_enc_loc_load_64;
		cu_enc_loc_str_8 = x86_64_enc_loc_str_8;
		cu_enc_loc_str_16 = x86_64_enc_loc_str_16;
		cu_enc_loc_str_32 = x86_64_enc_loc_str_32;
		cu_enc_loc_str_64 = x86_64_enc_loc_str_64;
		cu_enc_loc_array_dec_8 = x86_64_enc_loc_array_dec_8;
		cu_enc_loc_array_dec_16 = x86_64_enc_loc_array_dec_16;
		cu_enc_loc_array_dec_32 = x86_64_enc_loc_array_dec_32;
		cu_enc_loc_array_dec_64 = x86_64_enc_loc_array_dec_64;
		cu_enc_loc_array_load_8 = x86_64_enc_loc_array_load_8;
		cu_enc_loc_array_load_16 = x86_64_enc_loc_array_load_16;
		cu_enc_loc_array_load_32 = x86_64_enc_loc_array_load_32;
		cu_enc_loc_array_load_64 = x86_64_enc_loc_array_load_64;
		cu_enc_loc_array_str_8 = x86_64_enc_loc_array_str_8;
		cu_enc_loc_array_str_16 = x86_64_enc_loc_array_str_16;
		cu_enc_loc_array_str_32 = x86_64_enc_loc_array_str_32;
		cu_enc_loc_array_str_64 = x86_64_enc_loc_array_str_64;
		cu_enc_glo_ref = x86_64_enc_glo_ref;
		cu_enc_glo_dec_8 = x86_64_enc_glo_dec_8;
		cu_enc_glo_dec_16 = x86_64_enc_glo_dec_16;
		cu_enc_glo_dec_32 = x86_64_enc_glo_dec_32;
		cu_enc_glo_dec_64 = x86_64_enc_glo_dec_64;
		cu_enc_glo_load_8 = x86_64_enc_glo_load_8;
		cu_enc_glo_load_16 = x86_64_enc_glo_load_16;
		cu_enc_glo_load_32 = x86_64_enc_glo_load_32;
		cu_enc_glo_load_64 = x86_64_enc_glo_load_64;
		cu_enc_glo_str_8 = x86_64_enc_glo_str_8;
		cu_enc_glo_str_16 = x86_64_enc_glo_str_16;
		cu_enc_glo_str_32 = x86_64_enc_glo_str_32;
		cu_enc_glo_str_64 = x86_64_enc_glo_str_64;
		cu_enc_glo_array_dec_8 = x86_64_enc_glo_array_dec_8;
		cu_enc_glo_array_dec_16 = x86_64_enc_glo_array_dec_16;
		cu_enc_glo_array_dec_32 = x86_64_enc_glo_array_dec_32;
		cu_enc_glo_array_dec_64 = x86_64_enc_glo_array_dec_64;
		cu_enc_glo_array_load_8 = x86_64_enc_glo_array_load_8;
		cu_enc_glo_array_load_16 = x86_64_enc_glo_array_load_16;
		cu_enc_glo_array_load_32 = x86_64_enc_glo_array_load_32;
		cu_enc_glo_array_load_64 = x86_64_enc_glo_array_load_64;
		cu_enc_glo_array_str_8 = x86_64_enc_glo_array_str_8;
		cu_enc_glo_array_str_16 = x86_64_enc_glo_array_str_16;
		cu_enc_glo_array_str_32 = x86_64_enc_glo_array_str_32;
		cu_enc_glo_array_str_64 = x86_64_enc_glo_array_str_64;
		cu_enc_load_dref_8 = x86_64_enc_load_dref_8;
		cu_enc_load_dref_16 = x86_64_enc_load_dref_16;
		cu_enc_load_dref_32 = x86_64_enc_load_dref_32;
		cu_enc_load_dref_64 = x86_64_enc_load_dref_64;
		cu_enc_str_dref_8 = x86_64_enc_str_dref_8;
		cu_enc_str_dref_16 = x86_64_enc_str_dref_16;
		cu_enc_str_dref_32 = x86_64_enc_str_dref_32;
		cu_enc_str_dref_64 = x86_64_enc_str_dref_64;
		cu_enc_load_imm = x86_64_enc_load_imm;
		cu_enc_add = x86_64_enc_add;
		cu_enc_sub = x86_64_enc_sub;
		cu_enc_inc = x86_64_enc_inc;
		cu_enc_dec = x86_64_enc_dec;
		cu_enc_bit_not = x86_64_enc_bit_not;
		cu_enc_bit_and = x86_64_enc_bit_and;
		cu_enc_bit_or = x86_64_enc_bit_or;
		cu_enc_bit_xor = x86_64_enc_bit_xor;
		cu_enc_bit_shl = x86_64_enc_bit_shl;
		cu_enc_bit_shr = x86_64_enc_bit_shr;
		cu_enc_log_not = x86_64_enc_log_not;
		cu_enc_log_and = x86_64_enc_log_and;
		cu_enc_log_or = x86_64_enc_log_or;
		cu_enc_log_eq = x86_64_enc_log_eq;
		cu_enc_log_neq = x86_64_enc_log_neq;
		cu_enc_log_lt = x86_64_enc_log_lt;
		cu_enc_log_leq = x86_64_enc_log_leq;
		cu_enc_log_gt = x86_64_enc_log_gt;
		cu_enc_log_geq = x86_64_enc_log_geq;
		cu_enc_mult = x86_64_enc_mult;
		cu_enc_div = x86_64_enc_div;
		cu_enc_mod = x86_64_enc_mod;
	}
	else {
		printf("error: unsupported architecture\n");
		return -1;
	}
	
	if (strcmp(argv[2] + strlen(argv[2]) - 2, ".c")) {
		printf("error: expected .c file\n");
		return -1;
	}
	
	if (!strcmp(argv[3] + strlen(argv[3]) - 4, ".bin")) {
		cu_writ = cu_writ_bin;
	}
	else if (!strcmp(argv[3] + strlen(argv[3]) - 3, ".zn")) {
		cu_writ = cu_writ_zn;
	}
	else {
		printf("error: invalid writput format\n");
		return -1;
	}
	
	uint8_t* bin = calloc(1000000, 1);
	uint64_t bn = 0;
	struct au_sym_s* sym = calloc(1000000, 1);
	uint64_t symn = 0;
	struct au_sym_s* rel = calloc(1000000, 1);
	uint64_t reln = 0;
	int8_t e = 0;
	
	cu_lex(bin, &bn, argv[2], sym, &symn, rel, &reln, &e);
	
	if (!e) {
		cu_writ(bin, bn, sym, symn, rel, reln, argv[3]);
	}
	
	free(bin);
	return 0;
}
