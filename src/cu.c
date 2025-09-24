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

//   soli deo gloria

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* todo
 
 - functions
	- function pointers
 - arrays
	- array declaration
 	- single and multi dimensional
 	- array loading
 	- array storing
 - structs
 - casting
 
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

void (*cu_enc_loc_ref) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void (*cu_enc_loc_dec_8) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_16) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_32) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_64) (uint8_t*, uint64_t*);

void (*cu_enc_loc_load_8) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void (*cu_enc_loc_load_16) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void (*cu_enc_loc_load_32) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void (*cu_enc_loc_load_64) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void (*cu_enc_loc_str_8) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_16) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_32) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_64) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_glo_ref) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_load_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_load_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_load_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_load_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void (*cu_enc_glo_str_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_str_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_str_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_str_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_load_dref_8) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_load_dref_16) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_load_dref_32) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_load_dref_64) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_str_dref_8) (uint8_t*, uint64_t*);

void (*cu_enc_str_dref_16) (uint8_t*, uint64_t*);

void (*cu_enc_str_dref_32) (uint8_t*, uint64_t*);

void (*cu_enc_str_dref_64) (uint8_t*, uint64_t*);

void (*cu_enc_load_dref_8_inc) (uint8_t*, uint64_t*);

void (*cu_enc_load_dref_16_inc) (uint8_t*, uint64_t*);

void (*cu_enc_load_dref_32_inc) (uint8_t*, uint64_t*);

void (*cu_enc_load_dref_64_inc) (uint8_t*, uint64_t*);

void (*cu_enc_load_imm) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint64_t);

void (*cu_enc_func_pre_call) (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint16_t);

void (*cu_enc_func_call_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void (*cu_enc_func_call_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void (*cu_enc_func_call_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void (*cu_enc_func_call_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void (*cu_enc_func_call_void) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void (*cu_enc_func_ret) (uint8_t*, uint64_t*, uint16_t);

void (*cu_enc_func_brk) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint16_t);

void (*cu_enc_inc_sp) (uint8_t*, uint64_t*, uint16_t);

void (*cu_enc_cond_if) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void (*cu_enc_cond_else) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void (*cu_enc_cond_for) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void (*cu_enc_cond_post_for) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void (*cu_enc_add) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_sub) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_inc) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_dec) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_not) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_bit_and) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_bit_or) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_bit_xor) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_bit_shl) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_bit_shr) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_not) (uint8_t*, uint64_t*, uint8_t);

void (*cu_enc_log_and) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_or) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_eq) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_neq) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_lt) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_leq) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_gt) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_log_geq) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_mult) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_div) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void (*cu_enc_mod) (uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

struct cu_data_s {
	uint8_t* str; 			//variable/function name
	uint8_t len; 			//string length
	uint8_t type; 			//variable/return type
	uint32_t* dim;			//size of dimensions
	uint8_t dim_n;			//number of dimensions, 0 if not array
	struct cu_data_s* mem;	//members/parameters
	uint8_t mem_n;			//number of members/parameters
	uint8_t flag;			//flag, 0 for variable, 1 for function, 2 for parameter
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

uint8_t cu_int_hex_char(uint64_t a) {
	a = a & 15;
	if (a == 0) {
		return '0';
	}
	else if (a == 1) {
		return '1';
	}
	else if (a == 2) {
		return '2';
	}
	else if (a == 3) {
		return '3';
	}
	else if (a == 4) {
		return '4';
	}
	else if (a == 5) {
		return '5';
	}
	else if (a == 6) {
		return '6';
	}
	else if (a == 7) {
		return '7';
	}
	else if (a == 8) {
		return '8';
	}
	else if (a == 9) {
		return '9';
	}
	else if (a == 10) {
		return 'a';
	}
	else if (a == 11) {
		return 'b';
	}
	else if (a == 12) {
		return 'c';
	}
	else if (a == 13) {
		return 'd';
	}
	else if (a == 14) {
		return 'e';
	}
	else if (a == 15) {
		return 'f';
	}
}

uint64_t cu_str_int_char(int8_t* a, int8_t* e, int8_t* path, uint64_t ln) {
	if (a[0] >= 32 && a[0] <= 126 && a[0] != '\'' && a[0] != '\\' && a[1] == 0) {
		return a[0];
	}
	else if (a[0] == '\\' && a[1] == '0' && a[2] == 0) {
		return 0;
	}
	else if (a[0] == '\\' && a[1] == 'a' && a[2] == 0) {
		return 7;
	}
	else if (a[0] == '\\' && a[1] == 'b' && a[2] == 0) {
		return 8;
	}
	else if (a[0] == '\\' && a[1] == 't' && a[2] == 0) {
		return 9;
	}
	else if (a[0] == '\\' && a[1] == 'n' && a[2] == 0) {
		return 10;
	}
	else if (a[0] == '\\' && a[1] == 'v' && a[2] == 0) {
		return 11;
	}
	else if (a[0] == '\\' && a[1] == 'f' && a[2] == 0) {
		return 12;
	}
	else if (a[0] == '\\' && a[1] == 'r' && a[2] == 0) {
		return 13;
	}
	else if (a[0] == '\\' && a[1] == 'e' && a[2] == 0) {
		return 27;
	}
	else if (a[0] == '\\' && a[1] == '\"' && a[2] == 0) {
		return 39;
	}
	else if (a[0] == '\\' && a[1] == '\'' && a[2] == 0) {
		return 39;
	}
	else if (a[0] == '\\' && a[1] == '\\' && a[2] == 0) {
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
	else if (!strcmp(str, "else")) {
		return 11;
	}
	else if (!strcmp(str, "for")) {
		return 12;
	}
	else if (!strcmp(str, "while")) {
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
	
	uint8_t c = 0;					//comment flag
	uint8_t char_flag = 0;			//character flag
	uint8_t str_flag = 0;			//string flag
	uint8_t for_flag[256] = {};		//for statement variable declaration flag
	uint16_t str_n = 0;				//number of string immediates
	uint16_t if_n = 0;				//number of if statements
	uint16_t else_n = 0;			//number of else statements
	uint16_t cond_n = 0;			//number of conditionals
	uint16_t for_n = 0;				//number of for statements
	uint16_t while_n = 0;			//number of while statements
	
	uint8_t mod = 0;				//current mode
	// 0 - declaration
	// 1 - assignment
	uint8_t key = 0;				//current keyword
	uint8_t op[256] = {};			//operation
	uint8_t ref = 0;				//reference level
	
	uint8_t prnths_n = 0;			//level inside of parentheses
	uint8_t brackt_n = 0;			//level inside of brackets
	uint8_t braces_n = 0;			//level inside of braces
	uint8_t* func_bin[256];			//function binary
	uint64_t func_bn[256];			//function binary number
	struct au_sym_s* func_sym[256];	//function symbols
	uint64_t func_symn[256];		//function symbol number
	struct au_sym_s* func_rel[256];	//function relocations
	uint64_t func_reln[256];		//function relocation number
	
	struct cu_data_s stack[65536];	//
	uint16_t stack_n = 1;			//
	uint8_t para_n = 0;				//number of parameters
	
	uint16_t stack_dst = 0;			//variable assignment
	uint16_t stack_ref = 0; 		//variable dereference
	uint8_t dref_dst = 0;			//dereference destination flag
	uint8_t dref_src = 0;			//dereference source flag
	uint8_t ref_src = 0;			//reference flag
	uint8_t ret_dst = 0;			//return flag
	uint8_t brk_dst = 0;			//break flag
	uint8_t func_dst[256] = {};		//function braces flag
	uint8_t if_dst[256] = {};		//if statement flag
	uint8_t else_dst[256] = {};		//else statament flag
	uint8_t while_dst[256] = {};	//while statement flag
	uint8_t for_dst[256] = {};		//for statement flag
	
	uint8_t func_call[256] = {};	//function call flag
	uint8_t arg_n[256] = {};		//number of arguments
	uint8_t reg[256] = {};			//register
	uint8_t reg_full[256] = {};		//register full flag
	uint8_t call_n = 0;				//number of calls
	
	uint8_t func_dec = 0;			//function declaration flag
	uint8_t para_dec = 0;			//parameter declaration flag
	uint8_t array_dec = 0;			//array declaration flag
	
	for (uint16_t i = 0; i < 256; i++) {
		func_bin[i] = calloc(1048576, 1);
		func_bn[i] = 0;
		func_sym[i] = calloc(1048576, 1);
		func_symn[i] = 0;
		func_rel[i] = calloc(1048576, 1);
		func_reln[i] = 0;
	}
	
	cu_enc_ent(func_bin[0], &(func_bn[0]), func_rel[0], &(func_reln[0])); 
	cu_enc_exit(func_bin[0], &(func_bn[0]));
	
	void inc_stack(uint8_t sz) {
		for (uint16_t i = 1; i < stack_n; i++) {
			if (stack[i].scop && (stack[i].flag != 1)) {
				stack[i].indx = stack[i].indx + sz;
			}
		}
	}
	
	void dec_stack(uint8_t sz) {
		for (uint16_t i = 1; i < stack_n; i++) {
			if (stack[i].scop && (stack[i].flag != 1)) {
				stack[i].indx = stack[i].indx - sz;
			}
		}
	}
	
	uint16_t count_stack(uint8_t scop) {
		uint16_t x = 0;
		for (uint16_t i = stack_n - 1; i > 0; i--) {
			if ((stack[i].scop == scop) && stack[i].flag != 2) {
				if (stack[i].type == 4 || stack[i].type == 8 || stack[i].ref) {
					x = x + 8;
				}
				else if (stack[i].type == 1 || stack[i].type == 5) {
					x = x + 1;
				}
				else if (stack[i].type == 2 || stack[i].type == 6) {
					x = x + 2;
				}
				else if (stack[i].type == 3 || stack[i].type == 7) {
					x = x + 4;
				}
			}
		}
		return x;
	}
	
	void rem_stack(uint8_t scop) {
		for (uint16_t i = stack_n - 1; i > 0; i--) {
			if (stack[i].scop == scop) {
				if (stack[i].type == 4 || stack[i].type == 8 || stack[i].ref) {
					dec_stack(8);
				}
				else if (stack[i].type == 1 || stack[i].type == 5) {
					dec_stack(1);
				}
				else if (stack[i].type == 2 || stack[i].type == 6) {
					dec_stack(2);
				}
				else if (stack[i].type == 3 || stack[i].type == 7) {
					dec_stack(4);
				}
				//free(stack[i].str);
				stack_n = stack_n - 1;
			}
		}
	}
	
	uint16_t find_stack(uint8_t* str) {
		for (uint16_t i = stack_n - 1; i > 0; i--) {
			if (!strcmp(stack[i].str, str)) {
				return i;
			}
		}
		return 0;
	}			
	
	uint16_t count_para(struct cu_data_s func) {
		uint16_t x = 0;
		for (uint16_t i = 0; i < func.mem_n; i++) {
			if (func.mem[i].type == 4 || func.mem[i].type == 8 || func.mem[i].ref) {
				x = x + 8;
			}
			else if (func.mem[i].type == 1 || func.mem[i].type == 5) {
				x = x + 1;
			}
			else if (func.mem[i].type == 2 || func.mem[i].type == 6) {
				x = x + 2;
			}
			else if (func.mem[i].type == 3 || func.mem[i].type == 7) {
				x = x + 4;
			}
		}
		return x;
	}
	
	uint16_t find_para(uint8_t* str) {
		for (uint16_t i = stack_n - 1; i >= (stack_n - para_n); i--) {
			if (!strcmp(stack[i].str, str)) {
				return i;
			}
		}
		return 0;
	}
	
	void load_src(uint16_t stack_src) {
		if (stack_src) {
			if ((!stack[stack_src].scop && ref_src) || (stack[stack_src].flag == 1)) {
				cu_enc_glo_ref(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], stack[stack_src].str, stack[stack_src].len);
				ref_src = 0;
			}
			else if (!stack[stack_src].scop) {
				if (stack[stack_src].ref) {
					cu_enc_glo_load_64(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], stack[stack_src].str, stack[stack_src].len);
					if (mod == 0 && dref_dst && !stack_dst) {
						stack_dst = stack_src;
					}
					else if (dref_src && !stack_ref) {
						stack_ref = stack_src;
						dref_src = 0;
					}
				}
				else if (stack[stack_src].type == 1 || stack[stack_src].type == 5) {
					cu_enc_glo_load_8(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], stack[stack_src].str, stack[stack_src].len);
				}
				else if (stack[stack_src].type == 2 || stack[stack_src].type == 6) {
					cu_enc_glo_load_16(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], stack[stack_src].str, stack[stack_src].len);
				}
				else if (stack[stack_src].type == 3 || stack[stack_src].type == 7) {
					cu_enc_glo_load_32(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], stack[stack_src].str, stack[stack_src].len);
				}
				else if (stack[stack_src].type == 4 || stack[stack_src].type == 8) {
					cu_enc_glo_load_64(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], stack[stack_src].str, stack[stack_src].len);
				}
				
			}
			else if (ref_src) {
				cu_enc_loc_ref(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], stack[stack_src].indx);
				ref_src = 0;
			}
			else {
				if (stack[stack_src].ref) {
					cu_enc_loc_load_64(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], stack[stack_src].indx);
					if (mod == 0 && dref_dst && !stack_dst) {
						stack_dst = stack_src;
					}
					else if (dref_src && !stack_ref) {
						stack_ref = stack_src;
						dref_src = 0;
					}
				}
				else if (stack[stack_src].type == 1 || stack[stack_src].type == 5) {
					cu_enc_loc_load_8(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], stack[stack_src].indx);
				}
				else if (stack[stack_src].type == 2 || stack[stack_src].type == 6) {
					cu_enc_loc_load_16(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], stack[stack_src].indx);
				}
				else if (stack[stack_src].type == 3 || stack[stack_src].type == 7) {
					cu_enc_loc_load_32(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], stack[stack_src].indx);
				}
				else if (stack[stack_src].type == 4 || stack[stack_src].type == 8) {
					cu_enc_loc_load_64(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], stack[stack_src].indx);
				}
			}
		}
		else if (char_flag) { //character immediate
			uint8_t k = cu_str_int_char(lex, e, path, ln);
			cu_enc_load_imm(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], k);
			reg_full[call_n] = 1;
		}
		else if (str_flag) { //string immediate
			func_sym[0][func_symn[0]].str = malloc(12);
			memcpy(func_sym[0][func_symn[0]].str, "__str_$$_$$_", 12);
			func_sym[0][func_symn[0]].str[6] = cu_int_hex_char(str_n >> 4);
			func_sym[0][func_symn[0]].str[7] = cu_int_hex_char(str_n);
			func_sym[0][func_symn[0]].str[9] = cu_int_hex_char(str_n >> 12);
			func_sym[0][func_symn[0]].str[10] = cu_int_hex_char(str_n >> 8);
			func_sym[0][func_symn[0]].len = 12;
			func_sym[0][func_symn[0]].addr = func_bn[0];
			func_sym[0][func_symn[0]].typ = 0;
			cu_enc_glo_ref(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), inc_stack, reg[call_n], func_sym[0][func_symn[0]].str, func_sym[0][func_symn[0]].len);
			func_symn[0] = func_symn[0] + 1;
			for (uint8_t i = 0; i < li; i++) {
				if (lex[i] == '\\') {
					i = i + 1;
					if (lex[i] == '0') {
						func_bin[0][func_bn[0]] = 0;
					}
					else if (lex[i] == 'a') {
						func_bin[0][func_bn[0]] = 7;
					}
					else if (lex[i] == 'b') {
						func_bin[0][func_bn[0]] = 8;
					}
					else if (lex[i] == 't') {
						func_bin[0][func_bn[0]] = 9;
					}
					else if (lex[i] == 'n') {
						func_bin[0][func_bn[0]] = 10;
					}
					else if (lex[i] == 'v') {
						func_bin[0][func_bn[0]] = 11;
					}
					else if (lex[i] == 'f') {
						func_bin[0][func_bn[0]] = 12;
					}
					else if (lex[i] == 'r') {
						func_bin[0][func_bn[0]] = 13;
					}
					else if (lex[i] == 'e') {
						func_bin[0][func_bn[0]] = 27;
					}
					else if (lex[i] == '\"') {
						func_bin[0][func_bn[0]] = 34;
					}
					else if (lex[i] == '\'') {
						func_bin[0][func_bn[0]] = 39;
					}
					else if (lex[i] == '\\') {
						func_bin[0][func_bn[0]] = 92;
					}
					else {
						printf("[%s, %lu] error: illegal escape code '\\%c'\n", path, ln, lex[i + 1]);
						*e = -1;
					}
				}
				else {
					func_bin[0][func_bn[0]] = lex[i];
				}
				func_bn[0] = func_bn[0] + 1;
			}
			reg_full[call_n] = 1;
			//func_bin[0][func_bn[0]] = 0;
			//func_bn[0] = func_bn[0] + 1;
			str_n = str_n + 1;
		}
		else { //number immediate
			uint64_t k = cu_str_int_dec(lex, e, path, ln);
			cu_enc_load_imm(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n], k);
			reg_full[call_n] = 1;
		}
	}
	
	void adv_assign() {
		if (op[prnths_n]) {
			if (op[prnths_n] == 1) {
				cu_enc_add(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 2) {
				cu_enc_sub(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 3) {
				if (dref_dst) {
					if (!stack_dst) {
						cu_enc_load_dref_64_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
						cu_enc_load_dref_8_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
						cu_enc_load_dref_16_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
						cu_enc_load_dref_32_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8) {
						cu_enc_load_dref_64_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
				}
				else{
					load_src(stack_dst);
				}
				cu_enc_inc(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 4) {
				if (dref_dst) {
					if (!stack_dst) {
						cu_enc_load_dref_64_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
						cu_enc_load_dref_8_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
						cu_enc_load_dref_16_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
						cu_enc_load_dref_32_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
					else if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8) {
						cu_enc_load_dref_64_inc(func_bin[braces_n], &(func_bn[braces_n]));
					}
				}
				else{
					load_src(stack_dst);
				}
				cu_enc_dec(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 5) {
				cu_enc_bit_not(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (op[prnths_n] == 6) {
				cu_enc_bit_and(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 7) {
				cu_enc_bit_or(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 8) {
				cu_enc_bit_xor(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 9) {
				cu_enc_bit_shl(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 10) {
				cu_enc_bit_shr(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 11) {
				cu_enc_log_not(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (op[prnths_n] == 12) {
				cu_enc_log_and(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 13) {
				cu_enc_log_or(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 14) {
				cu_enc_log_eq(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 15) {
				cu_enc_log_neq(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 16) {
				cu_enc_log_lt(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 17) {
				cu_enc_log_leq(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 18) {
				cu_enc_log_gt(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 19) {
				cu_enc_log_geq(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 20) {
				cu_enc_mult(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 21) {
				cu_enc_div(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 22) {
				cu_enc_mod(func_bin[braces_n], &(func_bn[braces_n]), dec_stack, reg[call_n]);
				reg[call_n] = reg[call_n] - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
			else if (op[prnths_n] == 23) {
				if (!stack_ref) {
					cu_enc_load_dref_64(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				}
				else if (stack[stack_ref].type == 1 || stack[stack_ref].type == 5) {
					cu_enc_load_dref_8(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				}
				else if (stack[stack_ref].type == 2 || stack[stack_ref].type == 6) {
					cu_enc_load_dref_16(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				}
				else if (stack[stack_ref].type == 3 || stack[stack_ref].type == 7) {
					cu_enc_load_dref_32(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				}
				else if (stack[stack_ref].type == 4 || stack[stack_ref].type == 8) {
					cu_enc_load_dref_64(func_bin[braces_n], &(func_bn[braces_n]), reg[call_n]);
				}
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (op[prnths_n] == 24) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 0;
				prnths_n = prnths_n - 1;
			}
			else if (op[prnths_n] == 25) {
				if (stack[func_call[call_n]].mem_n > arg_n[call_n]) {
					printf("[%s, %lu] error: too few arguments given to function '%s'\n", path, ln, stack[func_call[call_n]].str);
					*e = -1;
				}
				else if (stack[func_call[call_n]].mem_n < arg_n[call_n]) {
					printf("[%s, %lu] error: too many arguments given to function '%s'\n", path, ln, stack[func_call[call_n]].str);
					*e = -1;
				}
				else {
					if (stack[func_call[call_n]].type == 4 || stack[func_call[call_n]].type == 8 || stack[func_call[call_n]].ref) {
						cu_enc_func_call_64(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), dec_stack, reg[call_n - 1], stack[func_call[call_n]].str, stack[func_call[call_n]].len, count_para(stack[func_call[call_n]]));
					}
					else if (stack[func_call[call_n]].type == 1 || stack[func_call[call_n]].type == 5) {
						cu_enc_func_call_8(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), dec_stack, reg[call_n - 1], stack[func_call[call_n]].str, stack[func_call[call_n]].len, count_para(stack[func_call[call_n]]));
					}
					else if (stack[func_call[call_n]].type == 2 || stack[func_call[call_n]].type == 6) {
						cu_enc_func_call_16(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), dec_stack, reg[call_n - 1], stack[func_call[call_n]].str, stack[func_call[call_n]].len, count_para(stack[func_call[call_n]]));
					}
					else if (stack[func_call[call_n]].type == 3 || stack[func_call[call_n]].type == 7) {
						cu_enc_func_call_32(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), dec_stack, reg[call_n - 1], stack[func_call[call_n]].str, stack[func_call[call_n]].len, count_para(stack[func_call[call_n]]));
					}
					else if (stack[func_call[call_n]].type == 9) {
						if (mod == 1 || call_n > 1) {
							printf("[%s, %lu] error: function '%s' is of void return type\n", path, ln, stack[func_call[call_n]].str);
							*e = -1;
						}
						else {
							cu_enc_func_call_void(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), dec_stack, reg[call_n - 1], stack[func_call[call_n]].str, stack[func_call[call_n]].len, count_para(stack[func_call[call_n]]));
						}
					}
				}
				func_call[call_n] = 0;
				arg_n[call_n] = 0;	
				call_n = call_n - 1;
				reg_full[call_n] = 1;
				op[prnths_n] = 0;
			}
		}
	}
	
	void end_assign() {
		if (op[prnths_n]) {
			adv_assign();
		}
		if (ret_dst) {
			uint16_t sz = 0;
			for (uint8_t b = braces_n; b > 0; b = b - 1) {
				sz = sz + count_stack(b);
				if (func_dst[b]) {
					break;
				}
				else {
					sz = sz + 8; //size of return address
				}
			}
			cu_enc_func_ret(func_bin[braces_n], &(func_bn[braces_n]), sz);
			ret_dst = 0;
		}
		else if (brk_dst) {
			uint16_t sz = 0;
			for (uint8_t b = braces_n; b >= 0; b = b - 1) {
				sz = sz + count_stack(b) + 8; //size of return address
				if (for_flag[b - 1]) {
					break;
				}
				else if (b == 0) {
					printf("[%s, %lu] error: nothing to break\n", path, ln);
					*e = -1;
				}
			}
			
			for_n = for_n - 1;
			func_rel[braces_n][func_reln[braces_n]].str = malloc(12);
			memcpy(func_rel[braces_n][func_reln[braces_n]].str, "__end_$$_$$_", 12);
			func_rel[braces_n][func_reln[braces_n]].str[6] = cu_int_hex_char(for_n >> 4);
			func_rel[braces_n][func_reln[braces_n]].str[7] = cu_int_hex_char(for_n);
			func_rel[braces_n][func_reln[braces_n]].str[9] = cu_int_hex_char(for_n >> 12);
			func_rel[braces_n][func_reln[braces_n]].str[10] = cu_int_hex_char(for_n >> 8);
			func_rel[braces_n][func_reln[braces_n]].len = 12;
			for_n = for_n + 1;
			
			cu_enc_func_brk(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), sz);
			brk_dst = 0;
		}
		else if (dref_dst) {
			if (!stack_dst) {
				cu_enc_str_dref_64(func_bin[braces_n], &(func_bn[braces_n]));
			}
			else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_str_dref_8(func_bin[braces_n], &(func_bn[braces_n]));
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_str_dref_16(func_bin[braces_n], &(func_bn[braces_n]));
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_str_dref_32(func_bin[braces_n], &(func_bn[braces_n]));
			}
			else if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8) {
				cu_enc_str_dref_64(func_bin[braces_n], &(func_bn[braces_n]));
			}
			reg[call_n] = 0;
			dref_dst = 0;
		}
		else if (!stack[stack_dst].scop) {
			if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8 || stack[stack_dst].ref) {
				cu_enc_glo_str_64(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), stack[stack_dst].str, stack[stack_dst].len);
			}
			else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_glo_str_8(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), stack[stack_dst].str, stack[stack_dst].len);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_glo_str_16(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), stack[stack_dst].str, stack[stack_dst].len);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_glo_str_32(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]), stack[stack_dst].str, stack[stack_dst].len);
			} 
		}
		else {
			if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8 || stack[stack_dst].ref) {
				cu_enc_loc_str_64(func_bin[braces_n], &(func_bn[braces_n]), stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_loc_str_8(func_bin[braces_n], &(func_bn[braces_n]), stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_loc_str_16(func_bin[braces_n], &(func_bn[braces_n]), stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_loc_str_32(func_bin[braces_n], &(func_bn[braces_n]), stack[stack_dst].indx);
			}
			reg[call_n] = 0;
		}
		mod = 0;
		reg_full[call_n] = 0;
	}
		
	void load_arg() {
		if (stack[func_call[call_n]].mem[arg_n[call_n]].type == 4 || stack[func_call[call_n]].mem[arg_n[call_n]].type == 8 || stack[func_call[call_n]].mem[arg_n[call_n]].ref) {
			cu_enc_loc_str_64(func_bin[braces_n], &(func_bn[braces_n]), stack[func_call[call_n]].mem[arg_n[call_n]].indx);
		}
		else if (stack[func_call[call_n]].mem[arg_n[call_n]].type == 1 || stack[func_call[call_n]].mem[arg_n[call_n]].type == 5) {
			cu_enc_loc_str_8(func_bin[braces_n], &(func_bn[braces_n]), stack[func_call[call_n]].mem[arg_n[call_n]].indx);
		}
		else if (stack[func_call[call_n]].mem[arg_n[call_n]].type == 2 || stack[func_call[call_n]].mem[arg_n[call_n]].type == 6) {
			cu_enc_loc_str_16(func_bin[braces_n], &(func_bn[braces_n]), stack[func_call[call_n]].mem[arg_n[call_n]].indx);
		}
		else if (stack[func_call[call_n]].mem[arg_n[call_n]].type == 3 || stack[func_call[call_n]].mem[arg_n[call_n]].type == 7) {
			cu_enc_loc_str_32(func_bin[braces_n], &(func_bn[braces_n]), stack[func_call[call_n]].mem[arg_n[call_n]].indx);
		}
		reg[call_n] = 0;
		reg_full[call_n] = 0;
	}
	
	void end_cond() {
		func_sym[braces_n][func_symn[braces_n]].str = malloc(13);
		memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__cond_$$_$$_", 13);
		func_sym[braces_n][func_symn[braces_n]].str[7] = cu_int_hex_char(cond_n >> 4);
		func_sym[braces_n][func_symn[braces_n]].str[8] = cu_int_hex_char(cond_n);
		func_sym[braces_n][func_symn[braces_n]].str[10] = cu_int_hex_char(cond_n >> 12);
		func_sym[braces_n][func_symn[braces_n]].str[11] = cu_int_hex_char(cond_n >> 8);
		func_sym[braces_n][func_symn[braces_n]].len = 13;
		func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
		func_sym[braces_n][func_symn[braces_n]].typ = 0;
		func_symn[braces_n] = func_symn[braces_n] + 1;
		cond_n = cond_n + 1;
		else_dst[braces_n] = 0;
	}
	
	void next_str() {
		if (mod == 1 || dref_dst || call_n) {
			load_src(find_stack(lex));
			adv_assign();
		}
		else if (!key && !stack_dst) { //variable assignment
			key = cu_str_key(lex);
			
			if (else_dst[braces_n] && !(if_dst[braces_n]) && (key != 10) && (key != 11)) {
				end_cond();
			}
			else if (!key) {
				stack_dst = find_stack(lex);
			}
			if (!key && !stack_dst) {
				printf("[%s, %lu] error: '%s' has not been declared\n", path, ln, lex);
				*e = -1;
			}
			else if (key == 14) {
				brk_dst = 1;
				mod = 1;
				key = 0;
			}
			else if (key == 15) {
				ret_dst = 1;
				mod = 1;
				key = 0;
			}
		}
		else if (key == 11) {
			key = cu_str_key(lex);
			
			if (key == 10) {
				if (else_dst[braces_n]) {
					if_dst[braces_n] = 2;
				}
				else {
					printf("[%s, %lu] error: no prior if statement\n", path, ln);
					*e = -1;
				}
			}
			else {
				printf("[%s, %lu] error: else what?\n", path, ln);
				*e = -1;
			}
		}
		else if (key && para_dec) { //parameter declaration
			if (find_para(lex)) {
				printf("[%s, %lu] error: parameter '%s' has already been declared\n", path, ln, lex);
				*e = -1;
				ref = 0;
				key = 0;
			}
			else {
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].dim_n = 0;
				stack[stack_n].mem_n = 0;
				stack[stack_n].flag = 2;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n + 1;
				stack[stack_n].ref = ref;
				if (key == 4 || key == 8 || ref) {
					inc_stack(8);
				}
				else if (key == 1 || key == 5) {
					inc_stack(1);
				}
				else if (key == 2 || key == 6) {
					inc_stack(2);
				}
				else if (key == 3 || key == 7) {
					inc_stack(4);
				}
				stack_n = stack_n + 1;
				para_n = para_n + 1;
				ref = 0;
				key = 0;
			}
		}
		else if (key && func_dec) { //function declaration
			if (find_stack(lex)) {
				printf("[%s, %lu] error: '%s' has already been declared\n", path, ln, lex);
				*e = -1;
				ref = 0;
				key = 0;
			}
			else {
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].dim_n = 0;
				stack[stack_n].mem_n = 0;
				stack[stack_n].flag = 1;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n;
				stack[stack_n].ref = ref;
				stack_n = stack_n + 1;
				ref = 0;
				key = 0;
				para_dec = 1;
			}
		}
		else if (key) { //variable declaration
			if (find_stack(lex)) {
				printf("[%s, %lu] error: '%s' has already been declared\n", path, ln, lex);
				*e = -1;
				ref = 0;
				key = 0;
			}
			else {
				if (for_dst[braces_n]) {
					if (for_dst[braces_n] == 1) {
						for_flag[braces_n] = 1;
					}
					else {
						printf("[%s, %lu] error: cannot declare variable here\n", path, ln, lex);
						*e = -1;
					}
				}
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].len = li;
				stack[stack_n].type = key;
				stack[stack_n].dim_n = 0;
				stack[stack_n].mem_n = 0;
				stack[stack_n].flag = 0;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = braces_n;
				stack[stack_n].ref = ref;
				if (key == 4 || key == 8 || ref) {
					if (braces_n) {
						cu_enc_loc_dec_64(func_bin[braces_n], &(func_bn[braces_n]));
						inc_stack(8);
					}
					else {
						cu_enc_glo_dec_64(func_bin[braces_n], &(func_bn[braces_n]), func_sym[braces_n], &(func_symn[braces_n]), lex, li);
					}
				}
				else if (key == 1 || key == 5) {
					if (braces_n) {
						cu_enc_loc_dec_8(func_bin[braces_n], &(func_bn[braces_n]));
						inc_stack(1);
					}
					else {
						cu_enc_glo_dec_8(func_bin[braces_n], &(func_bn[braces_n]), func_sym[braces_n], &(func_symn[braces_n]), lex, li);
					}
				}
				else if (key == 2 || key == 6) {
					if (braces_n) {
						cu_enc_loc_dec_16(func_bin[braces_n], &(func_bn[braces_n]));
						inc_stack(2);
					}
					else {
						cu_enc_glo_dec_16(func_bin[braces_n], &(func_bn[braces_n]), func_sym[braces_n], &(func_symn[braces_n]), lex, li);
					}
				}
				else if (key == 3 || key == 7) {
					if (braces_n) {
						cu_enc_loc_dec_32(func_bin[braces_n], &(func_bn[braces_n]));
						inc_stack(4);
					}
					else {
						cu_enc_glo_dec_32(func_bin[braces_n], &(func_bn[braces_n]), func_sym[braces_n], &(func_symn[braces_n]), lex, li);
					}
				}
				stack_dst = stack_n;
				stack_n = stack_n + 1;
				ref = 0;
				key = 0;
			}
		}
		lex[0] = 0;
		li = 0;
	}
	
	for (uint64_t fi = 0; fi < fs.st_size; fi++) {
		//printf("[%s, %lu] %c, %u\n", path, ln, fx[fi], stack_dst);
		
		if (((fx[fi] >= 97 && fx[fi] <= 122) || (fx[fi] >= 48 && fx[fi] <= 57)  || (fx[fi] >= 65 && fx[fi] <= 90) || fx[fi] == '_' || (fx[fi] == '-' && fx[fi + 1] != ' ' && fx[fi + 1] != '-' && fx[fi + 1] != '-')) && !c && !char_flag && !str_flag) { //string
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == '\'') && !c && !str_flag && fx[fi - 1] != '\\') { //character
			if (char_flag && li) {
				next_str();
				char_flag = 0;
			}
			else if (char_flag) {
				printf("[%s, %lu] error: expected character\n", path, ln);
				*e = -1;
				char_flag = 0;
			}
			else {
				if (li) {
					next_str();
				}
				char_flag = 1;
			}
		}
		else if ((fx[fi] == '\"') && !c && !char_flag && fx[fi - 1] != '\\') { //string
			if (str_flag && li) {
				next_str();
				str_flag = 0;
			}
			else if (str_flag) {
				printf("[%s, %lu] error: expected string\n", path, ln);
				*e = -1;
				str_flag = 0;
			}
			else {
				if (li) {
					next_str();
				}
				str_flag = 1;
			}
		}
		else if (char_flag || str_flag) {
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == '+') && (fx[fi + 1] == '+') && !c && !char_flag && !str_flag) { //increment
			if (li) {
				next_str();
			}
			else if (!stack_dst && !dref_dst) {
				printf("[%s, %lu] error: nothing named to be incremented\n", path, ln);
				*e = -1;
			}
			if (mod == 0) {
				op[prnths_n] = 3;
				mod = 1;
			}
			else {
				printf("[%s, %lu] error: cannot increment within assignment\n", path, ln);
				*e = -1;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '+') && !c && !char_flag && !str_flag) { //addition
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) { 
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 1;
			}
		}
		else if ((fx[fi] == '-' && fx[fi + 1] == '>') && li && !c && !char_flag && !str_flag) { //struct access (pointer)
			fi = fi + 1;
		}
		else if ((fx[fi] == '-') && (fx[fi + 1] == '-') && !c && !char_flag && !str_flag) { //decrement
			if (li) {
				next_str();
			}
			else if (!stack_dst && !dref_dst) {
				printf("[%s, %lu] error: nothing named to be decremented\n", path, ln);
				*e = -1;
			}
			if (mod == 0) {
				op[prnths_n] = 4;
				mod = 1;
			}
			else {
				printf("[%s, %lu] error: cannot decrement within assignment\n", path, ln);
				*e = -1;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '-') && !c && !char_flag && !str_flag) { //subtraction
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 2;
			}
		}
		else if ((fx[fi] == '!') && (fx[fi + 1] == '=') && !c && !char_flag && !str_flag) { //logical not equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 15;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '!') && !c && !char_flag && !str_flag) { //logical not
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				prnths_n = prnths_n + 1;
				op[prnths_n] = 11;
			}	
		}
		else if ((fx[fi] == '~') && !c && !char_flag && !str_flag) { //bitwise not
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				prnths_n = prnths_n + 1;
				op[prnths_n] = 5;
			}
		}
		else if ((fx[fi] == '&') && (fx[fi + 1] == '&') && !c && !char_flag && !str_flag) { //logical and
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 12;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '&') && !c && !char_flag && !str_flag) { //reference or bitwise and
			if (li) {
				next_str();
			}
			if ((mod == 1 || dref_dst || call_n) && fx[fi + 1] != ' ' && fx[fi + 1] != '(') { //reference
				ref_src = 1;
			}
			else if (mod == 1 || dref_dst || call_n) { //bitwise and
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 6;
			}
		}
		else if ((fx[fi] == '|') && (fx[fi + 1] == '|') && !c && !char_flag && !str_flag) { //logical or
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 13;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '|') && !c && !char_flag && !str_flag) { //bitwise or
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 7;
			}
		}
		else if ((fx[fi] == '^') && !c && !char_flag && !str_flag) { //bitwise exclusive or
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 8;
			}
		}
		else if ((fx[fi] == '<') && (fx[fi + 1] == '<') && !c && !char_flag && !str_flag) { //bitwise left shift
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 9;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '<') && (fx[fi + 1] == '=') && !c && !char_flag && !str_flag) { //logical less than or equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 17;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '<') && !c && !char_flag && !str_flag) { //logical less than
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 16;
			}
		}
		else if ((fx[fi] == '>') && (fx[fi + 1] == '>') && !c && !char_flag && !str_flag) { //bitwise right shift
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 10;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '>') && (fx[fi + 1] == '=') && !c && !char_flag && !str_flag) { //logical greater than or equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 19;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '>') && !c && !char_flag && !str_flag) { //logical greater than
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 18;
			}
		}
		else if ((fx[fi] == '=') && (fx[fi + 1] == '=') && !c && !char_flag && !str_flag) { //logical equal to
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 14;
			}
			fi = fi + 1;
		}
		else if ((fx[fi] == '=') && !c && !char_flag && !str_flag) { //assignment
			if (li) {
				next_str();
			}
			mod = 1;
		}
		else if (fx[fi] == '*' && fx[fi + 1] == '/' && c == 2 && !char_flag && !str_flag) {
			c = 0;
		}
		else if ((fx[fi] == '*') && !c && !char_flag && !str_flag) { //dereference or multiplication
			if (li) {
				next_str();
			}
			if (key >= 1 && key <= 8) { //pointer declaration
				ref = ref + 1;
			}
			else if ((mod == 1 || call_n) && fx[fi + 1] != ' ') { //dereference source
				prnths_n = prnths_n + 1;
				op[prnths_n] = 23;
				dref_src = 1;
			}
			else if (mod == 0 && fx[fi + 1] != ' ') { //dereference destination
				prnths_n = prnths_n + 1;
				op[prnths_n] = 24;
				dref_dst = 1;
			}
			else if (mod == 1 || dref_dst || call_n) { //multiplication
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 20;
			}
		}
		else if ((fx[fi] == '/') && (fx[fi + 1] == '/') && !c && !char_flag && !str_flag) { //line comment
			c = 1;
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '/') && (fx[fi + 1] == '*') && !c && !char_flag && !str_flag) { //block comment
			c = 2;
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '/') && !c && !char_flag && !str_flag) { //division
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 21;
			}
		}
		else if ((fx[fi] == '%') && !li && !c && !char_flag && !str_flag) { //modulo
			if (li) {
				next_str();
			}
			if (mod == 1 || dref_dst || call_n) {
				reg[call_n] = reg[call_n] + 1;
				op[prnths_n] = 22;
			}
		}
		else if (fx[fi] == '\n' && !char_flag && !str_flag) {
			if (c == 1) {
				c = 0;
			}
			ln = ln + 1;
		}
		else if ((fx[fi] == '.') && li && !c && !char_flag && !str_flag) { //struct access
			
		}
		else if ((fx[fi] == ' ') && li && !c && !char_flag && !str_flag) { //next string
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == ',') && !c && !char_flag && !str_flag) { //next string (parameter)
			if (para_dec && key && li) {
				next_str();	
			}
			else if (para_dec) {
				printf("[%s, %lu] error: expected parameter\n", path, ln);
				*e = -1;
			}
			else if (call_n) {
				if (arg_n[call_n] < stack[func_call[call_n]].mem_n) {
					if (li) {
						load_src(find_stack(lex));
						adv_assign();
					}
					load_arg();
				}
				arg_n[call_n] = arg_n[call_n] + 1;
			}
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ';') && !c && !char_flag && !str_flag) {
			if (li) {
				next_str();
			}
			if (mod == 1) {
				end_assign();
			}
			if (prnths_n && !(for_dst[braces_n] && prnths_n == 1)) {
				printf("[%s, %lu] error: expected parenthesis\n", path, ln);
				*e = -1;
			}
			if (func_dec) {
				rem_stack(braces_n + 1);
				func_dec = 0;
				para_n = 0;
			}
			stack_dst = 0;
			if (for_dst[braces_n] == 1) {
				for_dst[braces_n] = 2;
				mod = 1;
				
				func_sym[braces_n][func_symn[braces_n]].str = malloc(13);
				memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__loop_$$_$$_", 13);
				func_sym[braces_n][func_symn[braces_n]].str[7] = cu_int_hex_char(for_n >> 4);
				func_sym[braces_n][func_symn[braces_n]].str[8] = cu_int_hex_char(for_n);
				func_sym[braces_n][func_symn[braces_n]].str[10] = cu_int_hex_char(for_n >> 12);
				func_sym[braces_n][func_symn[braces_n]].str[11] = cu_int_hex_char(for_n >> 8);
				func_sym[braces_n][func_symn[braces_n]].len = 13;
				func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
				func_sym[braces_n][func_symn[braces_n]].typ = 0;
				func_symn[braces_n] = func_symn[braces_n] + 1;
			}
			else if (for_dst[braces_n] == 2) {
				for_dst[braces_n] = 3;
				mod = 0;
				
				func_rel[braces_n][func_reln[braces_n]].str = malloc(12);
				memcpy(func_rel[braces_n][func_reln[braces_n]].str, "__end_$$_$$_", 12);
				func_rel[braces_n][func_reln[braces_n]].str[6] = cu_int_hex_char(for_n >> 4);
				func_rel[braces_n][func_reln[braces_n]].str[7] = cu_int_hex_char(for_n);
				func_rel[braces_n][func_reln[braces_n]].str[9] = cu_int_hex_char(for_n >> 12);
				func_rel[braces_n][func_reln[braces_n]].str[10] = cu_int_hex_char(for_n >> 8);
				func_rel[braces_n][func_reln[braces_n]].len = 12;
				
				func_rel[braces_n][func_reln[braces_n] + 1].str = malloc(12);
				memcpy(func_rel[braces_n][func_reln[braces_n] + 1].str, "__for_$$_$$_", 12);
				func_rel[braces_n][func_reln[braces_n] + 1].str[6] = cu_int_hex_char(for_n >> 4);
				func_rel[braces_n][func_reln[braces_n] + 1].str[7] = cu_int_hex_char(for_n);
				func_rel[braces_n][func_reln[braces_n] + 1].str[9] = cu_int_hex_char(for_n >> 12);
				func_rel[braces_n][func_reln[braces_n] + 1].str[10] = cu_int_hex_char(for_n >> 8);
				func_rel[braces_n][func_reln[braces_n] + 1].len = 12;
				
				cu_enc_cond_for(func_bin[braces_n], &(func_bn[braces_n]), func_rel[braces_n], &(func_reln[braces_n]));
			}
			else if (for_dst[braces_n] == 3) {
				printf("[%s, %lu] error: unexpected semi-colon\n", path, ln);
				*e = -1;
			}
		}
		else if ((fx[fi] == '(') && (fx[fi + 1] == '*') && key && !c && !char_flag && !str_flag) { //function pointer
			fi = fi + 1;
		}
		else if ((fx[fi] == '(') && !c && !char_flag && !str_flag) {
			prnths_n = prnths_n + 1;
			if (key == 10) { //if statement
				key = 0;
				mod = 1;
				if (else_dst[braces_n] && (if_dst[braces_n] != 2)) {
					end_cond();
				}
				if_dst[braces_n] = 1;
				else_dst[braces_n] = 1;
			}
			else if (key == 12) { //for statement
				key = 0;
				mod = 0;
				for_dst[braces_n] = 1;
			}
			else if (key == 13) { //while statement
				func_sym[braces_n][func_symn[braces_n]].str = malloc(13);
				memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__init_$$_$$_", 13);
				func_sym[braces_n][func_symn[braces_n]].str[7] = cu_int_hex_char(while_n >> 4);
				func_sym[braces_n][func_symn[braces_n]].str[8] = cu_int_hex_char(while_n);
				func_sym[braces_n][func_symn[braces_n]].str[10] = cu_int_hex_char(while_n >> 12);
				func_sym[braces_n][func_symn[braces_n]].str[11] = cu_int_hex_char(while_n >> 8);
				func_sym[braces_n][func_symn[braces_n]].len = 13;
				func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
				func_sym[braces_n][func_symn[braces_n]].typ = 0;
				func_symn[braces_n] = func_symn[braces_n] + 1;
				
				key = 0;
				mod = 1;
				while_dst[braces_n] = 1;
			}
			else if (li && key) { //function declaration
				func_dec = 1;
				next_str();
			}
			else if (li) { //function call
				if (else_dst[braces_n]) {
					end_cond();
				}
				op[prnths_n] = 25;
				prnths_n = prnths_n + 1;
				call_n = call_n + 1;
				func_call[call_n] = find_stack(lex);
				if (!(func_call[call_n])) {
					printf("[%s, %lu] error: '%s' has not been declared\n", path, ln, lex);
					*e = -1;
				}
				else if (stack[func_call[call_n]].flag != 1) {
					printf("[%s, %lu] error: '%s' is not a function\n", path, ln, stack[func_call[call_n]].str);
					*e = -1;
				}
				else {
					cu_enc_func_pre_call(func_bin[braces_n], &(func_bn[braces_n]), inc_stack, reg[call_n - 1], count_para(stack[func_call[call_n]]));
				}
				lex[0] = 0;
				li = 0;
			}
		}
		else if ((fx[fi] == ')') && !c && !char_flag && !str_flag) { 
			if (prnths_n == 1 && for_dst[braces_n] == 3) {
				if (li) {
					next_str();
				}
				if (mod == 1) {
					end_assign();
				}
				stack_dst = 0;
			}
			else if (li && ((op[prnths_n - 1] == 25) || (op[prnths_n - 2] == 25))) {
				if (arg_n[call_n] < stack[func_call[call_n]].mem_n) {
					load_src(find_stack(lex));
					adv_assign();
					load_arg();
				}
				prnths_n = prnths_n - 1;
				arg_n[call_n] = arg_n[call_n] + 1;
				lex[0] = 0;
				li = 0;
				adv_assign();
			}
			else if (op[prnths_n - 1] == 25) {
				if (reg_full[call_n]) {
					load_arg();
					arg_n[call_n] = arg_n[call_n] + 1;
				}
				prnths_n = prnths_n - 1;
				adv_assign();
			}
			else if (li) {
				next_str();
			}
			if (para_dec) {
				stack[(stack_n - 1) - para_n].mem = malloc(sizeof(struct cu_data_s) * (para_n));
				stack[(stack_n - 1) - para_n].mem_n = para_n;
				for (uint8_t i = 0; i < para_n; i++) {
					stack[(stack_n - 1) - para_n].mem[i].type = stack[(stack_n - para_n) + i].type;
					stack[(stack_n - 1) - para_n].mem[i].indx = stack[(stack_n - para_n) + i].indx;
					stack[(stack_n - 1) - para_n].mem[i].ref = stack[(stack_n - para_n) + i].ref;
				}
				para_dec = 0;
			}
			if (prnths_n == 0) {
				printf("[%s, %lu] error: excess parenthesis\n", path, ln);
				*e = -1;
			}
			else {
				prnths_n = prnths_n - 1;
			}
			adv_assign();
		}
		else if ((fx[fi] == '[') && !c && !char_flag && !str_flag) { //next string (begin indexing)
			if (key) {
				array_dec = 1;
			}
			if (li) {
				next_str();
			}
			brackt_n = brackt_n + 1;
		}
		else if ((fx[fi] == ']') && !c && !char_flag && !str_flag) { //next string (end indexing)
			if (li) {
				next_str();
			}
			brackt_n = brackt_n - 1;
			adv_assign();
		}
		else if ((fx[fi] == '{') && !c && !char_flag && !str_flag) { //next string (begin function content)
			if (li) {
				next_str();
			}
			braces_n = braces_n + 1;
			if (if_dst[braces_n - 1]) {
				func_sym[braces_n][func_symn[braces_n]].str = malloc(11);
				memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__if_$$_$$_", 11);
				func_sym[braces_n][func_symn[braces_n]].str[5] = cu_int_hex_char(if_n >> 4);
				func_sym[braces_n][func_symn[braces_n]].str[6] = cu_int_hex_char(if_n);
				func_sym[braces_n][func_symn[braces_n]].str[8] = cu_int_hex_char(if_n >> 12);
				func_sym[braces_n][func_symn[braces_n]].str[9] = cu_int_hex_char(if_n >> 8);
				func_sym[braces_n][func_symn[braces_n]].len = 11;
				func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
				func_sym[braces_n][func_symn[braces_n]].typ = 0;
				func_symn[braces_n] = func_symn[braces_n] + 1;
				
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str = malloc(11);
				memcpy(func_rel[braces_n - 1][func_reln[braces_n - 1]].str, "__if_$$_$$_", 11);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[5] = cu_int_hex_char(if_n >> 4);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[6] = cu_int_hex_char(if_n);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[8] = cu_int_hex_char(if_n >> 12);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[9] = cu_int_hex_char(if_n >> 8);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].len = 11;
				if_n = if_n + 1;
				
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str = malloc(13);
				memcpy(func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str, "__cond_$$_$$_", 13);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[7] = cu_int_hex_char(cond_n >> 4);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[8] = cu_int_hex_char(cond_n);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[10] = cu_int_hex_char(cond_n >> 12);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[11] = cu_int_hex_char(cond_n >> 8);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].len = 13;
				
				cu_enc_cond_if(func_bin[braces_n - 1], &(func_bn[braces_n - 1]), func_rel[braces_n - 1], &(func_reln[braces_n - 1]));
				if_dst[braces_n - 1] = 0;
				mod = 0;
				inc_stack(8); //size of return address
			}
			else if ((key == 11) && (else_dst[braces_n - 1])) {
				func_sym[braces_n][func_symn[braces_n]].str = malloc(13);
				memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__else_$$_$$_", 13);
				func_sym[braces_n][func_symn[braces_n]].str[7] = cu_int_hex_char(else_n >> 4);
				func_sym[braces_n][func_symn[braces_n]].str[8] = cu_int_hex_char(else_n);
				func_sym[braces_n][func_symn[braces_n]].str[10] = cu_int_hex_char(else_n >> 12);
				func_sym[braces_n][func_symn[braces_n]].str[11] = cu_int_hex_char(else_n >> 8);
				func_sym[braces_n][func_symn[braces_n]].len = 13;
				func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
				func_sym[braces_n][func_symn[braces_n]].typ = 0;
				func_symn[braces_n] = func_symn[braces_n] + 1;
				
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str = malloc(13);
				memcpy(func_rel[braces_n - 1][func_reln[braces_n - 1]].str, "__else_$$_$$_", 13);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[7] = cu_int_hex_char(else_n >> 4);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[8] = cu_int_hex_char(else_n);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[10] = cu_int_hex_char(else_n >> 12);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[11] = cu_int_hex_char(else_n >> 8);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].len = 13;
				else_n = else_n + 1;
				
				cu_enc_cond_else(func_bin[braces_n - 1], &(func_bn[braces_n - 1]), func_rel[braces_n - 1], &(func_reln[braces_n - 1]));
				
				func_sym[braces_n - 1][func_symn[braces_n - 1]].str = malloc(13);
				memcpy(func_sym[braces_n - 1][func_symn[braces_n - 1]].str, "__cond_$$_$$_", 13);
				func_sym[braces_n - 1][func_symn[braces_n - 1]].str[7] = cu_int_hex_char(cond_n >> 4);
				func_sym[braces_n - 1][func_symn[braces_n - 1]].str[8] = cu_int_hex_char(cond_n);
				func_sym[braces_n - 1][func_symn[braces_n - 1]].str[10] = cu_int_hex_char(cond_n >> 12);
				func_sym[braces_n - 1][func_symn[braces_n - 1]].str[11] = cu_int_hex_char(cond_n >> 8);
				func_sym[braces_n - 1][func_symn[braces_n - 1]].len = 13;
				func_sym[braces_n - 1][func_symn[braces_n - 1]].addr = func_bn[braces_n - 1];
				func_sym[braces_n - 1][func_symn[braces_n - 1]].typ = 0;
				func_symn[braces_n - 1] = func_symn[braces_n - 1] + 1;
				cond_n = cond_n + 1;
				
				else_dst[braces_n - 1] = 0;
				key = 0;
				inc_stack(8); //size of return address
			}
			else if (for_dst[braces_n - 1]) {
				if (for_dst[braces_n - 1] == 3) {
					func_sym[braces_n][func_symn[braces_n]].str = malloc(12);
					memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__for_$$_$$_", 12);
					func_sym[braces_n][func_symn[braces_n]].str[6] = cu_int_hex_char(for_n >> 4);
					func_sym[braces_n][func_symn[braces_n]].str[7] = cu_int_hex_char(for_n);
					func_sym[braces_n][func_symn[braces_n]].str[9] = cu_int_hex_char(for_n >> 12);
					func_sym[braces_n][func_symn[braces_n]].str[10] = cu_int_hex_char(for_n >> 8);
					func_sym[braces_n][func_symn[braces_n]].len = 12;
					func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
					func_sym[braces_n][func_symn[braces_n]].typ = 0;
					func_symn[braces_n] = func_symn[braces_n] + 1;
					
					func_rel[braces_n - 1][func_reln[braces_n - 1]].str = malloc(13);
					memcpy(func_rel[braces_n - 1][func_reln[braces_n - 1]].str, "__loop_$$_$$_", 13);
					func_rel[braces_n - 1][func_reln[braces_n - 1]].str[7] = cu_int_hex_char(for_n >> 4);
					func_rel[braces_n - 1][func_reln[braces_n - 1]].str[8] = cu_int_hex_char(for_n);
					func_rel[braces_n - 1][func_reln[braces_n - 1]].str[10] = cu_int_hex_char(for_n >> 12);
					func_rel[braces_n - 1][func_reln[braces_n - 1]].str[11] = cu_int_hex_char(for_n >> 8);
					func_rel[braces_n - 1][func_reln[braces_n - 1]].len = 13;
					
					cu_enc_cond_post_for(func_bin[braces_n - 1], &(func_bn[braces_n - 1]), func_rel[braces_n - 1], &(func_reln[braces_n - 1]));
					
					func_sym[braces_n - 1][func_symn[braces_n - 1]].str = malloc(12);
					memcpy(func_sym[braces_n - 1][func_symn[braces_n - 1]].str, "__end_$$_$$_", 12);
					func_sym[braces_n - 1][func_symn[braces_n - 1]].str[6] = cu_int_hex_char(for_n >> 4);
					func_sym[braces_n - 1][func_symn[braces_n - 1]].str[7] = cu_int_hex_char(for_n);
					func_sym[braces_n - 1][func_symn[braces_n - 1]].str[9] = cu_int_hex_char(for_n >> 12);
					func_sym[braces_n - 1][func_symn[braces_n - 1]].str[10] = cu_int_hex_char(for_n >> 8);
					func_sym[braces_n - 1][func_symn[braces_n - 1]].len = 12;
					func_sym[braces_n - 1][func_symn[braces_n - 1]].addr = func_bn[braces_n - 1];
					func_sym[braces_n - 1][func_symn[braces_n - 1]].typ = 0;
					func_symn[braces_n - 1] = func_symn[braces_n - 1] + 1;
					for_n = for_n + 1;
					
					for_dst[braces_n - 1] = 0;
					mod = 0;
					inc_stack(8); //size of return address
				}
				else {
					printf("[%s, %lu] error: not enough semi-colons\n", path, ln);
					*e = -1;
				}
			}
			else if (while_dst[braces_n - 1]) {
				func_sym[braces_n][func_symn[braces_n]].str = malloc(14);
				memcpy(func_sym[braces_n][func_symn[braces_n]].str, "__while_$$_$$_", 14);
				func_sym[braces_n][func_symn[braces_n]].str[8] = cu_int_hex_char(while_n >> 4);
				func_sym[braces_n][func_symn[braces_n]].str[9] = cu_int_hex_char(while_n);
				func_sym[braces_n][func_symn[braces_n]].str[11] = cu_int_hex_char(while_n >> 12);
				func_sym[braces_n][func_symn[braces_n]].str[12] = cu_int_hex_char(while_n >> 8);
				func_sym[braces_n][func_symn[braces_n]].len = 14;
				func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
				func_sym[braces_n][func_symn[braces_n]].typ = 0;
				func_symn[braces_n] = func_symn[braces_n] + 1;
				
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str = malloc(14);
				memcpy(func_rel[braces_n - 1][func_reln[braces_n - 1]].str, "__while_$$_$$_", 14);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[8] = cu_int_hex_char(while_n >> 4);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[9] = cu_int_hex_char(while_n);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[11] = cu_int_hex_char(while_n >> 12);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].str[12] = cu_int_hex_char(while_n >> 8);
				func_rel[braces_n - 1][func_reln[braces_n - 1]].len = 14;
				
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str = malloc(13);
				memcpy(func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str, "__init_$$_$$_", 13);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[7] = cu_int_hex_char(while_n >> 4);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[8] = cu_int_hex_char(while_n);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[10] = cu_int_hex_char(while_n >> 12);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].str[11] = cu_int_hex_char(while_n >> 8);
				func_rel[braces_n - 1][func_reln[braces_n - 1] + 1].len = 13;
				while_n = while_n + 1;
				
				cu_enc_cond_if(func_bin[braces_n - 1], &(func_bn[braces_n - 1]), func_rel[braces_n - 1], &(func_reln[braces_n - 1]));
				while_dst[braces_n - 1] = 0;
				mod = 0;
				inc_stack(8); //size of return address
			}
			else if (key == 11) {
				printf("[%s, %lu] error: no prior if statement\n", path, ln);
				*e = -1;
			}
			else if (func_dec) {
				func_dec = 0;
				func_sym[braces_n][func_symn[braces_n]].str = malloc(stack[(stack_n - 1) - para_n].len);
				memcpy(func_sym[braces_n][func_symn[braces_n]].str, stack[(stack_n - 1) - para_n].str, stack[(stack_n - 1) - para_n].len);
				func_sym[braces_n][func_symn[braces_n]].len = stack[(stack_n - 1) - para_n].len;
				func_sym[braces_n][func_symn[braces_n]].addr = func_bn[braces_n];
				func_sym[braces_n][func_symn[braces_n]].typ = 0;
				func_symn[braces_n] = func_symn[braces_n] + 1;
				para_n = 0;
				inc_stack(8); //size for return address
				func_dst[braces_n] = 1;
			}
		}
		else if ((fx[fi] == '}') && !c && !char_flag && !str_flag) { //next string (end function content)
			if (li) {
				next_str();
			}
			if (else_dst[braces_n]) {
				end_cond();
			}
			if (key || stack_dst) {
				
			}
			else {
				cu_enc_func_ret(func_bin[braces_n], &(func_bn[braces_n]), count_stack(braces_n));
				rem_stack(braces_n);
				dec_stack(8); //size of return address
			}
			if (func_dst[braces_n]) {
				func_dst[braces_n] = 0;
			}
			braces_n = braces_n - 1;
			if (for_flag[braces_n]) {
				stack_n = stack_n - 1;
				if (stack[stack_n].type == 4 || stack[stack_n].type == 8 || stack[stack_n].ref) {
					dec_stack(8);
					cu_enc_inc_sp(func_bin[braces_n], &(func_bn[braces_n]), 8);
				}
				else if (stack[stack_n].type == 1 || stack[stack_n].type == 5) {
					dec_stack(1);
					cu_enc_inc_sp(func_bin[braces_n], &(func_bn[braces_n]), 1);
				}
				else if (stack[stack_n].type == 2 || stack[stack_n].type == 6) {
					dec_stack(2);
					cu_enc_inc_sp(func_bin[braces_n], &(func_bn[braces_n]), 2);
				}
				else if (stack[stack_n].type == 3 || stack[stack_n].type == 7) {
					dec_stack(4);
					cu_enc_inc_sp(func_bin[braces_n], &(func_bn[braces_n]), 4);
				}
				for_flag[braces_n] = 0;
			}
		}
	}
	munmap(fx, fs.st_size);
	
	for (uint16_t i = 0; i < 256; i++) {
		memcpy(bin + *bn, func_bin[i], func_bn[i]);
		for (uint64_t j = 0; j < func_symn[i]; j++) {
			func_sym[i][j].addr = func_sym[i][j].addr + *bn;
			sym[*symn].str = func_sym[i][j].str;
			sym[*symn].len = func_sym[i][j].len;
			sym[*symn].addr = func_sym[i][j].addr;
			sym[*symn].typ = func_sym[i][j].typ;
			*symn = *symn + 1;
		}
		for (uint64_t j = 0; j < func_reln[i]; j++) {
			func_rel[i][j].addr = func_rel[i][j].addr + *bn;
			rel[*reln].str = func_rel[i][j].str;
			rel[*reln].len = func_rel[i][j].len;
			rel[*reln].addr = func_rel[i][j].addr;
			rel[*reln].typ = func_rel[i][j].typ;
			*reln = *reln + 1;
		}
		*bn = *bn + func_bn[i];
		free(func_bin[i]);
		free(func_sym[i]);
		free(func_rel[i]);
	}
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
		cu_enc_load_dref_8 = x86_64_enc_load_dref_8;
		cu_enc_load_dref_16 = x86_64_enc_load_dref_16;
		cu_enc_load_dref_32 = x86_64_enc_load_dref_32;
		cu_enc_load_dref_64 = x86_64_enc_load_dref_64;
		cu_enc_str_dref_8 = x86_64_enc_str_dref_8;
		cu_enc_str_dref_16 = x86_64_enc_str_dref_16;
		cu_enc_str_dref_32 = x86_64_enc_str_dref_32;
		cu_enc_str_dref_64 = x86_64_enc_str_dref_64;
		cu_enc_load_dref_8_inc = x86_64_enc_load_dref_8_inc;
		cu_enc_load_dref_16_inc = x86_64_enc_load_dref_16_inc;
		cu_enc_load_dref_32_inc = x86_64_enc_load_dref_32_inc;
		cu_enc_load_dref_64_inc = x86_64_enc_load_dref_64_inc;
		cu_enc_load_imm = x86_64_enc_load_imm;
		cu_enc_func_pre_call = x86_64_enc_func_pre_call;
		cu_enc_func_call_8 = x86_64_enc_func_call_8;
		cu_enc_func_call_16 = x86_64_enc_func_call_16;
		cu_enc_func_call_32 = x86_64_enc_func_call_32;
		cu_enc_func_call_64 = x86_64_enc_func_call_64;
		cu_enc_func_call_void = x86_64_enc_func_call_void;
		cu_enc_func_ret = x86_64_enc_func_ret;
		cu_enc_func_brk = x86_64_enc_func_brk;
		cu_enc_inc_sp = x86_64_enc_inc_sp;
		cu_enc_cond_if = x86_64_enc_cond_if;
		cu_enc_cond_else = x86_64_enc_cond_else;
		cu_enc_cond_for = x86_64_enc_cond_for;
		cu_enc_cond_post_for = x86_64_enc_cond_post_for;
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
	
	uint8_t* bin = calloc(16777216, 1);
	uint64_t bn = 0;
	struct au_sym_s* sym = calloc(16777216, 1);
	uint64_t symn = 0;
	struct au_sym_s* rel = calloc(16777216, 1);
	uint64_t reln = 0;
	int8_t e = 0;
	
	cu_lex(bin, &bn, argv[2], sym, &symn, rel, &reln, &e);
	
	if (!e) {
		cu_writ(bin, bn, sym, symn, rel, reln, argv[3]);
	}
	
	free(bin);
	free(sym);
	free(rel);
	return 0;
}
