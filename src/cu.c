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

#include "x86/x64.h"

void (*cu_writ) (uint8_t*, uint64_t, struct au_sym_s*, uint64_t, struct au_sym_s*, uint64_t, int8_t*);

void (*cu_enc_ent) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*); 

void (*cu_enc_exit) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_8) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_16) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_32) (uint8_t*, uint64_t*);

void (*cu_enc_loc_dec_64) (uint8_t*, uint64_t*);

void (*cu_enc_load_reg_imm) (uint8_t*, uint64_t*, uint8_t, uint64_t);

void (*cu_enc_loc_load_reg_8) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_load_reg_16) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_load_reg_32) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_load_reg_64) (uint8_t*, uint64_t*, uint8_t, uint32_t);

void (*cu_enc_loc_str_8) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_16) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_32) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_loc_str_64) (uint8_t*, uint64_t*, uint32_t);

void (*cu_enc_glo_dec_8) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_16) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_32) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void (*cu_enc_glo_dec_64) (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);


struct cu_var_s {
	uint8_t* str; //variable name
	uint8_t type; //variable type
	uint32_t indx; //index into stack
	uint8_t scop; //level of scope, number of brackets
};

/*	operation types

	0	null
	
	1	declare 1 byte
	2	declare 2 bytes
	3	declare 4 bytes
	4	declare 8 bytes
	
	5	move 1 byte
	6	move 2 bytes
	7	move 4 bytes
	8	move 8 bytes
	
	9	call					//function out of scope
	10	branch					//function in scope
	
	11	add
	12	subtract
	
	13	bitwise not
	14	bitwise and
	15	bitwise or
	16	bitwise exclusive or
	17	bitwise left shift
	18	bitwise right shift
	
	19	logical not
	20	logical and
	21	logical or
	22	logical equal to
	23	logical greater than
	24	logical less than
	25	logical greater than or equal to
	26	logical less than or equal to
	
	27	multiply
	28	divide
	29	modulo
	
	30 return

*/

/*	operation classes

	declaration (move stack pointer for memory)
		the compiler must keep track of this variable independently from the order in which it is declared
	
	assignment (move something to something)
		the compiler doesn't care what is being assigned in itself, only from whom to whom
		
	binary operations (do something to something)
		this can be nested, and must be, within an assignment
	
	function calling (jump to code, parameters in tow)
		the compiler must keep track that all parameters are given, no more, no less
		"assigning" value to parameters?
		
*/

uint64_t cu_str_int_dec(int8_t* a, int8_t* e, int8_t* path, uint64_t ln) {
	uint64_t b = 0;
	int8_t sign = 1;
	for(uint8_t i = 0; i < 20; i++) {
		if (a[i] == 0 || a[i] == ')') {
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
		else if (a[i] != '0' && a[i] != ')') {
			printf("[%s, %lu] error: illegal character '%c'\n", path, ln, a[i]);
			*e = -1;
		}
	}
}

uint64_t cu_str_int_hex(int8_t* a, int8_t* e, int8_t* path, uint64_t ln) {
	uint64_t b = 0;
	for(uint8_t i = 0; i < 20; i++) {
		if (a[i] == 0 || a[i] == ')') {
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
		else if (a[i] != '0' && a[i] != ')') {
			printf("[%s, %lu] error: illegal character '%c'\n", path, ln, a[i]);
			*e = -1;
		}
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
	
	else if (!strcmp(str, "uint8_t*")) {
		return 9;
	}
	else if (!strcmp(str, "uint16_t*")) {
		return 10;
	}
	else if (!strcmp(str, "uint32_t*")) {
		return 11;
	}
	else if (!strcmp(str, "uin64_t*")) {
		return 12;
	}
	
	else if (!strcmp(str, "int8_t*")) {
		return 13;
	}
	else if (!strcmp(str, "int16_t*")) {
		return 14;
	}
	else if (!strcmp(str, "int32_t*")) {
		return 15;
	}
	else if (!strcmp(str, "int64_t*")) {
		return 16;
	}
	
	else if (!strcmp(str, "void")) {
		return 17;
	}
	
	else if (!strcmp(str, "if")) {
		
	}
	else if (!strcmp(str, "while")) {
		
	}
	else if (!strcmp(str, "for")) {
		
	}
	else if (!strcmp(str, "else")) {
		
	}
	
	else if (!strcmp(str, "return")) {
		return 30;
	}
	else if (!strcmp(str, "break")) {
		
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
	uint64_t ln = 0;
	int8_t c = 0;
	
	uint8_t mod = 0;		//current mode
	// 0 - declaration
	// 1 - assignment
	uint8_t key = 0;		//current keyword
	
	uint8_t brackt_n = 0;	//level inside of brackets
	uint8_t prnths_n = 0;	//level inside of parentheses
	
	struct cu_var_s stack[65536];
	uint16_t stack_n = 1;

	uint16_t stack_dst = 0; //variable assignment
	
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

	void end_assign() {
		if (!stack[stack_dst].scop) {
			if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
				}
			else if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8) {
				//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
			}
		}
		else {
			if (stack[stack_dst].type == 1 || stack[stack_dst].type == 5) {
				cu_enc_loc_str_8(bin, bn, stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 2 || stack[stack_dst].type == 6) {
				cu_enc_loc_str_16(bin, bn, stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 3 || stack[stack_dst].type == 7) {
				cu_enc_loc_str_32(bin, bn, stack[stack_dst].indx);
			}
			else if (stack[stack_dst].type == 4 || stack[stack_dst].type == 8) {
				cu_enc_loc_str_64(bin, bn, stack[stack_dst].indx);
			}
		}
		mod = 0;
	}
	
	void next_str() {
		if (mod == 1) {
			uint16_t stack_src = fnd_stack(lex);
			if (stack_src) {
				if (!stack[stack_src].scop) {
					if (stack[stack_src].type == 1 || stack[stack_src].type == 5) {
						//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
					}
					else if (stack[stack_src].type == 2 || stack[stack_src].type == 6) {
						//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
					}
					else if (stack[stack_src].type == 3 || stack[stack_src].type == 7) {
						//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
					}
					else if (stack[stack_src].type == 4 || stack[stack_src].type == 8) {
						//cu_enc_glo_load_reg_8(bin, bn, rel, reln);
					}
				}
				else {
					if (stack[stack_src].type == 1 || stack[stack_src].type == 5) {
						cu_enc_loc_load_reg_8(bin, bn, 0, stack[stack_src].indx);
					}
					else if (stack[stack_src].type == 2 || stack[stack_src].type == 6) {
						cu_enc_loc_load_reg_16(bin, bn, 0, stack[stack_src].indx);
					}
					else if (stack[stack_src].type == 3 || stack[stack_src].type == 7) {
						cu_enc_loc_load_reg_32(bin, bn, 0, stack[stack_src].indx);
					}
					else if (stack[stack_src].type == 4 || stack[stack_src].type == 8) {
						cu_enc_loc_load_reg_64(bin, bn, 0, stack[stack_src].indx);
					}
				}
			}
			else {
				uint64_t k = cu_str_int_dec(lex, e, path, ln);
				cu_enc_load_reg_imm(bin, bn, 0, k);
			}
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
		else if (key && !brackt_n) {
			if (key == 1 || key == 5) {
				cu_enc_glo_dec_8(bin, bn, sym, symn, lex, li);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(1);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 2 || key == 6) {
				cu_enc_glo_dec_16(bin, bn, sym, symn, lex, li);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(2);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 3 || key == 7) {
				cu_enc_glo_dec_32(bin, bn, sym, symn, lex, li);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(4);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 4 || key == 8) {
				cu_enc_glo_dec_64(bin, bn, sym, symn, lex, li);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(8);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			key = 0;
		}
		else if (key && brackt_n) {
			if (key == 1 || key == 5) {
				cu_enc_loc_dec_8(bin, bn);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(1);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 2 || key == 6) {
				cu_enc_loc_dec_16(bin, bn);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(2);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 3 || key == 7) {
				cu_enc_loc_dec_32(bin, bn);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(4);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			else if (key == 4 || key == 8) {
				cu_enc_loc_dec_64(bin, bn);
				
				stack[stack_n].str = malloc(li);
				memcpy(stack[stack_n].str, lex, li);
				stack[stack_n].type = key;
				stack[stack_n].indx = 0;
				stack[stack_n].scop = brackt_n;
				inc_stack(8);
				stack_dst = stack_n;
				stack_n = stack_n + 1;
			}
			key = 0;
		}
		lex[0] = 0;
		li = 0;
	}
	
	for (uint64_t fi = 0; fi < fs.st_size; fi++) {
		//printf("%c, %u, %u\n", fx[fi], mod, key);
		
		if (((fx[fi] >= 97 && fx[fi] <= 122) || (fx[fi] >= 48 && fx[fi] <= 57)  || (fx[fi] >= 65 && fx[fi] <= 90) || fx[fi] == '_' || fx[fi] == '-') && !c) { //string
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == '+') && (fx[fi + 1] == '=') && !c) { //addition compounded assignment
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '+') && (fx[fi + 1] == '+') && !c) { //increment
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '+') && !c) { //addition
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '-' && fx[fi + 1] == '>') && li && !c) { //struct access (pointer)
			
		}
		else if ((fx[fi] == '-') && (fx[fi + 1] == '=') && !c) { //subtraction compounded assignment
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '-') && (fx[fi + 1] == '-') && !c) { //decrement
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '-') && !c) { //subtraction
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '!') && !c) { //logical not
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '~') && !c) { //bitwise not
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '&') && (fx[fi + 1] == '&') && !c) { //logical and
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '&') && !c) { //reference or bitwise and
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '|') && (fx[fi + 1] == '|') && !c) { //logical or
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '|') && !c) { //bitwise or
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '^') && !c) { //bitwise exclusive or
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '>') && (fx[fi + 1] == '>') && !c) { //bitwise right shift
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '>') && !c) { //logical greater than
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '<') && (fx[fi + 1] == '<') && !c) { //bitwise left shift
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '<') && !c) { //logical less than
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '=') && (fx[fi + 1] == '=') && !c) { //logical equal to
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '=') && !c) { //assignment
			if (li) {
				next_str();
			}
			mod = 1;
		}
		else if ((fx[fi] == '>') && (fx[fi + 1] == '=') && !c) { //logical greater than or equal to
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '<') && (fx[fi + 1] == '=') && !c) { //logical less than or equal to
			if (li) {
				next_str();
			}
		}
		else if (fx[fi] == '*' && fx[fi + 1] == '/' && c == 2) {
			c = 0;
		}
		else if ((fx[fi] == '*') && !c) { //dereference or multiplication
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '/') && (fx[fi + 1] == '/') && !c) { //line comment
			c = 1;
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '/') && (fx[fi + 1] == '*') && !c) { //block comment
			c = 2;
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '/') && !c) { //division
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '%') && !li && !c) { //modulo
			if (li) {
				next_str();
			}
		}
		else if (fx[fi] == '\n') {
			if (c == 1) {
				c = 0;
			}
			ln = ln + 1;
		}
		else if ((fx[fi] == '.') && li && !c) { //struct access
			
		}
		else if ((fx[fi] == ' ') && li && !c) { //next string
			if (li) {
				next_str();
			}
			
		}
		else if ((fx[fi] == ',') && li && !c) { //next string (parameter)
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ';') && li && !c) {
			if (li) {
				next_str();
			}
			if (mod == 1) {
				end_assign();
			}
			stack_dst = 0;
		}
		else if ((fx[fi] == '(') && !c) {
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == ')') && !c) { 
			if (li) {
				next_str();
			}
		}
		else if ((fx[fi] == '{') && !c) { //next string (begin function content)
			if (li) {
				next_str();
			}
			brackt_n = brackt_n + 1;
		}
		else if ((fx[fi] == '}') && !c) { //next string (end function content)
			if (li) {
				next_str();
			}
			if (key || stack_dst) {
				//error
			}
			else {
				dec_stack(brackt_n);
			}
			brackt_n = brackt_n - 1;
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
	else if (!strcmp(argv[1], "arm64")) {
		
	}
	else if (!strcmp(argv[1], "x86")) {
		
	}
	else if (!strcmp(argv[1], "i386")) {
		
	}
	else if (!strcmp(argv[1], "x86-64")) {
		cu_enc_ent = x86_64_enc_ent;
		cu_enc_exit = x86_64_enc_exit;
		cu_enc_loc_dec_8 = x86_64_enc_loc_dec_8;
		cu_enc_loc_dec_16 = x86_64_enc_loc_dec_16;
		cu_enc_loc_dec_32 = x86_64_enc_loc_dec_32;
		cu_enc_loc_dec_64 = x86_64_enc_loc_dec_64;
		cu_enc_load_reg_imm = x86_64_enc_load_reg_imm;
		cu_enc_loc_load_reg_8 = x86_64_enc_loc_load_reg_8;
		cu_enc_loc_load_reg_16 = x86_64_enc_loc_load_reg_16;
		cu_enc_loc_load_reg_32 = x86_64_enc_loc_load_reg_32;
		cu_enc_loc_load_reg_64 = x86_64_enc_loc_load_reg_64;
		cu_enc_loc_str_8 = x86_64_enc_loc_str_8;
		cu_enc_loc_str_16 = x86_64_enc_loc_str_16;
		cu_enc_loc_str_32 = x86_64_enc_loc_str_32;
		cu_enc_loc_str_64 = x86_64_enc_loc_str_64;
		cu_enc_glo_dec_8 = x86_64_enc_glo_dec_8;
		cu_enc_glo_dec_16 = x86_64_enc_glo_dec_16;
		cu_enc_glo_dec_32 = x86_64_enc_glo_dec_32;
		cu_enc_glo_dec_64 = x86_64_enc_glo_dec_64;
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
