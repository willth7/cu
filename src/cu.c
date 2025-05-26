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

/*	todo

	local function declaration
	hierachy of scope
		need to be able to access variables from higher scope

*/

/*	notes

	are ifs, elses, and whiles not just just functions with a single parameter, the condition?

*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct cu_var_s {
	uint8_t type;				//variable type
	uint8_t* name;				//variable name
	uint8_t name_n;				//name length
};

struct cu_op_s;

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
	else if (!strcmp(str, "uin64_t")) {
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
		return 16;
	}
	else if (!strcmp(str, "uint16_t*")) {
		return 17;
	}
	else if (!strcmp(str, "uint32_t*")) {
		return 18;
	}
	else if (!strcmp(str, "uin64_t*")) {
		return 19;
	}
	
	else if (!strcmp(str, "int8_t*")) {
		return 20;
	}
	else if (!strcmp(str, "int16_t*")) {
		return 21;
	}
	else if (!strcmp(str, "int32_t*")) {
		return 22;
	}
	else if (!strcmp(str, "int64_t*")) {
		return 23;
	}
	
	else if (!strcmp(str, "void")) {
		return 24;
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
		
	}
	else if (!strcmp(str, "break")) {
		
	}
	
	else {
		return 0;
	}
}

uint8_t cu_str_op(uint8_t* str) {
	if (!strcmp(str, "+")) {			//addition
		return 1;
	}
	else if (!strcmp(str, "-")) {		//subtraction
		return 2;
	}
	
	else if (!strcmp(str, "~")) {		//bitwise not
		return 3;
	}
	else if (!strcmp(str, "&")) {		//bitwise and
		return 4;
	}
	else if (!strcmp(str, "|")) {		//bitwise or
		return 5;
	}
	else if (!strcmp(str, "^")) {		//bitwise exclusive or
		return 6;
	}
	else if (!strcmp(str, "<<")) {		//bitwise left shift
		return 7;
	}
	else if (!strcmp(str, ">>")) {		//bitwise right shift
		return 8;
	}
	
	else if (!strcmp(str, "!")) {		//logical not
		return 9;
	}
	else if (!strcmp(str, "&&")) {		//logical and
		return 10;
	}
	else if (!strcmp(str, "||")) {		//logical or
		return 11;
	}
	else if (!strcmp(str, "==")) {		//logical equal to
		return 12;
	}
	else if (!strcmp(str, ">")) {		//logical greater than
		return 13;
	}
	else if (!strcmp(str, "<")) {		//logical less than
		return 14;
	}
	else if (!strcmp(str, ">=")) {		//logical greater than or equal to
		return 15;
	}
	else if (!strcmp(str, "<=")) {		//logical less than or equal to
		return 16;
	}
	
	else if (!strcmp(str, "*")) {		//multiplication
		return 17;
	}
	else if (!strcmp(str, "/")) {		//division
		return 18;
	}
	else if (!strcmp(str, "%")) {		//modulo
		return 19;
	}
	
	
	else {
		return 0;
	}
}

uint8_t cu_var_str_cmp(struct cu_var_s* var, uint8_t var_n, uint8_t* str) {
	for (uint8_t i = 0; i < var_n; i++) {
		if (!strcmp(var[i].name, str)) {
			return i + 1;
		}
	}
	return 0;
}

uint8_t cu_func_str_cmp(struct cu_func_s* func, uint8_t func_n, uint8_t* str) {
	for (uint8_t i = 0; i < func_n; i++) {
		if (!strcmp(func[i].name, str)) {
			return i + 1;
		}
	}
	return 0;
}

void cu_var_print(struct cu_var_s* var, uint8_t var_n) {
	for (uint8_t i = 0; i < var_n; i++) {
		if (var[i].type == 1) {
			printf("\tunsigned byte %s\n", var[i].name);
		}
		else if (var[i].type == 2) {
			printf("\tunsigned halfword %s\n", var[i].name);
		}
		else if (var[i].type == 3) {
			printf("\tunsigned word %s\n", var[i].name);
		}
		else if (var[i].type == 5) {
			printf("\tsigned byte %s\n", var[i].name);
		}
		else if (var[i].type == 6) {
			printf("\tsigned halfword %s\n", var[i].name);
		}
		else if (var[i].type == 7) {
			printf("\tsigned word %s\n", var[i].name);
		}
	}
}

void cu_op_print(struct cu_op_s* op, uint8_t op_n) {
	for (uint8_t i = 0; i < op_n; i++) {
		printf("type %u, \n", op[i].type);
	}
}

void cu_func_print(struct cu_func_s* func, uint8_t func_n) {
	for (uint8_t i = 0; i < func_n; i++) {
		printf("function %s with parameters\n", func[i].name);
		cu_var_print(func[i].para, func[i].para_n);
		printf("and local variables\n");
		cu_var_print(func[i].var, func[i].var_n);
		printf("and local functions\n");
		cu_func_print(func[i].func, func[i].func_n);
		printf("\n");
		cu_op_print(func[i].op, func[i].op_n);
	}
}

void cu_lex(uint8_t* bin, uint64_t* bn, int8_t* path, int8_t* e, uint8_t addr_len) {
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
	uint8_t key = 0;		//current keyword
	
	struct cu_func_s* asn_scop = 0;	//scope for assignment
	uint64_t asn_indx = 0;			//index for assignment
	
	//0		higher scope
	//1		variable declaration
	//2		parameter declaration
	//3		function declaration
	
	//5		variable assignment
	//6		parameter assignment
	//7		function assignment
	
	//4		lower scope
	
	struct cu_func_s* scop[255] = {};
	scop[0] = malloc(sizeof(struct cu_func_s));
	uint8_t indx = 0;
	
	scop[0]->para_n = 0;
	
	scop[0]->var_n = 0;
	scop[0]->var = malloc(sizeof(struct cu_var_s) * 255);	//global variables
	scop[0]->func_n = 0;
	scop[0]->func = malloc(sizeof(struct cu_func_s) * 255);	//global functions
	
	scop[0]->op = malloc(sizeof(struct cu_var_s) * 1024);
	scop[0]->op_n = 0;
	
	
	for (uint64_t fi = 0; fi < fs.st_size; fi++) {
		//printf("%c, %u, %u\n", fx[fi], mod, key);
		
		if (((fx[fi] >= 97 && fx[fi] <= 122) || (fx[fi] >= 48 && fx[fi] <= 57)  || (fx[fi] >= 65 && fx[fi] <= 90) || fx[fi] == '_' || fx[fi] == '-') && !c) { //string
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == '&') && !li && !c) { //reference
			
		}
		else if ((fx[fi] == '*') && !li && !c) { //dereference
			
		}
		else if ((fx[fi] == '.') && li && !c) { //struct access
			
		}
		else if ((fx[fi] == '-' && fx[fi + 1] == '>') && li && !c) { //struct access (pointer)
			
		}
		else if ((fx[fi] == ' ') && li && !c) { 					//next string
			if (mod == 0 && key) {
				if (!cu_var_str_cmp(scop[indx]->var, scop[indx]->var_n, lex)) {
					scop[indx]->var[scop[indx]->var_n].type = key;
					scop[indx]->var[scop[indx]->var_n].name = malloc(strlen(lex));
					scop[indx]->var[scop[indx]->var_n].name_n = strlen(lex);
					memcpy(scop[indx]->var[scop[indx]->var_n].name, lex, strlen(lex));
					key = 0;
					mod = 1;
					
					scop[indx]->op[scop[indx]->op_n].type = key % 4;
					scop[indx]->op[scop[indx]->op_n].dst_scop = scop[indx];
					scop[indx]->op[scop[indx]->op_n].dst_indx = scop[indx]->var_n;
					scop[indx]->op[scop[indx]->op_n].dst_type = 0;
					scop[indx]->op_n = scop[indx]->op_n + 1;
					
					asn_scop = scop[indx];
					asn_indx = scop[indx]->var_n;
				}
				else {
					//error
				}
			}
			else if (mod == 0 && !key) {
				key = cu_str_key(lex);
				
				if (!key) {
					for (int8_t i = indx; i != -1; i--) {
						if (cu_var_str_cmp(scop[i]->var, scop[i]->var_n, lex)) {
							asn_scop = scop[i];
							asn_indx = cu_var_str_cmp(scop[i]->var, scop[i]->var_n, lex) - 1;
							mod = 5;
							break;
						}
						else if (!i) {
							//error, unknown variable
							
						}
					}
				}
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ',') && li && !c) { 						//next string (parameter)
			if (mod == 2 && key) {
				if (!cu_var_str_cmp(scop[indx]->func[scop[indx]->func_n].para, scop[indx]->func[scop[indx]->func_n].para_n, lex)) {
					scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].type = key;
					scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].name = malloc(strlen(lex));
					scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].name_n = strlen(lex);
					memcpy(scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].name, lex, strlen(lex));
					scop[indx]->func[scop[indx]->func_n].para_n = scop[indx]->func[scop[indx]->func_n].para_n + 1;
					key = 0;
				}
				else {
					//error
				}
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '(') && !c) {								//next string
			if (mod == 0 && li && key) {								//begin function parameters
				if (!cu_func_str_cmp(scop[indx]->func, scop[indx]->func_n, lex)) {
					scop[indx]->func[scop[indx]->func_n].type = key;
					scop[indx]->func[scop[indx]->func_n].name = malloc(strlen(lex));
					scop[indx]->func[scop[indx]->func_n].name_n = strlen(lex);
					memcpy(scop[indx]->func[scop[indx]->func_n].name, lex, strlen(lex));
					
					scop[indx]->func[scop[indx]->func_n].para = malloc(sizeof(struct cu_var_s) * 255);
					scop[indx]->func[scop[indx]->func_n].para_n = 0;
					
					scop[indx]->func[scop[indx]->func_n].var = malloc(sizeof(struct cu_var_s) * 255);
					scop[indx]->func[scop[indx]->func_n].var_n = 0;
					
					scop[indx]->func[scop[indx]->func_n].func = malloc(sizeof(struct cu_func_s) * 255);
					scop[indx]->func[scop[indx]->func_n].func_n = 0;
					
					scop[indx]->func[scop[indx]->func_n].op = malloc(sizeof(struct cu_op_s) * 1024);
					scop[indx]->func[scop[indx]->func_n].op_n = 0;
					
					key = 0;
					mod = 2;
				}
				else {
					//error
				}
			}
			else if (mod == 0 && li && !key) {						//function call
				for (int8_t i = indx; i != -1; i--) {
					if (cu_func_str_cmp(scop[i]->func, scop[i]->func_n, lex)) {
						asn_scop = scop[i];
						asn_indx = cu_func_str_cmp(scop[i]->func, scop[i]->func_n, lex);
						mod = 6;
						break;
					}
					else if (!i) {
						//error, unknown function
						
					}
				}
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ')') && !c) { 								//next string
			if (mod == 2 && key) {										//end function parameters
				if (!cu_var_str_cmp(scop[indx]->func[scop[indx]->func_n].para, scop[indx]->func[scop[indx]->func_n].para_n, lex)) {
					scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].type = key;
					scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].name = malloc(strlen(lex));
					scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].name_n = strlen(lex);
					memcpy(scop[indx]->func[scop[indx]->func_n].para[scop[indx]->func[scop[indx]->func_n].para_n].name, lex, strlen(lex));
					scop[indx]->func[scop[indx]->func_n].para_n = scop[indx]->func[scop[indx]->func_n].para_n + 1;
					
					key = 0;
					mod = 3;
				}
				else {
					//error
				}
			}
			else if (mod == 2) {
				mod = 3;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '{') && !c) { //next string (begin function content)
			if (mod == 3) {
				scop[indx + 1] = &(scop[indx]->func[scop[indx]->func_n]);
				indx = indx + 1;
				mod = 0;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '}') && !c) { //next string (end function content)
			if (mod == 0) {
				indx = indx - 1;
				scop[indx]->func_n = scop[indx]->func_n + 1;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ';') && !c) {
			if (mod == 0) {
				if (!cu_var_str_cmp(scop[indx]->var, scop[indx]->var_n, lex)) {
					scop[indx]->var[scop[indx]->var_n].type = key;
					scop[indx]->var[scop[indx]->var_n].name = malloc(strlen(lex));
					scop[indx]->var[scop[indx]->var_n].name_n = strlen(lex);
					memcpy(scop[indx]->var[scop[indx]->var_n].name, lex, strlen(lex));
					
					scop[indx]->op[scop[indx]->op_n].type = key % 4;
					scop[indx]->op[scop[indx]->op_n].dst_scop = scop[indx];
					scop[indx]->op[scop[indx]->op_n].dst_indx = scop[indx]->var_n;
					scop[indx]->op[scop[indx]->op_n].dst_type = 0;
					scop[indx]->op_n = scop[indx]->op_n + 1;
					
					scop[indx]->var_n = scop[indx]->var_n + 1;
					key = 0;
					mod = 0;
				}
				else {
					//error
				}
				key = 0;
				mod = 0;
			}
			else if (mod == 3) {
				scop[indx]->func_n = scop[indx]->func_n + 1;
				mod = 0;
			}
			/*else if (mod == 4) {
				func[func_n].var[func[func_n].var_n].type = key;
				func[func_n].var[func[func_n].var_n].name = malloc(strlen(lex));
				func[func_n].var[func[func_n].var_n].name_n = strlen(lex);
				memcpy(func[func_n].var[func[func_n].var_n].name, lex, strlen(lex));
				func[func_n].var_n = func[func_n].var_n + 1;
				key = 0;
				mod = 4;
			}
			else if (mod == 4) {
				scop[indx]->op[scop[indx]->op_n].type = 9;
				scop[indx]->op[scop[indx]->op_n].dst_scop = scop[i];
				scop[indx]->op[scop[indx]->op_n].dst_indx = cu_func_str_cmp(scop[i]->func, scop[i]->func_n, lex);
				scop[indx]->op[scop[indx]->op_n].dst_type = 2;
				scop[indx]->op_n = scop[indx]->op_n + 1;
			}*/
			else if (mod == 5) {
				if ((lex[0] >= 48 && lex[0] <= 57) || lex[0] == 45) {
					printf("%s\n", asn_scop->var[asn_indx].name);
					if (asn_scop->var[asn_indx].type == 1) {
						scop[indx]->op[scop[indx]->op_n].type = 5;
						scop[indx]->op[scop[indx]->op_n].dst_scop = asn_scop;
						scop[indx]->op[scop[indx]->op_n].dst_indx = asn_indx;
						scop[indx]->op[scop[indx]->op_n].dst_type = 0;
						
						scop[indx]->op[scop[indx]->op_n].src_type = 3;
						scop[indx]->op[scop[indx]->op_n].src_imm = cu_str_int_dec(lex, e, path, ln);
						scop[indx]->op_n = scop[indx]->op_n + 1;
					}
					mod = 0;
				}
			}
			else if (key == 0) {
				key = cu_str_key(lex); //single keywords
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '=') && !c) {
			
		}
		else if (fx[fi] == '/' && fx[fi + 1] == '/') { //line comment
			c = 1;
			lex[0] = 0;
			li = 0;
		}
		else if (fx[fi] == '/' && fx[fi + 1] == '*') { //block comment
			c = 2;
			lex[0] = 0;
			li = 0;
		}
		else if (fx[fi] == '\n' && c == 1) {
			c = 0;
		}
		else if (fx[fi] == '*' && fx[fi + 1] == '/' && c == 2) {
			c = 0;
		}
	}
	
	cu_var_print(scop[indx]->var, scop[indx]->var_n);
	cu_func_print(scop[indx]->func, scop[indx]->func_n);
	
	munmap(fx, fs.st_size);
}

void cu_writ_bin(uint8_t* bin, uint64_t bn, int8_t* path) {
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
		
	}
	else if (!strcmp(argv[3] + strlen(argv[3]) - 3, ".zn")) {
		
	}
	else {
		printf("error: invalid writput format\n");
		return -1;
	}
	
	uint8_t* bin = calloc(1000000, 1);
	uint64_t bn = 0;
	uint8_t e = 0;
	cu_lex(bin, &bn, argv[2], &e, 4);
	
	/*if (!e) {
		cu_writ_bin(bin, bn, argv[3]);
	}*/
	
	free(bin);
	return 0;
}
