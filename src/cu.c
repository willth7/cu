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

struct cu_var_s {
	uint8_t type;				//variable type
	uint8_t* name;				//variable name
	uint8_t name_n;				//name length;
	
	uint8_t* val;				//value
	uint8_t* str_t;				//string for custom type
	uint8_t str_n;				//string length
};

struct cu_op_s {
	uint8_t type;				//operation type
	uint64_t src;				//operand source
	uint64_t dest;				//operand destination
	struct cu_var_s imm;		//immediate
};

struct cu_func_s {
	uint8_t type;				//return type
	uint8_t* name;				//function name
	uint8_t name_n;				//name length;
	
	uint8_t* str_t;				//string for custom type
	uint8_t str_n;				//string length
	
	struct cu_var_s* para;		//parameters
	uint8_t para_n;				//number of parameters
	
	struct cu_var_s* scope;		//scope
	uint64_t scope_n;			//number of parameters
	
	struct cu_op_s* op;			//operations
	uint64_t op_n;				//number of operations
};

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
	if (!strcmp(str, "void")) {
		return 1;
	}
	
	else if (!strcmp(str, "uint8_t")) {
		return 8;
	}
	else if (!strcmp(str, "uint16_t")) {
		return 9;
	}
	else if (!strcmp(str, "uint32_t")) {
		return 10;
	}
	else if (!strcmp(str, "uin64_t")) {
		return 11;
	}
	
	else if (!strcmp(str, "int8_t")) {
		return 12;
	}
	else if (!strcmp(str, "int16_t")) {
		return 13;
	}
	else if (!strcmp(str, "int32_t")) {
		return 14;
	}
	else if (!strcmp(str, "int64_t")) {
		return 15;
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
			return 1;
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

void cu_lex(uint8_t* bin, uint64_t* bn, int8_t* path, int8_t* e) {
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
	
	//0		global
	//1		global declaration (variable)
	//2		global declaration and assignment (variable)
	//3		function parameter declaration
	//4		global declaration (function)
	//5		global declaration and assignment (function)
	
	//6		local declaration (variable)
	//7		local assignment (variable)
	//8		local declaration and assignment (variable)
	//9		local declaration (function)
	//10	local assignment (function)
	//11	local declaration and assignment (function)
	
	struct cu_var_s var[255] = {};			//global variables
	uint8_t var_n = 0;
	struct cu_func_s func[255] = {};		//functions
	uint8_t func_n = 0;
	struct cu_var_s para[255] = {};			//function parameters
	uint8_t para_n = 0;
	
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
				if (!cu_var_str_cmp(var, var_n, lex)) {
					var[var_n].type = key;
					var[var_n].name = malloc(strlen(lex));
					var[var_n].name_n = strlen(lex);
					memcpy(var[var_n].name, lex, strlen(lex));
					key = 0;
					mod = 1;
				}
				else {
					//error
				}
			}
			else if (mod == 0 || mod == 3) {
				key = cu_str_key(lex);
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ',') && li && !c) { 						//next string (parameter)
			if (mod == 3 && key) {
				if (!cu_var_str_cmp(para, para_n, lex)) {
					para[para_n].type = key;
					para[para_n].name = malloc(strlen(lex));
					para[para_n].name_n = strlen(lex);
					memcpy(para[para_n].name, lex, strlen(lex));
					para_n = para_n + 1;
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
				if (!cu_func_str_cmp(func, func_n, lex)) {
					func[func_n].type = key;
					func[func_n].name = malloc(strlen(lex));
					func[func_n].name_n = strlen(lex);
					memcpy(func[func_n].name, lex, strlen(lex));
					key = 0;
					mod = 3;
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
		else if ((fx[fi] == ')') && !c) { 								//next string
			if (mod == 3 && key) {										//end function parameters
				if (!cu_var_str_cmp(para, para_n, lex)) {
					para[para_n].type = key;
					para[para_n].name = malloc(strlen(lex));
					para[para_n].name_n = strlen(lex);
					memcpy(para[para_n].name, lex, strlen(lex));
					para_n = para_n + 1;
					
					func[func_n].para = malloc(sizeof(struct cu_var_s) * para_n);
					func[func_n].para_n = para_n;
					memcpy(func[func_n].para, para, sizeof(struct cu_var_s) * para_n);
					
					key = 0;
					mod = 4;
				}
				else {
					//error
				}
			}
			else if (mod == 3) {
				func[func_n].para = malloc(sizeof(struct cu_var_s) * para_n);
				func[func_n].para_n = para_n;
				memcpy(func[func_n].para, para, sizeof(struct cu_var_s) * para_n);
				mod = 4;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '{') && !c) { //next string (begin function content)
			if (mod == 4) {
				mod = 5;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '}') && !c) { //next string (end function content)
			if (mod == 5) {
				func_n = func_n + 1;
				mod = 0;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ';') && !c) {
			if (mod == 0) {
				var[var_n].type = key;
				var[var_n].name = malloc(strlen(lex));
				var[var_n].name_n = strlen(lex);
				memcpy(var[var_n].name, lex, strlen(lex));
				key = 0;
				
				if (var[var_n].type == 8) {
					var[var_n].val = malloc(1);
					uint8_t val = 0;
					memcpy(var[var_n].val, &val, 1);
				}
				else if (var[var_n].type == 9) {
					var[var_n].val = malloc(2);
					uint16_t val = 0;
					memcpy(var[var_n].val, &val, 2);
				}
				else if (var[var_n].type == 10) {
					var[var_n].val = malloc(3);
					uint32_t val = 0;
					memcpy(var[var_n].val, &val, 3);
				}
				else if (var[var_n].type == 11) {
					var[var_n].val = malloc(4);
					uint64_t val = 0;
					memcpy(var[var_n].val, &val, 4);
				}
				else if (var[var_n].type == 12) {
					var[var_n].val = malloc(1);
					int8_t val = 0;
					memcpy(var[var_n].val, &val, 1);
				}
				else if (var[var_n].type == 13) {
					var[var_n].val = malloc(2);
					int16_t val = 0;
					memcpy(var[var_n].val, &val, 2);
				}
				else if (var[var_n].type == 14) {
					var[var_n].val = malloc(3);
					int32_t val = 0;
					memcpy(var[var_n].val, &val, 3);
				}
				else if (var[var_n].type == 15) {
					var[var_n].val = malloc(4);
					int64_t val = 0;
					memcpy(var[var_n].val, &val, 4);
				}
				var_n = var_n + 1;
				mod = 0;
			}
			else if (mod == 2) {
				if (var[var_n].type == 8) {
					var[var_n].val = malloc(1);
					uint8_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 1);
				}
				else if (var[var_n].type == 9) {
					var[var_n].val = malloc(2);
					uint16_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 2);
				}
				else if (var[var_n].type == 10) {
					var[var_n].val = malloc(3);
					uint32_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 3);
				}
				else if (var[var_n].type == 11) {
					var[var_n].val = malloc(4);
					uint64_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 4);
				}
				else if (var[var_n].type == 12) {
					var[var_n].val = malloc(1);
					int8_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 1);
				}
				else if (var[var_n].type == 13) {
					var[var_n].val = malloc(2);
					int16_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 2);
				}
				else if (var[var_n].type == 14) {
					var[var_n].val = malloc(3);
					int32_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 3);
				}
				else if (var[var_n].type == 15) {
					var[var_n].val = malloc(4);
					int64_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 4);
				}
				var_n = var_n + 1;
				mod = 0;
			}
			else if (mod == 4) {
				func[func_n].para = malloc(sizeof(struct cu_var_s) * para_n);
				func[func_n].para_n = para_n;
				memcpy(func[func_n].para, para, sizeof(struct cu_var_s) * para_n);
				func_n = func_n + 1;
				para_n = 0;
				mod = 0;
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
			if (mod == 1) {
				mod = 2;
			}
			else {
				//error
			}
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
	
	for (uint8_t i = 0; i < var_n; i++) {
		if (var[i].type == 8) {
			printf("unsigned byte %s with value of %u\n", var[i].name, *(var[i].val));
		}
		else if (var[i].type == 9) {
			printf("unsigned halfword %s with value of %u\n", var[i].name, *(var[i].val) + ((*(var[i].val + 1) << 8)));
		}
		else if (var[i].type == 10) {
			printf("unsigned word %s with value of %u\n", var[i].name, *(var[i].val) + ((*(var[i].val + 1) << 8)) + ((*(var[i].val + 2) << 16)) + ((*(var[i].val + 3) << 24)));
		}
		else if (var[i].type == 12) {
			printf("signed byte %s with value of %i\n", var[i].name, (int8_t) *(var[i].val));
		}
		else if (var[i].type == 13) {
			printf("signed halfword %s with value of %i\n", var[i].name, (int16_t) (*(var[i].val) + ((*(var[i].val + 1) << 8))));
		}
		else if (var[i].type == 14) {
			printf("signed word %s with value of %i\n", var[i].name, (int32_t) (*(var[i].val) + ((*(var[i].val + 1) << 8)) + ((*(var[i].val + 2) << 16)) + ((*(var[i].val + 3) << 24))));
		}
	}
	for (uint8_t i = 0; i < func_n; i++) {
		printf("function %s with parameters\n", func[i].name);
		for (uint8_t j = 0; j < func[i].para_n; j++) {
			if (func[i].para[j].type == 8) {
				printf("\tunsigned byte %s\n", func[i].para[j].name);
			}
			else if (func[i].para[j].type == 9) {
				printf("\tunsigned halfword %s\n", func[i].para[j].name);
			}
			else if (func[i].para[j].type == 10) {
				printf("\tunsigned word %s\n", func[i].para[j].name);
			}
			else if (func[i].para[j].type == 12) {
				printf("\tsigned byte %s\n", func[i].para[j].name);
			}
			else if (func[i].para[j].type == 13) {
				printf("\tsigned halfword %s\n", func[i].para[j].name);
			}
			else if (func[i].para[j].type == 14) {
				printf("\tsigned word %s\n", func[i].para[j].name);
			}
		}
	}
	
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
	cu_lex(bin, &bn, argv[2], &e);
	
	/*if (!e) {
		cu_writ_bin(bin, bn, argv[3]);
	}*/
	
	free(bin);
	return 0;
}
