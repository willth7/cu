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

struct cu_script_s {
	uint64_t glbl_n;
	void* glbl;
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
	/*
	0							global scope
	1	void type 				generic
	2	custom type 			generic
	3	undefined
	4	undefined
	5	undefined
	6	undefined
	7	undefined
	8	unsigned byte 			generic
	9	unsigned halfword 		generic
	10	unsigned word 			generic
	11	unsigned doubleword		generic
	12	signed byte 			generic
	13	signed halfword 		generic
	14	signed word 			generic
	15	signed doubleword 		generic
	16							variable bit
	17	void type 				variable
	18	custom type 			variable
	19	undefined
	20	undefined
	21	undefined
	22	undefined
	23	undefined
	24	unsigned byte 			variable
	25	unsigned halfword 		variable
	26	unsigned word 			variable
	27	unsigned doubleword 	variable
	28	signed byte 			variable
	29	signed halfword 		variable
	30	signed word 			variable
	31	signed doubleword 		variable
	32							parameter bit
	33	void type 				parameter
	34	custom type 			parameter
	35	undefined
	36	undefined
	37	undefined
	38	undefined
	39	undefined
	40	unsigned byte 			parameter
	41	unsigned halfword 		parameter
	42	unsigned word 			parameter
	43	unsigned doubleword 	parameter
	44	signed byte 			parameter
	45	signed halfword 		parameter
	46	signed word 			parameter
	47	signed doubleword 		parameter
	48							function bits
	49	void type 				
	50	custom type 			
	51	undefined
	52	undefined
	53	undefined
	54	undefined
	55	undefined
	56	unsigned byte 			
	57	unsigned halfword 		
	58	unsigned word 			
	59	unsigned doubleword 	
	60	signed byte 			
	61	signed halfword 		
	62	signed word 			
	63	signed doubleword 		
	64							assignment bit
	*/
	
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
	else if (!strcmp(str, "in64_t")) {
		return 15;
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
	
	else {
		return 0;
	}
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
	
	uint8_t key = 0;
	
	struct cu_func_s func[255] = {};
	uint8_t func_n = 0;
	struct cu_var_s var[255] = {};
	uint8_t var_n = 0;
	struct cu_var_s para[255] = {};
	uint8_t para_n = 0;
	
	for (uint64_t fi = 0; fi < fs.st_size; fi++) {
		//printf("%c, %u\n", fx[fi], key);
		
		if (((fx[fi] >= 97 && fx[fi] <= 122) || (fx[fi] >= 48 && fx[fi] <= 57)  || (fx[fi] >= 65 && fx[fi] <= 90) || fx[fi] == '_' || fx[fi] == '-') && !c) { //string
			lex[li] = fx[fi];
			lex[li + 1] = 0;
			li++;
		}
		else if ((fx[fi] == ' ') && li && !c) { //next string (variable)
			if (key == 0) {
				key = cu_str_key(lex);
			}
			else if (key == 32) {
				key = cu_str_key(lex) | 32;
			}
			else if (key >= 8 && key <= 15) {
				var[var_n].type = key & 15;
				var[var_n].name = malloc(strlen(lex));
				var[var_n].name_n = strlen(lex);
				memcpy(var[var_n].name, lex, strlen(lex));
				key = key | 16;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ',') && li && !c) { //next string (parameter)
			if (key >= (8 | 32) && key <= (15 | 32)) {
				para[para_n].type = key & 15;
				para[para_n].name = malloc(strlen(lex));
				para[para_n].name_n = strlen(lex);
				memcpy(para[para_n].name, lex, strlen(lex));
				para_n = para_n + 1;
				key = 32;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '(') && !c) { //next string (begin function parameters)
			if (key >= 8 && key <= 15) {
				func[func_n].type = key & 15;
				func[func_n].name = malloc(strlen(lex));
				func[func_n].name_n = strlen(lex);
				memcpy(func[func_n].name, lex, strlen(lex));
				key = 32;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ')') && !c) { //next string (end function parameters)
			if (key >= (8 | 32) && key <= (15 | 32)) {
				para[para_n].type = key & 15;
				para[para_n].name = malloc(strlen(lex));
				para[para_n].name_n = strlen(lex);
				memcpy(para[para_n].name, lex, strlen(lex));
				key = 48;
			}
			else if (key == 32) {
				key = 48;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == ';') && !c) {
			if (key == 0) {
				key = cu_str_key(lex);
			}
			else if (key >= (8 | 16) && key <= (15 | 16)) {
				
				if (key == (8 | 16)) {
					var[var_n].val = malloc(1);
					uint8_t val = 0;
					memcpy(var[var_n].val, &val, 1);
					printf("new byte %s with value of %u\n", var[var_n].name, *(var[var_n].val));
				}
				else if (key == (9 | 16)) {
					var[var_n].val = malloc(2);
					uint16_t val = 0;
					memcpy(var[var_n].val, &val, 2);
					printf("new byte %s with value of %u\n", var[var_n].name, *(var[var_n].val) + ((*(var[var_n].val + 1) << 8)));
				}
				else if (key == (10 | 16)) {
					var[var_n].val = malloc(3);
					uint32_t val = 0;
					memcpy(var[var_n].val, &val, 3);
				}
				else if (key == (11 | 16)) {
					var[var_n].val = malloc(4);
					uint64_t val = 0;
					memcpy(var[var_n].val, &val, 4);
				}
				else if (key == (12 | 16)) {
					var[var_n].val = malloc(1);
					int8_t val = 0;
					memcpy(var[var_n].val, &val, 1);
					printf("new byte %s with value of %i\n", var[var_n].name, *(var[var_n].val));
				}
				else if (key == (13 | 16)) {
					var[var_n].val = malloc(2);
					int16_t val = 0;
					memcpy(var[var_n].val, &val, 2);
					printf("new byte %s with value of %i\n", var[var_n].name, *(var[var_n].val) + ((*(var[var_n].val + 1) << 8)));
				}
				else if (key == (14 | 16)) {
					var[var_n].val = malloc(3);
					int32_t val = 0;
					memcpy(var[var_n].val, &val, 3);
				}
				else if (key == (15 | 16)) {
					var[var_n].val = malloc(4);
					int64_t val = 0;
					memcpy(var[var_n].val, &val, 4);
				}
				
				var_n = var_n + 1;
				key = 0;
			}
			else if (key >= ((8 | 16) | 64) && key <= ((15 | 16) | 64)) {
				
				if (key == ((8 | 16)| 64)) {
					var[var_n].val = malloc(1);
					uint8_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 1);
				}
				else if (key == ((9 | 16) | 64)) {
					var[var_n].val = malloc(2);
					uint16_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 2);
				}
				else if (key == ((10 | 16) | 64)) {
					var[var_n].val = malloc(3);
					uint32_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 3);
				}
				else if (key == ((11 | 16) | 64)) {
					var[var_n].val = malloc(4);
					uint64_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 4);
				}
				else if (key == ((12 | 16) | 64)) {
					var[var_n].val = malloc(1);
					int8_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 1);
				}
				else if (key == ((13 | 16) | 64)) {
					var[var_n].val = malloc(2);
					int16_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 2);
				}
				else if (key == ((14 | 16) | 64)) {
					var[var_n].val = malloc(3);
					int32_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 3);
				}
				else if (key == ((15 | 16) | 64)) {
					var[var_n].val = malloc(4);
					int64_t val = cu_str_int_dec(lex, e, path, ln);
					memcpy(var[var_n].val, &val, 4);
				}
				
				var_n = var_n + 1;
				key = 0;
			}
			
			else if (key == 32) {
				//error
			}
			else if (key == 48) {
				key = 0;
				func_n = func_n + 1;
			}
			else {
				//error
			}
			
			lex[0] = 0;
			li = 0;
		}
		else if ((fx[fi] == '=') && !c) {
			if (key == 0) {
				//error
			}
			else if (key >= (8 | 16) && key <= (15 | 16)) {
				key = key | 64;
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
		printf("function %s\n", func[i].name);
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
	
	if (!e) {
		cu_writ_bin(bin, bn, argv[3]);
	}
	
	free(bin);
	return 0;
}
