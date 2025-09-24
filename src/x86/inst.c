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

void x86_64_inst_mvp(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
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

void x86_64_enc_add_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 0 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_add_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 2 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_add_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 0 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_add_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 4 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_add_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_add_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_add_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_add_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_or_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 8 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_or_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 10 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_or_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 8 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_or_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 12 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 1); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_or_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_or_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_or_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_or_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_adc_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 16 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_adc_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 18 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_adc_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 16 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_adc_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 20 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_adc_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_adc_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_adc_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_adc_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_sbb_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 24 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sbb_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 26 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sbb_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 24 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_sbb_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 28 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 3); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_sbb_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sbb_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_sbb_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_sbb_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_and_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 32 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_and_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 34 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_and_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 32 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_and_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 36 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_and_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_and_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_and_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_and_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_sub_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 40 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sub_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 42 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sub_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 40 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_sub_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 44 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 5); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_sub_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sub_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_sub_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_sub_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_xor_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 48 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_xor_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 50 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_xor_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 48 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_xor_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 52 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_xor_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_xor_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_xor_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_xor_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_cmp_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 56 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_cmp_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 58 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_cmp_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 56 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_cmp_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, 0, 0, r);
		x86_64_inst_byt(bin, bn, 60 + !!(r & 48)); //op
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
	else if ((r & 48) && k < 256) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_mod(bin, bn, 3, r, 7); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 128 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 7); //modrm
		x86_64_inst_lcp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_cmp_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 128); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_cmp_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_cmp_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_cmp_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k < 256) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k < 256) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && k < 256) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (k < 256) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 131); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 129); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_push_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
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

void x86_64_enc_pop_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 143); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_pop_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, 0);
	x86_64_inst_byt(bin, bn, 88 | (r & 7)); //op
}

void x86_64_enc_jo_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 112); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 128); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jno_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 113); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 129); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jc_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 114); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 130); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jnc_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 115); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 131); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_je_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 116); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 132); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jne_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 117); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 133); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jna_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 118); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 134); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_ja_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 119); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 135); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_js_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 120); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 136); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jns_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 121); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 137); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jpe_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 122); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 138); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jpo_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 123); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 139); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jl_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 124); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 140); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jge_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 125); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 141); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jle_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 126); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 142); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jg_imm(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 127); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 15); //op
		x86_64_inst_byt(bin, bn, 143); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_xchg_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 134 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_xchg_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	if ((rd & 15) == 0) {
		x86_64_prfx_leg(bin, bn, 0, rs);
		x86_64_prfx_rex(bin, bn, 0, 0, rs);
		x86_64_inst_byt(bin, bn, 144 + (rs & 7)); //op
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, rs);
		x86_64_prfx_rex(bin, bn, rd, 0, rs);
		x86_64_inst_byt(bin, bn, 134 + !!(rd & 48)); //op
		x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
	}
}

void x86_64_enc_mov_addr_reg(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t r) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 136 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_mov_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 138 + !!(r & 48)); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_mov_reg_reg(uint8_t* bin, uint64_t* bn, uint8_t rd, uint8_t rs) {
	x86_64_prfx_leg(bin, bn, 0, rs);
	x86_64_prfx_rex(bin, bn, rd, 0, rs);
	x86_64_inst_byt(bin, bn, 136 + !!(rd & 48)); //op
	x86_64_inst_mod(bin, bn, 3, rd, rs); //modrm
}

void x86_64_enc_mov_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if ((r & 48) && k < 4294967296) {
		x86_64_prfx_rex(bin, bn, r, 0, 48);
		x86_64_inst_byt(bin, bn, 199); //op
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
 		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, (176 + (!!(r & 48) * 8)) | (r & 7)); //op
		x86_64_inst_mvp(bin, bn, r, k); //imm
	}
}

void x86_64_enc_mov_addr_k8(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 198); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_mov_addr_k16(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint16_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k16(bin, bn, k); //imm
	}
}

void x86_64_enc_mov_addr_k32(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_mov_addr_k64(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint32_t k) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 199); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_lea_reg_addr(uint8_t* bin, uint64_t* bn, uint8_t r, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, 0, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 0, 5, r); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 0, b, r); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 0, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 1, b, r); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 1, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 2, b, r); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, r);
 		x86_64_prfx_rex(bin, bn, b, 0, r);
 		x86_64_inst_byt(bin, bn, 141); //op
 		x86_64_inst_mod(bin, bn, 2, 4, r); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rol_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
}

void x86_64_enc_rol_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rolb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rolw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rold_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rolq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rolb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rolw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rold_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rolq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_ror_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 1); //modrm
}

void x86_64_enc_ror_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 1); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rorb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rorw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rord_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rorq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rorb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rorw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rord_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rorq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcl_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
}

void x86_64_enc_rcl_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rclb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rclw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rcld_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rclq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rclb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rclw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcld_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rclq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcr_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 3); //modrm
}

void x86_64_enc_rcr_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 3); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcrb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rcrw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rcrd_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rcrq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_rcrb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcrw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcrd_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_rcrq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shl_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
}

void x86_64_enc_shl_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shlb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shlw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shld_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shlq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shlb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shlw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shld_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shlq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shr_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 5); //modrm
}

void x86_64_enc_shr_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 5); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shrb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shrw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shrd_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shrq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_shrb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shrw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shrd_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_shrq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sal_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
}

void x86_64_enc_sal_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_salb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_salw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sald_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_salq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_salb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_salw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sald_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_salq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sar_reg_cl(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 210 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
}

void x86_64_enc_sar_reg_imm(uint8_t* bin, uint64_t* bn, uint8_t r, uint64_t k) {
	if (k == 1) {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 208 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
	}
	else {
		x86_64_prfx_leg(bin, bn, 0, r);
		x86_64_prfx_rex(bin, bn, r, 0, r & 48);
		x86_64_inst_byt(bin, bn, 192 + !!(r & 48)); //op
		x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sarb_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 210); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sarw_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sard_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sarq_addr_cl(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 211); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_sarb_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 208); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 192); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sarw_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sard_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_sarq_addr_imm(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d, uint8_t k) {
	if (b == 117 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0 && k == 1) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128 && k == 1) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && k == 1) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0 && k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (k == 1) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 209); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 193); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_ret(uint8_t* bin, uint64_t* bn) {
	x86_64_inst_byt(bin, bn, 195); //op
}

void x86_64_enc_int(uint8_t* bin, uint64_t* bn, uint8_t k) {
	if (k == 3) {
		x86_64_inst_byt(bin, bn, 204); //op
	}
	else {
		x86_64_inst_byt(bin, bn, 205); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
}

void x86_64_enc_call(uint8_t* bin, uint64_t* bn, uint32_t k) {
	x86_64_inst_byt(bin, bn, 232); //op
	x86_64_inst_k32(bin, bn, k); //imm
}

void x86_64_enc_call_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, 0);
	x86_64_inst_byt(bin, bn, 255); //op
	x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
}

void x86_64_enc_call_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_jmp(uint8_t* bin, uint64_t* bn, uint32_t k) {
	if (k < 256) {
		x86_64_inst_byt(bin, bn, 235); //op
		x86_64_inst_byt(bin, bn, k); //imm
	}
	else {
		x86_64_inst_byt(bin, bn, 233); //op
		x86_64_inst_k32(bin, bn, k); //imm
	}
}

void x86_64_enc_jmp_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, 0);
	x86_64_inst_byt(bin, bn, 255); //op
	x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
}

void x86_64_enc_jmp_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_not_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 246 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 2); //modrm
}

void x86_64_enc_notb_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_notw_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_notd_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_notq_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 2); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 2); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 2); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 2); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 2); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_neg_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 246 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 3); //modrm
}

void x86_64_enc_negb_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_negw_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_negd_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_negq_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 3); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 3); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 3); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 3); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 3); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_mul_rax_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 246 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 4); //modrm
}

void x86_64_enc_mulb_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_mulw_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_muld_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_mulq_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 4); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 4); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 4); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 4); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 4); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_imul_rax_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 246 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 5); //modrm
}

void x86_64_enc_imulb_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_imulw_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_imuld_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_imulq_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 5); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 5); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 5); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 5); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 5); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_div_rax_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 246 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 6); //modrm
}

void x86_64_enc_divb_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_divw_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_divd_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_divq_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 6); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 6); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 6); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 6); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 6); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_idiv_rax_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 246 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 7); //modrm
}

void x86_64_enc_idivb_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 246); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_idivw_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_idivd_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_idivq_rax_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 7); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, b, 7); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, b, 7); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, b, 7); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 247); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 7); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_inc_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 254 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 0); //modrm
}

void x86_64_enc_incb_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_incw_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_incd_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_incq_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 0); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 0); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 0); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 0); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 0); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_dec_reg(uint8_t* bin, uint64_t* bn, uint8_t r) {
	x86_64_prfx_leg(bin, bn, 0, r);
	x86_64_prfx_rex(bin, bn, r, 0, r & 48);
	x86_64_inst_byt(bin, bn, 254 + !!(r & 48)); //op
	x86_64_inst_mod(bin, bn, 3, r, 1); //modrm
}

void x86_64_enc_decb_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 254); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_decw_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 16);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_decd_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 0);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_decq_addr(uint8_t* bin, uint64_t* bn, uint8_t b, uint8_t i, uint8_t s, int32_t d) {
	if (b == 117) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, 0, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 5, 1); //modrm
 		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0 && d == 0) { //mod 0
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
	}
	else if ((b & 7) != 5 && i == 0 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, b, 1); //modrm
	}
	else if ((b & 7) != 5 && d == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 0, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
	}
	else if ((b & 7) == 4 && i == 0 && d >= -128 && d < 128) { //mod 1
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (i == 0 && d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, b, 1); //modrm
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if (d >= -128 && d < 128) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 1, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_byt(bin, bn, d); //disp
	}
	else if ((b & 7) == 4 && i == 0) { //mod 2
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, 0, 4, 4); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else if (i == 0) {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, b, 1); //modrm
		x86_64_inst_k32(bin, bn, d); //disp
	}
	else {
		x86_64_prfx_leg(bin, bn, b, 0);
 		x86_64_prfx_rex(bin, bn, b, 0, 48);
 		x86_64_inst_byt(bin, bn, 255); //op
 		x86_64_inst_mod(bin, bn, 2, 4, 1); //modrm
		x86_64_inst_mod(bin, bn, s, b, i); //sib
		x86_64_inst_k32(bin, bn, d); //disp
	}
}

void x86_64_enc_syscall(uint8_t* bin, uint64_t* bn) {
	x86_64_inst_byt(bin, bn, 15); //op
	x86_64_inst_byt(bin, bn, 5); //op
}
