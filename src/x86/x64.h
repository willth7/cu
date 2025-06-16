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

void x86_64_enc_ent(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void x86_64_enc_exit(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_8(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_16(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_32(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_64(uint8_t*, uint64_t*);

void x86_64_enc_load_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_loc_load_reg_8(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_load_reg_16(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_load_reg_32(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_load_reg_64(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_str_8(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_str_16(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_str_32(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_loc_str_64(uint8_t*, uint64_t*, uint8_t, uint32_t);

void x86_64_enc_glo_dec_8(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_16(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_32(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_64(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

