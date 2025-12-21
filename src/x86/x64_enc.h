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

void x86_64_enc_ent(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void x86_64_enc_exit(uint8_t*, uint64_t*);



void x86_64_enc_loc_ref(uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void x86_64_enc_loc_dec_8(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_16(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_32(uint8_t*, uint64_t*);

void x86_64_enc_loc_dec_64(uint8_t*, uint64_t*);



void x86_64_enc_loc_load_8(uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void x86_64_enc_loc_load_16(uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void x86_64_enc_loc_load_32(uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);

void x86_64_enc_loc_load_64(uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint32_t);



void x86_64_enc_loc_str_8(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_loc_str_16(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_loc_str_32(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_loc_str_64(uint8_t*, uint64_t*, uint32_t);



void x86_64_enc_glo_ref(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_8(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_16(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_32(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_dec_64(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);



void x86_64_enc_glo_load_8(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void x86_64_enc_glo_load_16(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void x86_64_enc_glo_load_32(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);

void x86_64_enc_glo_load_64(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t);



void x86_64_enc_glo_str_8(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_str_16(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_str_32(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);

void x86_64_enc_glo_str_64(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint8_t*, uint8_t);



void x86_64_enc_load_dref_8(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_load_dref_16(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_load_dref_32(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_load_dref_64(uint8_t*, uint64_t*, uint8_t);



void x86_64_enc_str_dref_8(uint8_t*, uint64_t*);

void x86_64_enc_str_dref_16(uint8_t*, uint64_t*);

void x86_64_enc_str_dref_32(uint8_t*, uint64_t*);

void x86_64_enc_str_dref_64(uint8_t*, uint64_t*);



void x86_64_enc_load_dref_8_inc(uint8_t*, uint64_t*);

void x86_64_enc_load_dref_16_inc(uint8_t*, uint64_t*);

void x86_64_enc_load_dref_32_inc(uint8_t*, uint64_t*);

void x86_64_enc_load_dref_64_inc(uint8_t*, uint64_t*);

void x86_64_enc_load_imm(uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint64_t);



void x86_64_enc_func_pre_call (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint16_t);

void x86_64_enc_func_call_8 (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_func_call_16 (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_func_call_32 (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_func_call_64 (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_func_call_void (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);



void x86_64_enc_pnt_call_8 (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_pnt_call_16 (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_pnt_call_32 (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_pnt_call_64 (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);

void x86_64_enc_pnt_call_void (uint8_t*, uint64_t*, void (*inc_stack) (uint8_t), uint8_t, uint8_t*, uint8_t, uint16_t);



void x86_64_enc_func_ret (uint8_t*, uint64_t*, uint16_t);

void x86_64_enc_func_brk (uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*, uint16_t);

void x86_64_enc_inc_sp(uint8_t*, uint64_t*, uint16_t);



void x86_64_enc_cond_if(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void x86_64_enc_cond_else(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void x86_64_enc_cond_for(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);

void x86_64_enc_cond_post_for(uint8_t*, uint64_t*, struct au_sym_s*, uint64_t*);



void x86_64_enc_add(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_sub(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_inc(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_dec(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_bit_not(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_bit_and(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_bit_or(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_bit_xor(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_bit_shl(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_bit_shr(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_not(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_log_and(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_or(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_eq(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_neq(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_lt(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_leq(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_gt(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_log_geq(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_mult(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_div(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

void x86_64_enc_mod(uint8_t*, uint64_t*, void (*dec_stack) (uint8_t), uint8_t);

