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

void x86_64_inst_byt(uint8_t*, uint64_t*, uint8_t);

void x86_64_prfx_leg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_prfx_rex(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t);

void x86_64_inst_mod(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t);

void x86_64_inst_k16(uint8_t*, uint64_t*, uint16_t);

void x86_64_inst_k32(uint8_t*, uint64_t*, uint32_t);

void x86_64_inst_k64(uint8_t*, uint64_t*, uint64_t);

void x86_64_inst_lcp(uint8_t*, uint64_t*, uint8_t, int32_t);

void x86_64_inst_mvp(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_add_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_add_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_add_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_add_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_add_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_add_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_add_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_add_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_or_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_or_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_or_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_or_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_or_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_or_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_or_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_or_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_adc_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_adc_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_adc_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_adc_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_adc_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_adc_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_adc_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_adc_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_sbb_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sbb_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sbb_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_sbb_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_sbb_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sbb_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_sbb_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_sbb_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_and_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_and_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_and_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_and_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_and_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_and_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_and_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_and_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_sub_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sub_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sub_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_sub_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_sub_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sub_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_sub_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_sub_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_xor_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_xor_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_xor_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_xor_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_xor_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_xor_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_xor_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_xor_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_cmp_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_cmp_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_cmp_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_cmp_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_cmp_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_cmp_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_cmp_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_cmp_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_push_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_push_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_push_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_pop_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_pop_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_jo_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jno_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jc_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jnc_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_je_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jne_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jna_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_ja_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_js_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jns_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jpe_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jpo_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jl_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jge_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jle_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jg_imm(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_xchg_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_xchg_reg_reg(uint8_t*, uint64_t*, uint8_t, uint8_t);

void x86_64_enc_mov_addr_reg(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_mov_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_mov_reg_reg(uint8_t*, uint64_t*, uint8_t rd, uint8_t rs);

void x86_64_enc_mov_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_mov_addr_k8(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_mov_addr_k16(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint16_t);

void x86_64_enc_mov_addr_k32(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_mov_addr_k64(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint32_t);

void x86_64_enc_lea_reg_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rol_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_rol_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_rolb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rolw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rold_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rolq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rolb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rolw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rold_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rolq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_ror_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_ror_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_rorb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rorw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rord_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rorq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rorb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rorw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rord_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rorq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rcl_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_rcl_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_rclb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rclw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rcld_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rclq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rclb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rclw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rcld_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rclq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rcr_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_rcr_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_rcrb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rcrw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rcrd_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rcrq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_rcrb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rcrw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rcrd_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_rcrq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shl_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_shl_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_shlb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shlw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shld_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shlq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shlb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shlw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shld_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shlq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shr_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_shr_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_shrb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shrw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shrd_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shrq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_shrb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shrw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shrd_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_shrq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sal_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_sal_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_salb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_salw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sald_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_salq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_salb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_salw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sald_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_salq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sar_reg_cl(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_sar_reg_imm(uint8_t*, uint64_t*, uint8_t, uint64_t);

void x86_64_enc_sarb_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sarw_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sard_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sarq_addr_cl(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_sarb_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sarw_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sard_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_sarq_addr_imm(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t, uint8_t);

void x86_64_enc_ret(uint8_t*, uint64_t*);

void x86_64_enc_int(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_call(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_call_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_call_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_jmp(uint8_t*, uint64_t*, uint32_t);

void x86_64_enc_jmp_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_jmp_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_not_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_notb_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_notw_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_notd_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_notq_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_neg_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_negb_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_negw_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_negd_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_negq_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_mul_rax_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_mulb_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_mulw_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_muld_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_mulq_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_imul_rax_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_imulb_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_imulw_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_imuld_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_imulq_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_div_rax_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_divb_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_divw_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_divd_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_divq_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_idiv_rax_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_idivb_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_idivw_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_idivd_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_idivq_rax_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_inc_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_incb_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_incw_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_incd_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_incq_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_dec_reg(uint8_t*, uint64_t*, uint8_t);

void x86_64_enc_decb_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_decw_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_decd_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_decq_addr(uint8_t*, uint64_t*, uint8_t, uint8_t, uint8_t, int32_t);

void x86_64_enc_syscall(uint8_t*, uint64_t*);

