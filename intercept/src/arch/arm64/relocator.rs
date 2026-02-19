use crate::arch::arm64::writer::{Arm64Writer, Reg};
use crate::types::HookError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InsnKind {
    Other,
    B,
    BL,
    BCond,
    CbzCbnz,
    TbzTbnz,
    Adr,
    Adrp,
    LdrLiteral64,
    LdrLiteral32,
    LdrLiteralFp64,
    LdrLiteralFp32,
    LdrLiteralFp128,
    Ldrsw,
}

fn insn_kind(insn: u32) -> InsnKind {
    // B / BL
    match insn & 0xFC00_0000 {
        0x1400_0000 => return InsnKind::B,
        0x9400_0000 => return InsnKind::BL,
        _ => {}
    }

    // B.cond: 0b01010100 imm19 cond (bit4 must be 0)
    if (insn & 0xFF00_0010) == 0x5400_0000 {
        return InsnKind::BCond;
    }

    // CBZ/CBNZ: 0b?0110100 / 0b?0110101
    match insn & 0x7F00_0000 {
        0x3400_0000 | 0x3500_0000 => return InsnKind::CbzCbnz,
        0x3600_0000 | 0x3700_0000 => return InsnKind::TbzTbnz,
        _ => {}
    }

    // ADR / ADRP
    if (insn & 0x9F00_0000) == 0x1000_0000 {
        return InsnKind::Adr;
    }
    if (insn & 0x9F00_0000) == 0x9000_0000 {
        return InsnKind::Adrp;
    }

    // LDR (literal) 64-bit
    if (insn & 0xFF00_0000) == 0x5800_0000 {
        return InsnKind::LdrLiteral64;
    }

    // LDR (literal) 32-bit: LDR Wt, [PC, #imm]
    if (insn & 0xFF00_0000) == 0x1800_0000 {
        return InsnKind::LdrLiteral32;
    }

    // LDR (literal) SIMD/FP 64-bit: LDR Dt, [PC, #imm]
    if (insn & 0xFF00_0000) == 0x5C00_0000 {
        return InsnKind::LdrLiteralFp64;
    }

    // LDR (literal) SIMD/FP 32-bit: LDR St, [PC, #imm]
    if (insn & 0xFF00_0000) == 0x1C00_0000 {
        return InsnKind::LdrLiteralFp32;
    }

    // LDR (literal) SIMD/FP 128-bit: LDR Qt, [PC, #imm]
    if (insn & 0xFF00_0000) == 0x9C00_0000 {
        return InsnKind::LdrLiteralFp128;
    }

    // LDRSW (literal): LDRSW Xt, [PC, #imm]
    if (insn & 0xFF00_0000) == 0x9800_0000 {
        return InsnKind::Ldrsw;
    }

    InsnKind::Other
}

fn sign_extend(value: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (value << shift) >> shift
}

fn decode_imm26(insn: u32) -> i64 {
    let imm26 = (insn & 0x03FF_FFFF) as i64;
    sign_extend(imm26, 26)
}

fn decode_imm21_adr(insn: u32) -> i64 {
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = ((insn >> 5) & 0x7ffff) as i64;
    let imm = (immhi << 2) | immlo;
    sign_extend(imm, 21)
}

fn decode_imm19(insn: u32) -> i64 {
    let imm19 = ((insn >> 5) & 0x7ffff) as i64;
    sign_extend(imm19, 19)
}

fn decode_imm14(insn: u32) -> i64 {
    let imm14 = ((insn >> 5) & 0x3fff) as i64;
    sign_extend(imm14, 14)
}

fn rd(insn: u32) -> u32 {
    insn & 0x1f
}

fn branch_target(pc: u64, insn: u32) -> u64 {
    let imm26 = decode_imm26(insn);
    let off = imm26 << 2;
    (pc as i64).wrapping_add(off) as u64
}

fn branch_target_imm19(pc: u64, insn: u32) -> u64 {
    let off = decode_imm19(insn) << 2;
    (pc as i64).wrapping_add(off) as u64
}

fn branch_target_imm14(pc: u64, insn: u32) -> u64 {
    let off = decode_imm14(insn) << 2;
    (pc as i64).wrapping_add(off) as u64
}

fn invert_cond(cond: u32) -> u32 {
    // ARM condition codes are paired (eq/ne, cs/cc, ...). Inversion toggles bit 0.
    (cond ^ 1) & 0xf
}

unsafe fn emit_b_cond_skip(writer: &mut Arm64Writer, cond: u32) {
    // Skip over the long-branch stub:
    //   b.<invcond> +20
    //   ldr x16, [pc,#8]
    //   br  x16
    //   .quad target
    //
    // B.cond uses imm19<<2 from the instruction's PC. To reach pc+20, imm19=5.
    const SKIP_IMM19: u32 = 5;
    let imm19 = SKIP_IMM19 & 0x7ffff;
    let insn = 0x5400_0000 | (imm19 << 5) | (cond & 0xf);
    writer.put_u32_raw(insn);
}

unsafe fn emit_cbz_cbnz_skip(writer: &mut Arm64Writer, insn: u32, invert: bool) {
    // Same skip distance as above: 20 bytes => imm19=5.
    const SKIP_IMM19: u32 = 5;
    let mut out = insn;
    if invert {
        out ^= 1 << 24; // toggle op (cbz <-> cbnz), preserve sf+rt
    }
    out = (out & !0x00FF_FFE0) | ((SKIP_IMM19 & 0x7ffff) << 5);
    writer.put_u32_raw(out);
}

unsafe fn emit_tbz_tbnz_skip(writer: &mut Arm64Writer, insn: u32, invert: bool) {
    // TBZ/TBNZ uses imm14<<2 from the instruction's PC. 20 bytes => imm14=5.
    const SKIP_IMM14: u32 = 5;
    let mut out = insn;
    if invert {
        out ^= 1 << 24; // toggle op (tbz <-> tbnz)
    }
    out = (out & !0x0007_FFE0) | ((SKIP_IMM14 & 0x3fff) << 5);
    writer.put_u32_raw(out);
}

fn estimated_size(kind: InsnKind) -> usize {
    match kind {
        InsnKind::Other => 4,
        InsnKind::Adr | InsnKind::Adrp => 16,
        InsnKind::LdrLiteral64
        | InsnKind::LdrLiteral32
        | InsnKind::LdrLiteralFp64
        | InsnKind::LdrLiteralFp32
        | InsnKind::LdrLiteralFp128
        | InsnKind::Ldrsw => 20,
        InsnKind::B => 16,     // LDR+BR+literal
        InsnKind::BL => 20,    // MOVZ/MOVK*4 + BLR
        InsnKind::BCond => 20, // b.<invcond> + long branch
        InsnKind::CbzCbnz => 20,
        InsnKind::TbzTbnz => 20,
    }
}

/// Check if a given instruction uses register X16 or X17.
fn insn_uses_x16_x17(insn: u32) -> (bool, bool) {
    let mut x16 = false;
    let mut x17 = false;

    // Check common register fields:
    //   Rd/Rt (bits 0-4), Rn (bits 5-9), Rt2 (bits 14-10), Rm (bits 16-20)
    // Rt2 is used by STP/LDP for the second register. On non-STP/LDP instructions
    // bits 14-10 may be immediate fields, causing conservative false positives —
    // this is acceptable (we pick the other scratch register unnecessarily).
    let rd = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rt2 = (insn >> 10) & 0x1f;
    let rm = (insn >> 16) & 0x1f;

    // Don't flag SP (31) as X16/X17.
    for r in [rd, rn, rt2, rm] {
        if r == 16 {
            x16 = true;
        }
        if r == 17 {
            x17 = true;
        }
    }

    (x16, x17)
}

/// Determine the maximum number of instructions that can be safely relocated
/// from a function prologue, and which scratch register (X16 or X17) is available.
///
/// Returns `(max_insns, scratch_reg)` where max_insns is the safe relocation
/// limit and scratch_reg is the register available for long-branch stubs.
/// Stops relocation at BL/BLR boundaries.
///
/// # Safety
/// `input` must point to at least `max_insns` valid ARM64 instructions.
pub unsafe fn can_relocate(input: *const u32, max_insns: usize) -> (usize, Reg) {
    let mut limit = max_insns;
    let mut x16_used = false;
    let mut x17_used = false;

    for i in 0..max_insns {
        let insn = unsafe { input.add(i).read() };
        let kind = insn_kind(insn);

        // Check scratch register usage.
        let (u16, u17) = insn_uses_x16_x17(insn);
        x16_used |= u16;
        x17_used |= u17;

        // BL and BLR mark boundaries where further relocation is unsafe
        // (they set LR to pc+4, creating a return-address dependency).
        //
        // Note: SVC (syscall trap) is NOT a boundary — it is fully
        // position-independent and the relocator copies it verbatim.
        // On macOS the dyld shared cache has no free pages for near
        // allocation, so we must relocate past SVC to reach enough
        // instructions for the redirect patch.
        let is_blr = (insn & 0xFFFF_FC1F) == 0xD63F_0000;

        if kind == InsnKind::BL || is_blr {
            // Include this instruction but stop after it.
            limit = i + 1;
            break;
        }
    }

    let scratch = if !x16_used {
        Reg::X16
    } else if !x17_used {
        Reg::X17
    } else {
        // Both used - we'll still use X16 but this is a known limitation.
        // In practice, prologues rarely use both x16 and x17.
        Reg::X16
    };

    (limit, scratch)
}

pub struct Arm64Relocator {
    input: *const u32,
    input_pc: u64,
    pos: usize,
}

impl Arm64Relocator {
    pub fn new(input: *const u32, input_pc: u64) -> Self {
        Self {
            input,
            input_pc,
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// # Safety
    /// The writer must have sufficient capacity and the source instructions must be valid.
    pub unsafe fn relocate_n(
        &mut self,
        writer: &mut Arm64Writer,
        count: usize,
    ) -> Result<(), HookError> {
        if count == 0 {
            return Ok(());
        }

        let start_pos = self.pos;
        let start_src_pc = self.input_pc + (start_pos as u64) * 4;
        let src_bytes = (count as u64) * 4;
        let end_src_pc = start_src_pc + src_bytes;

        // Read source instructions.
        let mut insns: Vec<u32> = Vec::with_capacity(count);
        for i in 0..count {
            insns.push(self.input.add(self.pos + i).read());
        }

        // Build a mapping from original instruction PCs to their relocated PCs.
        let mut src_pcs: Vec<u64> = Vec::with_capacity(count);
        let mut dst_pcs: Vec<u64> = Vec::with_capacity(count);
        let mut cur_dst_pc = writer.pc();
        for (i, &insn) in insns.iter().enumerate().take(count) {
            let src_pc = self.input_pc + ((self.pos + i) as u64) * 4;
            src_pcs.push(src_pc);
            dst_pcs.push(cur_dst_pc);
            cur_dst_pc = cur_dst_pc.wrapping_add(estimated_size(insn_kind(insn)) as u64);
        }

        let map_dst = |target: u64| -> u64 {
            if target < start_src_pc || target >= end_src_pc {
                return target;
            }
            let idx = ((target - start_src_pc) / 4) as usize;
            if idx < dst_pcs.len() {
                dst_pcs[idx]
            } else {
                target
            }
        };

        // Emit relocated instructions.
        for (i, &insn) in insns.iter().enumerate() {
            let src_pc = src_pcs[i];
            self.pos += 1;

            match insn_kind(insn) {
                InsnKind::Other => {
                    writer.put_u32_raw(insn);
                }
                InsnKind::Adr => {
                    let target = (src_pc as i64).wrapping_add(decode_imm21_adr(insn)) as u64;
                    let dst = rd(insn);
                    writer.put_ldr_reg_address(core::mem::transmute::<u8, Reg>(dst as u8), target);
                }
                InsnKind::Adrp => {
                    let imm = decode_imm21_adr(insn);
                    let target = ((src_pc & !0xfffu64) as i64).wrapping_add(imm << 12) as u64;
                    let dst = rd(insn);
                    writer.put_ldr_reg_address(core::mem::transmute::<u8, Reg>(dst as u8), target);
                }
                InsnKind::LdrLiteral64 => {
                    let target_addr = (src_pc as i64).wrapping_add(decode_imm19(insn) << 2) as u64;
                    let rt = rd(insn);
                    let scratch: u8 = if rt == 16 { 17 } else { 16 };
                    writer
                        .put_ldr_reg_address(core::mem::transmute::<u8, Reg>(scratch), target_addr);
                    writer.put_ldr_reg_reg_offset(
                        core::mem::transmute::<u8, Reg>(rt as u8),
                        core::mem::transmute::<u8, Reg>(scratch),
                        0,
                    );
                }
                InsnKind::LdrLiteral32 => {
                    // LDR Wt, [PC, #imm] — 32-bit GPR literal load.
                    let target_addr = (src_pc as i64).wrapping_add(decode_imm19(insn) << 2) as u64;
                    let rt = rd(insn);
                    let scratch: u8 = if rt == 16 { 17 } else { 16 };
                    writer
                        .put_ldr_reg_address(core::mem::transmute::<u8, Reg>(scratch), target_addr);
                    // LDR Wt, [Xscratch, #0] — 32-bit unsigned offset load.
                    // Encoding: 0xB9400000 | (imm12 << 10) | (rn << 5) | rt
                    writer.put_u32_raw(0xB940_0000 | ((scratch as u32) << 5) | rt);
                }
                InsnKind::LdrLiteralFp64 => {
                    // LDR Dt, [PC, #imm] — 64-bit SIMD/FP literal load.
                    let target_addr = (src_pc as i64).wrapping_add(decode_imm19(insn) << 2) as u64;
                    let rt = rd(insn);
                    // FP registers don't conflict with GPR X16/X17, always use X16.
                    let scratch: u8 = 16;
                    writer
                        .put_ldr_reg_address(core::mem::transmute::<u8, Reg>(scratch), target_addr);
                    // LDR Dt, [X16, #0] — FP 64-bit load from GPR base.
                    // Encoding: 0xFD400000 | (imm12 << 10) | (rn << 5) | rt
                    writer.put_u32_raw(0xFD40_0000 | ((scratch as u32) << 5) | rt);
                }
                InsnKind::LdrLiteralFp32 => {
                    // LDR St, [PC, #imm] — 32-bit SIMD/FP literal load.
                    let target_addr = (src_pc as i64).wrapping_add(decode_imm19(insn) << 2) as u64;
                    let rt = rd(insn);
                    // FP registers don't conflict with GPR X16/X17, always use X16.
                    let scratch: u8 = 16;
                    writer
                        .put_ldr_reg_address(core::mem::transmute::<u8, Reg>(scratch), target_addr);
                    // LDR St, [X16, #0] — FP 32-bit load from GPR base.
                    // Encoding: 0xBD400000 | (imm12 << 10) | (rn << 5) | rt
                    writer.put_u32_raw(0xBD40_0000 | ((scratch as u32) << 5) | rt);
                }
                InsnKind::LdrLiteralFp128 => {
                    // LDR Qt, [PC, #imm] — 128-bit SIMD/FP literal load.
                    let target_addr = (src_pc as i64).wrapping_add(decode_imm19(insn) << 2) as u64;
                    let rt = rd(insn);
                    // FP registers don't conflict with GPR X16/X17, always use X16.
                    let scratch: u8 = 16;
                    writer
                        .put_ldr_reg_address(core::mem::transmute::<u8, Reg>(scratch), target_addr);
                    // LDR Qt, [X16, #0] — FP 128-bit load from GPR base.
                    // Encoding: 0x3DC00000 | (imm12 << 10) | (rn << 5) | rt
                    writer.put_u32_raw(0x3DC0_0000 | ((scratch as u32) << 5) | rt);
                }
                InsnKind::Ldrsw => {
                    // LDRSW Xt, [PC, #imm] — sign-extending 32-bit literal load.
                    let target_addr = (src_pc as i64).wrapping_add(decode_imm19(insn) << 2) as u64;
                    let rt = rd(insn);
                    let scratch: u8 = if rt == 16 { 17 } else { 16 };
                    writer
                        .put_ldr_reg_address(core::mem::transmute::<u8, Reg>(scratch), target_addr);
                    // LDRSW Xt, [Xscratch, #0] — signed 32-bit load.
                    // Encoding: 0xB9800000 | (imm12 << 10) | (rn << 5) | rt
                    writer.put_u32_raw(0xB980_0000 | ((scratch as u32) << 5) | rt);
                }
                InsnKind::B => {
                    let target = map_dst(branch_target(src_pc, insn));
                    writer.put_ldr_br_address(Reg::X16, target);
                }
                InsnKind::BL => {
                    let target = map_dst(branch_target(src_pc, insn));
                    writer.put_mov_reg_u64(Reg::X16, target);
                    writer.put_blr_reg(Reg::X16);
                }
                InsnKind::BCond => {
                    let target = map_dst(branch_target_imm19(src_pc, insn));
                    let cond = insn & 0xf;

                    // If this is effectively unconditional, just do a long branch.
                    if cond == 0xe || cond == 0xf {
                        writer.put_ldr_br_address(Reg::X16, target);
                    } else {
                        emit_b_cond_skip(writer, invert_cond(cond));
                        writer.put_ldr_br_address(Reg::X16, target);
                    }
                }
                InsnKind::CbzCbnz => {
                    let target = map_dst(branch_target_imm19(src_pc, insn));
                    emit_cbz_cbnz_skip(writer, insn, true);
                    writer.put_ldr_br_address(Reg::X16, target);
                }
                InsnKind::TbzTbnz => {
                    let target = map_dst(branch_target_imm14(src_pc, insn));
                    emit_tbz_tbnz_skip(writer, insn, true);
                    writer.put_ldr_br_address(Reg::X16, target);
                }
            }
        }

        // Sanity: ensure we advanced exactly `count` instructions.
        debug_assert_eq!(self.pos, start_pos + count);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(buf: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
    }

    fn read_u64(buf: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
    }

    /// Non-PC-relative instructions copy verbatim.
    #[test]
    fn relocator_one_to_one() {
        let input: [u32; 2] = [0xa9be4ff4, 0x92800210]; // STP, MOVN
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 2).unwrap();
            assert_eq!(w.offset(), 8, "two non-PC-relative insns → 8 bytes");
        }
        assert_eq!(read_u32(&buf, 0), 0xa9be4ff4);
        assert_eq!(read_u32(&buf, 4), 0x92800210);
    }

    /// LDR X16, [PC, #+8] → scratch-load + deref.
    #[test]
    fn relocator_ldr_x_should_be_rewritten() {
        // LDR X16, [PC, #+8]: rt=16, imm19=2
        let input: [u32; 1] = [0x58000050];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "LDR literal expands to 20 bytes");
        }
        // Since rt=16, scratch=17. Emits: LDR X17,[PC,#8]; B +12; .quad 2056; LDR X16,[X17]
        assert_eq!(read_u32(&buf, 0), 0x58000051, "LDR X17, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12 (skip literal)");
        assert_eq!(read_u64(&buf, 8), 2056, "literal = input_pc + 8");
        assert_eq!(read_u32(&buf, 16), 0xF9400230, "LDR X16, [X17, #0]");
    }

    /// ADR X1, #+0x14E6 → load absolute address via literal pool.
    #[test]
    fn relocator_adr_should_be_rewritten() {
        let input: [u32; 1] = [0x5000a721]; // ADR X1, #+5350
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 16, "ADR expands to 16 bytes");
        }
        // Target: input_pc + 0x14E6 = 2048 + 5350 = 7398
        assert_eq!(read_u32(&buf, 0), 0x58000041, "LDR X1, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12");
        assert_eq!(read_u64(&buf, 8), 7398, "literal = 2048 + 5350");
    }

    /// ADRP X3, #+0x14E6 pages → load page-aligned address via literal pool.
    #[test]
    fn relocator_adrp_should_be_rewritten() {
        let input: [u32; 1] = [0xd000a723]; // ADRP X3
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 16, "ADRP expands to 16 bytes");
        }
        // Target: (input_pc & ~0xFFF) + 5350 << 12 = 0 + 0x14E6000
        assert_eq!(read_u32(&buf, 0), 0x58000043, "LDR X3, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12");
        assert_eq!(read_u64(&buf, 8), 0x14E6000, "literal = ADRP target");
    }

    /// CBZ X0, #+24 → inverted CBNZ skip + LDR+BR stub.
    #[test]
    fn relocator_cbz_should_be_rewritten() {
        // CBZ X0, #+24: sf=1, op=0(CBZ), imm19=6, rt=0
        let input: [u32; 1] = [0xb40000c0];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "CBZ expands to 20 bytes");
        }
        // Inverted CBNZ X0, #+20 (imm19=5)
        assert_eq!(read_u32(&buf, 0), 0xb50000a0, "CBNZ X0 skip");
        // LDR X16, [PC, #8]; BR X16; .quad target
        assert_eq!(read_u32(&buf, 4), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 8), 0xD61F0200, "BR X16");
        assert_eq!(read_u64(&buf, 12), 2072, "target = 2048 + 24");
    }

    /// TBNZ W1, #9, #+12 → inverted TBZ skip + LDR+BR stub.
    #[test]
    fn relocator_tbnz_should_be_rewritten() {
        // TBNZ W1, #9, #+12: op=1(TBNZ), b40=9, imm14=3, rt=1
        let input: [u32; 1] = [0x37480061];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "TBNZ expands to 20 bytes");
        }
        // Inverted TBZ W1, #9, #+20 (imm14=5)
        assert_eq!(read_u32(&buf, 0), 0x364800a1, "TBZ W1, #9 skip");
        assert_eq!(read_u32(&buf, 4), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 8), 0xD61F0200, "BR X16");
        assert_eq!(read_u64(&buf, 12), 2060, "target = 2048 + 12");
    }

    /// B.LO #+24 → inverted B.HS skip + LDR+BR stub.
    #[test]
    fn relocator_b_cond_should_be_rewritten() {
        // B.LO #+24: imm19=6, cond=3 (LO)
        let input: [u32; 1] = [0x540000c3];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "B.cond expands to 20 bytes");
        }
        // Inverted: B.HS #+20 (cond=2, imm19=5)
        assert_eq!(read_u32(&buf, 0), 0x540000a2, "B.HS skip");
        assert_eq!(read_u32(&buf, 4), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 8), 0xD61F0200, "BR X16");
        assert_eq!(read_u64(&buf, 12), 2072, "target = 2048 + 24");
    }

    /// B #-664 → LDR X16 + BR with absolute target.
    #[test]
    fn relocator_b_should_be_rewritten() {
        let input: [u32; 1] = [0x17ffff5a]; // B #-664
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 16, "B expands to 16 bytes (LDR+BR+literal)");
        }
        // Target: 2048 - 664 = 1384
        assert_eq!(read_u32(&buf, 0), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0xD61F0200, "BR X16");
        assert_eq!(read_u64(&buf, 8), 1384, "literal = 2048 - 664");
    }

    /// BL #-664 → MOVZ/MOVK chain + BLR X16.
    #[test]
    fn relocator_bl_should_be_rewritten() {
        let input: [u32; 1] = [0x97ffff5a]; // BL #-664
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "BL expands to 20 bytes (MOVZ/MOVK*3+BLR)");
        }
        // Target: 1384 = 0x568
        assert_eq!(read_u32(&buf, 0), 0xD280AD10, "MOVZ X16, #0x568");
        assert_eq!(read_u32(&buf, 4), 0xF2A00010, "MOVK X16, #0, LSL #16");
        assert_eq!(read_u32(&buf, 8), 0xF2C00010, "MOVK X16, #0, LSL #32");
        assert_eq!(read_u32(&buf, 12), 0xF2E00010, "MOVK X16, #0, LSL #48");
        assert_eq!(read_u32(&buf, 16), 0xD63F0200, "BLR X16");
    }

    /// BLR is a relocation boundary — can_relocate stops after it.
    #[test]
    fn cannot_relocate_with_early_blr() {
        let insns: [u32; 4] = [
            0x58000050, // LDR X16, [PC, #+8]
            0xD63F0200, // BLR X16
            0xD503201F, // NOP
            0xD503201F, // NOP
        ];
        let (limit, scratch) = unsafe { can_relocate(insns.as_ptr(), 4) };
        assert_eq!(
            limit, 2,
            "BLR should stop relocation (include it, stop after)"
        );
        assert_eq!(scratch, Reg::X17, "x17 since x16 is used");
    }

    /// RET is NOT a relocation boundary.
    #[test]
    fn ret_is_not_end_of_block() {
        let insns: [u32; 4] = [
            0xD503201F, // NOP
            0xD503201F, // NOP
            0xD65F03C0, // RET
            0xD503201F, // NOP
        ];
        let (limit, scratch) = unsafe { can_relocate(insns.as_ptr(), 4) };
        assert_eq!(limit, 4, "RET is not a relocation boundary");
        assert_eq!(scratch, Reg::X16, "x16 available (no x16/x17 usage)");
    }

    #[test]
    fn relocate_cbz_to_intra_prologue_target_avoids_branching_into_patched_prologue() {
        // Build a tiny "function prologue":
        //   0x1000: cbz x0, +8  (target = 0x1008, i.e. third insn)
        //   0x1004: nop
        //   0x1008: nop
        //   0x100c: nop
        //
        // After relocation into a trampoline, the cbz must target the relocated third insn.
        let src_pc = 0x1000u64;
        let cbz = 0xB400_0000u32 | (2 << 5); // imm19=2 => +8, rt=x0, sf=1 (64-bit)
        let input = [cbz, 0xD503_201F, 0xD503_201F, 0xD503_201F];

        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = Arm64Relocator::new(input.as_ptr(), src_pc);
            r.relocate_n(&mut w, 4).unwrap();
        }

        // Expect first instruction is inverted cbz/cbnz with imm19=5 (skip stub).
        let first = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(first & 0x7F00_0000, 0xB500_0000 & 0x7F00_0000); // CBNZ class
        assert_eq!((first >> 5) & 0x7ffff, 5);

        // Literal in the long branch stub should point inside the relocated prologue (>= 0x2000).
        let lit = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        assert!((0x2000..0x2000 + 128).contains(&lit));
    }

    /// LDR W16, [PC, #+8] → scratch-load + 32-bit deref.
    #[test]
    fn relocator_ldr_w_should_be_rewritten() {
        // LDR W16, [PC, #+8]: opc=00, V=0, imm19=2, rt=16
        let input: [u32; 1] = [0x18000050];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "LDR W literal expands to 20 bytes");
        }
        // Since rt=16, scratch=17. Emits: LDR X17,[PC,#8]; B +12; .quad 2056; LDR W16,[X17]
        assert_eq!(read_u32(&buf, 0), 0x58000051, "LDR X17, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12 (skip literal)");
        assert_eq!(read_u64(&buf, 8), 2056, "literal = input_pc + 8");
        assert_eq!(read_u32(&buf, 16), 0xB9400230, "LDR W16, [X17, #0]");
    }

    /// LDR D0, [PC, #+8] → scratch-load + FP 64-bit deref.
    #[test]
    fn relocator_ldr_d_should_be_rewritten() {
        // LDR D0, [PC, #+8]: opc=01, V=1, imm19=2, rt=0
        let input: [u32; 1] = [0x5C000040];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "LDR D literal expands to 20 bytes");
        }
        // FP reg doesn't conflict with GPR, scratch=X16.
        // Emits: LDR X16,[PC,#8]; B +12; .quad 2056; LDR D0,[X16]
        assert_eq!(read_u32(&buf, 0), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12 (skip literal)");
        assert_eq!(read_u64(&buf, 8), 2056, "literal = input_pc + 8");
        assert_eq!(read_u32(&buf, 16), 0xFD400200, "LDR D0, [X16, #0]");
    }

    /// LDRSW X16, [PC, #+8] → scratch-load + signed 32-bit deref.
    #[test]
    fn relocator_ldrsw_should_be_rewritten() {
        // LDRSW X16, [PC, #+8]: opc=10, V=0, imm19=2, rt=16
        let input: [u32; 1] = [0x98000050];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "LDRSW expands to 20 bytes");
        }
        // Since rt=16, scratch=17.
        // Emits: LDR X17,[PC,#8]; B +12; .quad 2056; LDRSW X16,[X17]
        assert_eq!(read_u32(&buf, 0), 0x58000051, "LDR X17, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12 (skip literal)");
        assert_eq!(read_u64(&buf, 8), 2056, "literal = input_pc + 8");
        assert_eq!(read_u32(&buf, 16), 0xB9800230, "LDRSW X16, [X17, #0]");
    }

    /// BR is intentionally NOT a boundary.
    /// BR is position-independent: it jumps to a register value, so the
    /// relocated copy behaves identically to the original.
    #[test]
    fn can_relocate_does_not_stop_at_br() {
        let insns: [u32; 4] = [
            0xD503201F, // NOP
            0xD61F0200, // BR X16
            0xD503201F, // NOP
            0xD503201F, // NOP
        ];
        let (limit, _scratch) = unsafe { can_relocate(insns.as_ptr(), 4) };
        assert_eq!(
            limit, 4,
            "BR is position-independent and should not stop relocation"
        );
    }

    /// LDR S0, [PC, #+8] → scratch-load + FP 32-bit deref.
    #[test]
    fn relocator_ldr_s_should_be_rewritten() {
        // LDR S0, [PC, #+8]: opc=00, V=1, imm19=2, rt=0
        let input: [u32; 1] = [0x1C000040];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "LDR S literal expands to 20 bytes");
        }
        // FP reg doesn't conflict with GPR, scratch=X16.
        // Emits: LDR X16,[PC,#8]; B +12; .quad 2056; LDR S0,[X16]
        assert_eq!(read_u32(&buf, 0), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12 (skip literal)");
        assert_eq!(read_u64(&buf, 8), 2056, "literal = input_pc + 8");
        assert_eq!(read_u32(&buf, 16), 0xBD400200, "LDR S0, [X16, #0]");
    }

    /// LDR Q0, [PC, #+8] → scratch-load + FP 128-bit deref.
    #[test]
    fn relocator_ldr_q_should_be_rewritten() {
        // LDR Q0, [PC, #+8]: opc=00, V=1, imm19=2, rt=0 (with size=11)
        let input: [u32; 1] = [0x9C000040];
        let mut buf = [0u8; 128];
        unsafe {
            let mut w = Arm64Writer::new(buf.as_mut_ptr(), buf.len(), 1024);
            let mut r = Arm64Relocator::new(input.as_ptr(), 2048);
            r.relocate_n(&mut w, 1).unwrap();
            assert_eq!(w.offset(), 20, "LDR Q literal expands to 20 bytes");
        }
        // FP reg doesn't conflict with GPR, scratch=X16.
        // Emits: LDR X16,[PC,#8]; B +12; .quad 2056; LDR Q0,[X16]
        assert_eq!(read_u32(&buf, 0), 0x58000050, "LDR X16, [PC, #8]");
        assert_eq!(read_u32(&buf, 4), 0x14000003, "B +12 (skip literal)");
        assert_eq!(read_u64(&buf, 8), 2056, "literal = input_pc + 8");
        assert_eq!(read_u32(&buf, 16), 0x3DC00200, "LDR Q0, [X16, #0]");
    }

    /// STP X19, X16, [SP, #-16]! has X16 in Rt2 (bits 14-10) — scratch should be X17.
    #[test]
    fn can_relocate_detects_x16_in_stp_rt2() {
        // STP X19, X16, [SP, #-16]!
        // Encoding: 0xA9800000 | (0x7E << 15) | (16 << 10) | (31 << 5) | 19
        //         = 0xA9800000 | 0x003F0000 | 0x00004000 | 0x000003E0 | 0x13
        //         = 0xA9BF43F3
        let insns: [u32; 1] = [0xA9BF43F3];
        let (_limit, scratch) = unsafe { can_relocate(insns.as_ptr(), 1) };
        assert_eq!(scratch, Reg::X17, "X16 in Rt2 should cause fallback to X17");
    }

    /// STP X19, X17, [SP, #-16]! has X17 in Rt2 (bits 14-10) — scratch should be X16.
    #[test]
    fn can_relocate_detects_x17_in_stp_rt2() {
        // STP X19, X17, [SP, #-16]!
        // Same as above but Rt2=17: 0xA9BF47F3
        let insns: [u32; 1] = [0xA9BF47F3];
        let (_limit, scratch) = unsafe { can_relocate(insns.as_ptr(), 1) };
        assert_eq!(
            scratch,
            Reg::X16,
            "X17 in Rt2 should cause X16 to be chosen"
        );
    }
}
