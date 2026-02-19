use crate::arch::x86_64::writer::X86_64Writer;
use crate::types::HookError;

// ── Instruction classification ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InsnKind {
    Normal,      // Copy verbatim
    RipRelative, // Has ModRM with mod=0, rm=5 (RIP+disp32)
    JmpRel8,     // EB rel8
    JmpRel32,    // E9 rel32
    JccRel8,     // 70-7F rel8
    JccRel32,    // 0F 80-8F rel32
    CallRel32,   // E8 rel32
    Ret,         // C3 / C2
    End,         // INT3 (CC), UD2 (0F 0B), HLT (F4)
}

// ── Decoded instruction ──────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DecodedInsn {
    len: usize,
    kind: InsnKind,
    /// For RipRelative: byte offset within the instruction where the disp32 starts.
    rip_disp_offset: Option<usize>,
    /// For branches: the signed offset from instruction start.
    branch_offset: i64,
    /// For JccRel8/JccRel32: the condition code (lower 4 bits of opcode).
    cc: u8,
}

// ── Opcode tables ────────────────────────────────────────────────────

/// Returns true if a one-byte opcode (after legacy prefixes + REX) takes a ModRM byte.
fn one_byte_has_modrm(opcode: u8) -> bool {
    // Nearly all opcodes 0x00-0x3F in groups of 8 have ModRM for first 6 of each group.
    // Then 0x62-0x63, 0x69, 0x6B, 0x80-0x8F, 0xC0-0xC1, 0xC4-0xC5, 0xC6-0xC7,
    // 0xD0-0xD3, 0xF6-0xF7, 0xFE-0xFF, etc.
    match opcode {
        0x00..=0x03
        | 0x08..=0x0B
        | 0x10..=0x13
        | 0x18..=0x1B
        | 0x20..=0x23
        | 0x28..=0x2B
        | 0x30..=0x33
        | 0x38..=0x3B
        | 0x62..=0x63
        | 0x69
        | 0x6B
        | 0x80..=0x8F
        | 0xC0..=0xC1
        | 0xC4..=0xC7
        | 0xD0..=0xD3
        | 0xD8..=0xDF
        | 0xF6..=0xF7
        | 0xFE..=0xFF => true,
        _ => false,
    }
}

/// Returns the immediate size in bytes for a one-byte opcode.
/// Only covers common cases; returns 0 for opcodes without immediates.
fn one_byte_imm_size(opcode: u8, has_66_prefix: bool, has_rexw: bool) -> usize {
    match opcode {
        // Short ALU immediate forms
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => 1, // AL, imm8
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => {
            if has_66_prefix {
                2
            } else {
                4
            } // AX/EAX/RAX, imm16/32
        }
        0x68 => {
            if has_66_prefix {
                2
            } else {
                4
            }
        } // PUSH imm16/32
        0x69 => {
            if has_66_prefix {
                2
            } else {
                4
            }
        } // IMUL r, r/m, imm16/32
        0x6A | 0x6B => 1,        // PUSH imm8, IMUL r, r/m, imm8
        0x70..=0x7F => 1,        // Jcc rel8
        0x80 | 0x82 | 0x83 => 1, // group1 r/m, imm8
        0x81 => {
            if has_66_prefix {
                2
            } else {
                4
            }
        } // group1 r/m, imm16/32
        0xA0 => {
            if has_rexw {
                8
            } else {
                4
            }
        } // MOV AL, moffs
        0xA1 => {
            if has_rexw {
                8
            } else {
                4
            }
        } // MOV AX/EAX/RAX, moffs
        0xA2 => {
            if has_rexw {
                8
            } else {
                4
            }
        } // MOV moffs, AL
        0xA3 => {
            if has_rexw {
                8
            } else {
                4
            }
        } // MOV moffs, AX/EAX/RAX
        0xA8 => 1,               // TEST AL, imm8
        0xA9 => {
            if has_66_prefix {
                2
            } else {
                4
            }
        } // TEST AX/EAX/RAX, imm16/32
        0xB0..=0xB7 => 1,        // MOV r8, imm8
        0xB8..=0xBF => {
            // MOV r16/32/64, imm16/32/64
            if has_rexw {
                8
            } else if has_66_prefix {
                2
            } else {
                4
            }
        }
        0xC0..=0xC1 => 1, // Shift grp2 r/m, imm8
        0xC2 => 2,        // RET imm16
        0xC6 => 1,        // MOV r/m8, imm8
        0xC7 => {
            if has_66_prefix {
                2
            } else {
                4
            }
        } // MOV r/m16/32, imm16/32 (sign-extended to 64 if REX.W)
        0xC8 => 3,        // ENTER imm16, imm8
        0xCD => 1,        // INT imm8
        0xD4..=0xD5 => 1, // AAM/AAD (legacy)
        0xE0..=0xE3 => 1, // LOOPxx/JCXZ rel8
        0xE4..=0xE7 => 1, // IN/OUT imm8
        0xE8 | 0xE9 => 4, // CALL/JMP rel32
        0xEB => 1,        // JMP rel8
        0xF6 => 0,        // Handled via ModRM (TEST r/m8, imm8 is /0 with 1-byte imm)
        0xF7 => 0,        // Handled via ModRM (TEST r/m, imm is /0 with 4-byte imm)
        _ => 0,
    }
}

/// Returns true if a two-byte opcode (0F xx) takes a ModRM byte.
fn two_byte_has_modrm(opcode2: u8) -> bool {
    match opcode2 {
        // Most 0F xx opcodes have ModRM, major exceptions:
        0x05
        | 0x06
        | 0x07
        | 0x08
        | 0x09
        | 0x0B
        | 0x0E
        | 0xA0..=0xA1
        | 0xA8..=0xA9
        | 0x77
        | 0x30..=0x37 => false,
        0x80..=0x8F => false, // Jcc rel32 (no ModRM, has imm32)
        _ => true,
    }
}

/// Returns the immediate size for a two-byte opcode (0F xx).
fn two_byte_imm_size(opcode2: u8, _has_66: bool) -> usize {
    match opcode2 {
        0x70..=0x73 => 1, // SSE cmp with imm8
        0x80..=0x8F => 4, // Jcc rel32
        0xA4 | 0xAC => 1, // SHLD/SHRD imm8
        0xBA => 1,        // BT/BTS/BTR/BTC imm8
        0xC2 => 1,        // CMPPS/D imm8
        0xC4 => 1,        // PINSRW imm8
        0xC5 => 1,        // PEXTRW imm8
        0xC6 => 1,        // SHUFPS/D imm8
        _ => 0,
    }
}

/// For F6/F7 opcodes, the /0 and /1 reg fields indicate TEST which has an immediate.
fn group_test_imm_size(opcode: u8, modrm: u8, has_66: bool) -> usize {
    let reg = (modrm >> 3) & 7;
    if reg <= 1 {
        // /0 or /1 = TEST
        if opcode == 0xF6 {
            1
        }
        // TEST r/m8, imm8
        else if has_66 {
            2
        }
        // TEST r/m16, imm16
        else {
            4
        } // TEST r/m32, imm32
    } else {
        0
    }
}

// ── Instruction decoder ──────────────────────────────────────────────

/// Decode one x86_64 instruction at `input`. Returns the decoded instruction info.
///
/// This is a minimal decoder focused on prologue instructions and branch instructions
/// that need relocation. It handles legacy prefixes, REX, 1/2/3-byte opcodes,
/// ModRM+SIB+displacement, and immediates.
fn decode_insn(input: *const u8, _pc: u64) -> DecodedInsn {
    let mut pos = 0usize;

    let read = |p: usize| -> u8 { unsafe { input.add(p).read() } };
    let read_i8 = |p: usize| -> i8 { read(p) as i8 };
    let read_i32 = |p: usize| -> i32 { unsafe { (input.add(p) as *const i32).read_unaligned() } };

    // ── Legacy prefixes ──
    let mut has_66 = false;
    loop {
        match read(pos) {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {
                pos += 1;
            } // segment overrides + branch hints
            0x66 => {
                has_66 = true;
                pos += 1;
            }
            0x67 => {
                pos += 1;
            } // address-size
            0xF0 => {
                pos += 1;
            } // LOCK
            0xF2 | 0xF3 => {
                pos += 1;
            } // REPNE/REP
            _ => break,
        }
    }

    // ── REX prefix (0x40-0x4F) ──
    let mut has_rexw = false;
    let mut _rex_b = false;
    if read(pos) & 0xF0 == 0x40 {
        let rex = read(pos);
        has_rexw = (rex & 0x08) != 0;
        _rex_b = (rex & 0x01) != 0;
        pos += 1;
    }

    let _opcode_start = pos;
    let opcode = read(pos);
    pos += 1;

    // ── Special single-byte instructions ──

    // ENDBR64: F3 0F 1E FA — handled as a normal 4-byte sequence by prefix+2-byte decoder

    // RET
    if opcode == 0xC3 {
        return DecodedInsn {
            len: pos,
            kind: InsnKind::Ret,
            rip_disp_offset: None,
            branch_offset: 0,
            cc: 0,
        };
    }
    if opcode == 0xC2 {
        // RET imm16
        pos += 2;
        return DecodedInsn {
            len: pos,
            kind: InsnKind::Ret,
            rip_disp_offset: None,
            branch_offset: 0,
            cc: 0,
        };
    }

    // INT3, HLT
    if opcode == 0xCC || opcode == 0xF4 {
        return DecodedInsn {
            len: pos,
            kind: InsnKind::End,
            rip_disp_offset: None,
            branch_offset: 0,
            cc: 0,
        };
    }

    // JMP rel8
    if opcode == 0xEB {
        let off = read_i8(pos) as i64;
        pos += 1;
        return DecodedInsn {
            len: pos,
            kind: InsnKind::JmpRel8,
            rip_disp_offset: None,
            branch_offset: off,
            cc: 0,
        };
    }

    // JMP rel32
    if opcode == 0xE9 {
        let off = read_i32(pos) as i64;
        pos += 4;
        return DecodedInsn {
            len: pos,
            kind: InsnKind::JmpRel32,
            rip_disp_offset: None,
            branch_offset: off,
            cc: 0,
        };
    }

    // CALL rel32
    if opcode == 0xE8 {
        let off = read_i32(pos) as i64;
        pos += 4;
        // Detect CALL $+0 (PIC pattern): offset == 0
        return DecodedInsn {
            len: pos,
            kind: InsnKind::CallRel32,
            rip_disp_offset: None,
            branch_offset: off,
            cc: 0,
        };
    }

    // Jcc rel8 (70-7F)
    if opcode >= 0x70 && opcode <= 0x7F {
        let cc = opcode & 0x0F;
        let off = read_i8(pos) as i64;
        pos += 1;
        return DecodedInsn {
            len: pos,
            kind: InsnKind::JccRel8,
            rip_disp_offset: None,
            branch_offset: off,
            cc,
        };
    }

    // ── Two-byte opcode (0F xx) ──
    if opcode == 0x0F {
        let opcode2 = read(pos);
        pos += 1;

        // UD2
        if opcode2 == 0x0B {
            return DecodedInsn {
                len: pos,
                kind: InsnKind::End,
                rip_disp_offset: None,
                branch_offset: 0,
                cc: 0,
            };
        }

        // Jcc rel32 (0F 80-8F)
        if opcode2 >= 0x80 && opcode2 <= 0x8F {
            let cc = opcode2 & 0x0F;
            let off = read_i32(pos) as i64;
            pos += 4;
            return DecodedInsn {
                len: pos,
                kind: InsnKind::JccRel32,
                rip_disp_offset: None,
                branch_offset: off,
                cc,
            };
        }

        // ModRM for 2-byte opcode
        let mut rip_disp_offset = None;
        if two_byte_has_modrm(opcode2) {
            let modrm = read(pos);
            pos += 1;
            let mod_ = modrm >> 6;
            let rm = modrm & 7;

            if mod_ == 0 && rm == 5 {
                // RIP-relative
                rip_disp_offset = Some(pos);
                pos += 4;
            } else if mod_ != 3 {
                // SIB
                if rm == 4 {
                    pos += 1; // SIB byte
                }
                // Displacement
                match mod_ {
                    0 => {
                        if rm == 5 { /* already handled */ }
                        // rm=4 with SIB: check SIB base
                        // If SIB base=5 and mod=0, there's a disp32
                        if rm == 4 {
                            let sib = read(pos - 1);
                            let sib_base = sib & 7;
                            if sib_base == 5 {
                                pos += 4; // disp32
                            }
                        }
                    }
                    1 => {
                        pos += 1;
                    } // disp8
                    2 => {
                        pos += 4;
                    } // disp32
                    _ => {}
                }
            }
        }

        // Immediate for 2-byte opcode
        let imm_sz = two_byte_imm_size(opcode2, has_66);
        pos += imm_sz;

        let kind = if rip_disp_offset.is_some() {
            InsnKind::RipRelative
        } else {
            InsnKind::Normal
        };
        return DecodedInsn {
            len: pos,
            kind,
            rip_disp_offset,
            branch_offset: 0,
            cc: 0,
        };
    }

    // ── Three-byte opcodes (0F 38 xx, 0F 3A xx) ──
    // These are primarily SSE/AVX and always have ModRM. Handled generically.

    // ── One-byte opcode with ModRM ──
    let mut rip_disp_offset = None;
    if one_byte_has_modrm(opcode) {
        let modrm = read(pos);
        pos += 1;
        let mod_ = modrm >> 6;
        let rm = modrm & 7;

        if mod_ == 0 && rm == 5 {
            // RIP-relative
            rip_disp_offset = Some(pos);
            pos += 4;
        } else if mod_ != 3 {
            if rm == 4 {
                pos += 1; // SIB
            }
            match mod_ {
                0 => {
                    if rm == 4 {
                        let sib = read(pos - 1);
                        let sib_base = sib & 7;
                        if sib_base == 5 {
                            pos += 4;
                        }
                    }
                }
                1 => {
                    pos += 1;
                }
                2 => {
                    pos += 4;
                }
                _ => {}
            }
        }

        // Extra immediate for F6/F7 TEST
        if opcode == 0xF6 || opcode == 0xF7 {
            pos += group_test_imm_size(opcode, modrm, has_66);
        } else {
            pos += one_byte_imm_size(opcode, has_66, has_rexw);
        }
    } else {
        // No ModRM — just immediate
        pos += one_byte_imm_size(opcode, has_66, has_rexw);
    }

    let kind = if rip_disp_offset.is_some() {
        InsnKind::RipRelative
    } else {
        InsnKind::Normal
    };
    DecodedInsn {
        len: pos,
        kind,
        rip_disp_offset,
        branch_offset: 0,
        cc: 0,
    }
}

// ── ENDBR64 detection ────────────────────────────────────────────────

/// Returns true if the bytes at `p` are ENDBR64 (F3 0F 1E FA).
pub fn is_endbr64(p: *const u8) -> bool {
    unsafe {
        p.read() == 0xF3
            && p.add(1).read() == 0x0F
            && p.add(2).read() == 0x1E
            && p.add(3).read() == 0xFA
    }
}

// ── Public API ───────────────────────────────────────────────────────

pub struct X86_64Relocator {
    input: *const u8,
    input_pc: u64,
}

impl X86_64Relocator {
    pub fn new(input: *const u8, input_pc: u64) -> Self {
        Self { input, input_pc }
    }

    /// Relocate at least `min_bytes` of instructions from `input` to `writer`.
    /// Returns the number of source bytes consumed.
    pub unsafe fn relocate_bytes(
        &mut self,
        writer: &mut X86_64Writer,
        min_bytes: usize,
    ) -> Result<usize, HookError> {
        let mut src_offset = 0usize;

        while src_offset < min_bytes {
            let src_pc = self.input_pc + src_offset as u64;
            let insn = decode_insn(self.input.add(src_offset), src_pc);

            if insn.len == 0 {
                return Err(HookError::RelocationFailed);
            }

            match insn.kind {
                InsnKind::Ret | InsnKind::End => {
                    // Stop early — can't relocate past a ret/end
                    if src_offset < min_bytes {
                        return Err(HookError::RelocationFailed);
                    }
                    break;
                }
                InsnKind::Normal => {
                    // Copy verbatim
                    let src = self.input.add(src_offset);
                    writer.put_bytes(core::slice::from_raw_parts(src, insn.len));
                }
                InsnKind::RipRelative => {
                    // Copy instruction, adjust disp32 for new PC.
                    let src = self.input.add(src_offset);
                    let disp_off = insn.rip_disp_offset.unwrap();
                    let old_disp = (src.add(disp_off) as *const i32).read_unaligned();

                    // Absolute target = old_pc + insn_len + old_disp
                    let abs_target = (src_pc as i64 + insn.len as i64 + old_disp as i64) as u64;

                    // New disp = abs_target - (new_pc + insn_len)
                    let new_pc = writer.pc();
                    let new_disp = abs_target as i64 - (new_pc as i64 + insn.len as i64);

                    if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
                        return Err(HookError::RelocationFailed);
                    }

                    // Copy instruction bytes, patch the disp32
                    let bytes = core::slice::from_raw_parts(src, insn.len);
                    let mut patched = Vec::new();
                    patched.extend_from_slice(bytes);
                    let new_disp_bytes = (new_disp as i32).to_le_bytes();
                    patched[disp_off..disp_off + 4].copy_from_slice(&new_disp_bytes);
                    writer.put_bytes(&patched);
                }
                InsnKind::JmpRel8 | InsnKind::JmpRel32 => {
                    // Compute absolute target, emit absolute jump.
                    let abs_target = (src_pc as i64 + insn.len as i64 + insn.branch_offset) as u64;
                    writer.put_jmp_address(abs_target);
                }
                InsnKind::JccRel8 | InsnKind::JccRel32 => {
                    // Emit inverted Jcc short (skip 16 bytes) + JMP far to target.
                    let abs_target = (src_pc as i64 + insn.len as i64 + insn.branch_offset) as u64;
                    let inv_cc = insn.cc ^ 1;

                    // Inverted Jcc rel8 that skips over the JMP far (16 bytes).
                    // Jcc rel8: opcode = 0x70 + cc, rel8 = 16 (jump over 16B far jmp)
                    writer.put_bytes(&[0x70 | inv_cc, 16]);
                    writer.put_jmp_far(abs_target);
                }
                InsnKind::CallRel32 => {
                    let abs_target = (src_pc as i64 + insn.len as i64 + insn.branch_offset) as u64;
                    if insn.branch_offset == 0 {
                        // CALL $+0 (PIC pattern): push old_pc + insn_len onto stack
                        let return_addr = src_pc + insn.len as u64;
                        // mov r11, return_addr; push r11
                        writer
                            .put_mov_reg_imm64(crate::arch::x86_64::writer::Reg::R11, return_addr);
                        writer.put_push_reg(crate::arch::x86_64::writer::Reg::R11);
                    } else {
                        // Regular CALL: mov r11, target; call r11
                        writer.put_mov_reg_imm64(crate::arch::x86_64::writer::Reg::R11, abs_target);
                        writer.put_call_reg(crate::arch::x86_64::writer::Reg::R11);
                    }
                }
            }

            src_offset += insn.len;
        }

        Ok(src_offset)
    }
}

/// Check how many bytes from `input` can be safely relocated.
/// Returns the maximum number of source bytes that can be relocated,
/// stopping at RET, INT3, UD2, HLT, or when `min_bytes` is satisfied.
pub fn can_relocate(input: *const u8, min_bytes: usize) -> usize {
    let mut offset = 0usize;

    loop {
        if offset >= min_bytes {
            return offset;
        }
        let insn = decode_insn(unsafe { input.add(offset) }, 0);
        if insn.len == 0 {
            return offset;
        }
        match insn.kind {
            InsnKind::Ret | InsnKind::End => {
                return offset;
            }
            _ => {
                offset += insn.len;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::writer::X86_64Writer;

    #[test]
    fn decode_nop() {
        let code = [0x90u8]; // NOP
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 1);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn decode_ret() {
        let code = [0xC3u8];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 1);
        assert_eq!(insn.kind, InsnKind::Ret);
    }

    #[test]
    fn decode_push_rbp() {
        let code = [0x55u8]; // push rbp
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 1);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn decode_mov_rsp_rbp() {
        // mov rbp, rsp = 48 89 E5
        let code = [0x48u8, 0x89, 0xE5];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 3);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn decode_sub_rsp_imm32() {
        // sub rsp, 0x80 = 48 81 EC 80 00 00 00
        let code = [0x48u8, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 7);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn decode_jmp_rel32() {
        // E9 FB 00 00 00 = jmp +0x100 (from insn start, offset after 5-byte insn)
        let code = [0xE9u8, 0xFB, 0x00, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 5);
        assert_eq!(insn.kind, InsnKind::JmpRel32);
        assert_eq!(insn.branch_offset, 0xFB);
    }

    #[test]
    fn decode_jmp_rel8() {
        // EB 10 = jmp +16
        let code = [0xEBu8, 0x10];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 2);
        assert_eq!(insn.kind, InsnKind::JmpRel8);
        assert_eq!(insn.branch_offset, 0x10);
    }

    #[test]
    fn decode_call_rel32() {
        // E8 FB 0F 00 00 = call +0x1000
        let code = [0xE8u8, 0xFB, 0x0F, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 5);
        assert_eq!(insn.kind, InsnKind::CallRel32);
        assert_eq!(insn.branch_offset, 0xFFB);
    }

    #[test]
    fn decode_jcc_rel8() {
        // 74 10 = je +16
        let code = [0x74u8, 0x10];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 2);
        assert_eq!(insn.kind, InsnKind::JccRel8);
        assert_eq!(insn.cc, 4);
        assert_eq!(insn.branch_offset, 0x10);
    }

    #[test]
    fn decode_jcc_rel32() {
        // 0F 84 FB 0F 00 00 = je +0x1000
        let code = [0x0Fu8, 0x84, 0xFB, 0x0F, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 6);
        assert_eq!(insn.kind, InsnKind::JccRel32);
        assert_eq!(insn.cc, 4);
        assert_eq!(insn.branch_offset, 0xFFB);
    }

    #[test]
    fn decode_rip_relative_mov() {
        // 48 8B 05 10 00 00 00 = mov rax, [rip+0x10]
        let code = [0x48u8, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 7);
        assert_eq!(insn.kind, InsnKind::RipRelative);
        assert_eq!(insn.rip_disp_offset, Some(3));
    }

    #[test]
    fn decode_rip_relative_lea() {
        // 48 8D 05 10 00 00 00 = lea rax, [rip+0x10]
        let code = [0x48u8, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 7);
        assert_eq!(insn.kind, InsnKind::RipRelative);
    }

    #[test]
    fn decode_endbr64() {
        // ENDBR64: F3 0F 1E FA
        let code = [0xF3u8, 0x0F, 0x1E, 0xFA];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 4);
        assert_eq!(insn.kind, InsnKind::Normal); // Decoded as a normal instruction
    }

    #[test]
    fn decode_mov_reg_imm64() {
        // 48 B8 EF BE AD DE 00 00 00 00 = movabs rax, 0xDEADBEEF
        let code = [0x48u8, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_insn(code.as_ptr(), 0x1000);
        assert_eq!(insn.len, 10);
        assert_eq!(insn.kind, InsnKind::Normal);
    }

    #[test]
    fn can_relocate_basic() {
        // push rbp; mov rbp,rsp; sub rsp,0x80; ret
        let code = [
            0x55u8, // push rbp (1)
            0x48, 0x89, 0xE5, // mov rbp, rsp (3)
            0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, // sub rsp, 0x80 (7)
            0xC3, // ret
        ];
        assert_eq!(can_relocate(code.as_ptr(), 5), 11); // stops before ret
    }

    #[test]
    fn can_relocate_with_endbr64() {
        // ENDBR64 is handled by the caller (attach/replace) which adjusts
        // the function pointer to skip it. Test that can_relocate works
        // when called on code starting after ENDBR64.
        let code = [
            0x55u8, // push rbp (1)
            0x48, 0x89, 0xE5, // mov rbp, rsp (3)
            0xC3, // ret
        ];
        // min_bytes=5 → push rbp(1) + mov rbp,rsp(3) = 4 bytes, then ret stops
        assert_eq!(can_relocate(code.as_ptr(), 5), 4);
    }

    #[test]
    fn relocate_rip_relative_mov() {
        // mov rax, [rip+0x100] at PC=0x1000
        // Absolute target = 0x1000 + 7 + 0x100 = 0x1107
        let code = [0x48u8, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1000);
            let consumed = r.relocate_bytes(&mut w, 7).unwrap();
            assert_eq!(consumed, 7);
            // New disp = 0x1107 - (0x2000 + 7) = 0x1107 - 0x2007 = -0xF00
            let new_disp = i32::from_le_bytes(buf[3..7].try_into().unwrap());
            assert_eq!(new_disp, -0xF00);
        }
    }

    #[test]
    fn relocate_jmp_rel32() {
        // jmp +0x100 at PC=0x1000 → target = 0x1000 + 5 + 0x100 = 0x1105
        let code = [0xE9u8, 0x00, 0x01, 0x00, 0x00];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1000);
            let consumed = r.relocate_bytes(&mut w, 5).unwrap();
            assert_eq!(consumed, 5);
            // Should emit a jump to 0x1105. Since 0x1105 is within ±2GB of 0x2000,
            // it should use a near JMP.
            assert_eq!(buf[0], 0xE9); // near jmp
        }
    }

    #[test]
    fn relocate_jcc_rel8() {
        // je +0x10 at PC=0x1000 → target = 0x1000 + 2 + 0x10 = 0x1012
        let code = [0x74u8, 0x10];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1000);
            let consumed = r.relocate_bytes(&mut w, 2).unwrap();
            assert_eq!(consumed, 2);
            // Should emit: inverted Jcc (JNE skip 16) + JMP far to 0x1012
            assert_eq!(buf[0], 0x75); // JNE rel8 (inverted JE)
            assert_eq!(buf[1], 16); // skip 16 bytes
        }
    }

    #[test]
    fn relocate_call_rel32() {
        // call +0x100 at PC=0x1000 → target = 0x1000 + 5 + 0x100 = 0x1105
        let code = [0xE8u8, 0x00, 0x01, 0x00, 0x00];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1000);
            let consumed = r.relocate_bytes(&mut w, 5).unwrap();
            assert_eq!(consumed, 5);
            // Should emit: mov r11, 0x1105; call r11
            // mov r11, imm64 = 49 BB <8 bytes>
            assert_eq!(buf[0], 0x49);
            assert_eq!(buf[1], 0xBB);
            let target = u64::from_le_bytes(buf[2..10].try_into().unwrap());
            assert_eq!(target, 0x1105);
        }
    }

    #[test]
    fn relocate_after_endbr64() {
        // Simulate the caller already having skipped ENDBR64.
        // The relocator receives the code starting after ENDBR64.
        let code = [
            0x55u8, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
        ];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1004);
            let consumed = r.relocate_bytes(&mut w, 4).unwrap();
            assert_eq!(consumed, 4);
            assert_eq!(buf[0], 0x55);
            assert_eq!(&buf[1..4], &[0x48, 0x89, 0xE5]);
        }
    }

    #[test]
    fn relocate_jmp_rel8() {
        // EB 10 = jmp +16 at PC=0x1000
        // Absolute target = 0x1000 + 2 + 0x10 = 0x1012
        let code = [0xEBu8, 0x10];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1000);
            let consumed = r.relocate_bytes(&mut w, 2).unwrap();
            assert_eq!(consumed, 2);
            // Should emit a jump to 0x1012. Since target is within ±2GB,
            // it should use a near JMP (E9).
            assert_eq!(buf[0], 0xE9);
            let rel = i32::from_le_bytes(buf[1..5].try_into().unwrap());
            // Absolute target = writer_pc_after_insn + rel = (0x2000 + 5) + rel
            let abs_target = (0x2005i64 + rel as i64) as u64;
            assert_eq!(abs_target, 0x1012);
        }
    }

    #[test]
    fn relocate_multiple_rip_relative() {
        // Two consecutive RIP-relative MOVs:
        //   mov rax, [rip+0x100] at PC=0x1000 (7 bytes)
        //   mov rbx, [rip+0x200] at PC=0x1007 (7 bytes)
        // Relocated to PC=0x2000
        let code = [
            0x48u8, 0x8B, 0x05, 0x00, 0x01, 0x00, 0x00, // mov rax, [rip+0x100]
            0x48, 0x8B, 0x1D, 0x00, 0x02, 0x00, 0x00, // mov rbx, [rip+0x200]
        ];
        let mut buf = [0u8; 64];
        unsafe {
            let mut w = X86_64Writer::new(buf.as_mut_ptr(), buf.len(), 0x2000);
            let mut r = X86_64Relocator::new(code.as_ptr(), 0x1000);
            let consumed = r.relocate_bytes(&mut w, 14).unwrap();
            assert_eq!(consumed, 14);

            // First instruction: abs_target = 0x1000 + 7 + 0x100 = 0x1107
            // New disp = 0x1107 - (0x2000 + 7) = 0x1107 - 0x2007 = -0xF00
            let disp1 = i32::from_le_bytes(buf[3..7].try_into().unwrap());
            assert_eq!(disp1, -0xF00);

            // Second instruction: abs_target = 0x1007 + 7 + 0x200 = 0x120E
            // New disp = 0x120E - (0x2007 + 7) = 0x120E - 0x200E = -0xE00
            let disp2 = i32::from_le_bytes(buf[10..14].try_into().unwrap());
            assert_eq!(disp2, -0xE00);
        }
    }

    #[test]
    fn can_relocate_insufficient_bytes() {
        // A 1-byte RET (0xC3). can_relocate should return 0 since
        // RET stops scanning immediately and 0 < min_bytes.
        let code = [0xC3u8];
        assert_eq!(can_relocate(code.as_ptr(), 5), 0);
    }
}
