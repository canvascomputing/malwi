use crate::types::HookError;

#[derive(Debug)]
pub struct CodeSlice {
    pub data: *mut u8,
    pub pc: *const u8,
    pub size: usize,
}

unsafe impl Send for CodeSlice {}
unsafe impl Sync for CodeSlice {}

#[derive(Debug)]
pub struct CodeAllocator {
    slab_size: usize,
}

impl Default for CodeAllocator {
    fn default() -> Self {
        Self { slab_size: 4096 }
    }
}

impl CodeAllocator {
    pub fn new(slab_size: usize) -> Self {
        Self { slab_size: slab_size.max(4096) }
    }

    pub fn alloc_near(&mut self, near: *const u8, max_distance: usize) -> Result<CodeSlice, HookError> {
        #[cfg(target_os = "macos")]
        unsafe {
            use mach2::kern_return::KERN_SUCCESS;
            use mach2::traps::mach_task_self;
            use mach2::vm::mach_vm_allocate;
            use mach2::vm_region::{vm_region_basic_info_64, VM_REGION_BASIC_INFO_64};
            use mach2::vm_statistics::VM_FLAGS_FIXED;
            use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

            let task = mach_task_self();
            let near_u = near as u64;
            let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as u64;

            let win_start = near_u.saturating_sub(max_distance as u64) & !(page_sz - 1);
            let win_end = near_u.saturating_add(max_distance as u64) & !(page_sz - 1);
            let need = self.slab_size as u64;

            // Enumerate VM regions in the window and look for gaps.
            let mut addr: mach_vm_address_t = win_start;
            let mut prev_end: u64 = win_start;

            while addr < win_end {
                let mut region_addr = addr;
                let mut region_size: mach_vm_size_t = 0;
                let mut info: vm_region_basic_info_64 = core::mem::zeroed();
                let mut info_count = vm_region_basic_info_64::count();
                let mut object_name: u32 = 0;

                let kr = mach2::vm::mach_vm_region(
                    task,
                    &mut region_addr,
                    &mut region_size,
                    VM_REGION_BASIC_INFO_64,
                    (&mut info as *mut _) as mach2::vm_region::vm_region_info_t,
                    &mut info_count,
                    &mut object_name,
                );

                if kr != KERN_SUCCESS {
                    break;
                }

                let region_end = region_addr.saturating_add(region_size);

                // Gap is [prev_end, region_addr).
                if region_addr > prev_end {
                    let gap_start = prev_end;
                    let gap_end = region_addr.min(win_end);
                    if gap_end > gap_start && gap_end - gap_start >= need {
                        let mut candidate = near_u.clamp(gap_start, gap_end - need);
                        candidate &= !(page_sz - 1);

                        let mut out = candidate as mach_vm_address_t;
                        let kr = mach_vm_allocate(task, &mut out, need, VM_FLAGS_FIXED);
                        if kr == KERN_SUCCESS {
                            return Ok(CodeSlice {
                                data: out as *mut u8,
                                pc: out as *const u8,
                                size: self.slab_size,
                            });
                        }
                    }
                }

                prev_end = prev_end.max(region_end);
                addr = region_end;
            }

            // No gap found within the requested range.
            Err(HookError::AllocationFailed)
        }

        #[cfg(target_os = "linux")]
        unsafe {
            let near_u = near as usize;
            let page_sz = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let need = self.slab_size;

            let win_start = near_u.saturating_sub(max_distance) & !(page_sz - 1);
            let win_end = near_u.saturating_add(max_distance) & !(page_sz - 1);

            // Parse /proc/self/maps to find gaps in the address space.
            if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                let mut regions: Vec<(usize, usize)> = Vec::new();
                for line in maps.lines() {
                    let Some(range) = line.split_whitespace().next() else { continue };
                    let Some((start_s, end_s)) = range.split_once('-') else { continue };
                    let Ok(start) = usize::from_str_radix(start_s, 16) else { continue };
                    let Ok(end) = usize::from_str_radix(end_s, 16) else { continue };
                    regions.push((start, end));
                }
                regions.sort_by_key(|&(s, _)| s);

                // Look for gaps between regions within the window.
                let mut prev_end = win_start;
                for &(region_start, region_end) in &regions {
                    if region_start > win_end {
                        break;
                    }
                    if region_start > prev_end {
                        let gap_start = prev_end;
                        let gap_end = region_start.min(win_end);
                        if gap_end > gap_start && gap_end - gap_start >= need {
                            let candidate = near_u.clamp(gap_start, gap_end - need) & !(page_sz - 1);
                            let ptr = libc::mmap(
                                candidate as *mut libc::c_void,
                                need,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                                -1,
                                0,
                            );
                            if ptr != libc::MAP_FAILED {
                                return Ok(CodeSlice {
                                    data: ptr as *mut u8,
                                    pc: ptr as *const u8,
                                    size: need,
                                });
                            }
                        }
                    }
                    prev_end = prev_end.max(region_end);
                }

                // Check gap after last region.
                if prev_end < win_end && win_end - prev_end >= need {
                    let candidate = near_u.clamp(prev_end, win_end - need) & !(page_sz - 1);
                    let ptr = libc::mmap(
                        candidate as *mut libc::c_void,
                        need,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                        -1,
                        0,
                    );
                    if ptr != libc::MAP_FAILED {
                        return Ok(CodeSlice {
                            data: ptr as *mut u8,
                            pc: ptr as *const u8,
                            size: need,
                        });
                    }
                }
            }

            // Fall back: allocate anywhere.
            self.alloc_any()
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (near, max_distance);
            Err(HookError::Unsupported)
        }
    }

    pub fn alloc_any(&mut self) -> Result<CodeSlice, HookError> {
        #[cfg(target_os = "macos")]
        unsafe {
            use mach2::kern_return::KERN_SUCCESS;
            use mach2::traps::mach_task_self;
            use mach2::vm::{mach_vm_allocate, mach_vm_protect};
            use mach2::vm_statistics::VM_FLAGS_ANYWHERE;
            use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE};

            let task = mach_task_self();
            let mut addr: u64 = 0;
            let kr = mach_vm_allocate(task, &mut addr, self.slab_size as u64, VM_FLAGS_ANYWHERE);
            if kr != KERN_SUCCESS {
                return Err(HookError::AllocationFailed);
            }

            // Start RW for emission.
            let kr = mach_vm_protect(task, addr, self.slab_size as u64, 0, VM_PROT_READ | VM_PROT_WRITE);
            if kr != KERN_SUCCESS {
                return Err(HookError::AllocationFailed);
            }

            Ok(CodeSlice {
                data: addr as *mut u8,
                pc: addr as *const u8,
                size: self.slab_size,
            })
        }

        #[cfg(target_os = "linux")]
        unsafe {
            let ptr = libc::mmap(
                core::ptr::null_mut(),
                self.slab_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(HookError::AllocationFailed);
            }
            Ok(CodeSlice {
                data: ptr as *mut u8,
                pc: ptr as *const u8,
                size: self.slab_size,
            })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(HookError::Unsupported)
        }
    }

    pub unsafe fn make_executable(&self, slice: &CodeSlice) -> Result<(), HookError> {
        #[cfg(target_os = "macos")]
        {
            use mach2::kern_return::KERN_SUCCESS;
            use mach2::traps::mach_task_self;
            use mach2::vm::mach_vm_protect;
            use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ};

            let task = mach_task_self();
            let kr = mach_vm_protect(task, slice.data as u64, slice.size as u64, 0, VM_PROT_READ | VM_PROT_EXECUTE);
            if kr != KERN_SUCCESS {
                return Err(HookError::AllocationFailed);
            }
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            if libc::mprotect(
                slice.data as *mut libc::c_void,
                slice.size,
                libc::PROT_READ | libc::PROT_EXEC,
            ) != 0
            {
                return Err(HookError::AllocationFailed);
            }
            crate::code::cache::invalidate_icache(slice.data, slice.size);
            Ok(())
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = slice;
            Err(HookError::Unsupported)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_any_returns_executable_page() {
        let mut alloc = CodeAllocator::default();
        let slice = alloc.alloc_any().expect("alloc");
        unsafe {
            // Write a RET instruction for AArch64 (or NOP for non-aarch64) and flip to RX.
            #[cfg(target_arch = "aarch64")]
            {
                // ret
                (slice.data as *mut u32).write(0xD65F03C0);
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                (slice.data as *mut u8).write(0xC3); // ret
            }
            alloc.make_executable(&slice).expect("protect");
        }
    }

    #[test]
    fn alloc_near_returns_within_range() {
        let mut alloc = CodeAllocator::default();
        let near = alloc_near_returns_within_range as *const u8;
        let max_distance = 1024 * 1024 * 1024; // 1GiB (avoid flakiness vs ASLR/fragmentation)
        let slice = alloc.alloc_near(near, max_distance).expect("alloc_near");
        let dist = if (slice.data as usize) >= (near as usize) {
            (slice.data as usize) - (near as usize)
        } else {
            (near as usize) - (slice.data as usize)
        };
        assert!(dist <= max_distance);
    }
}
