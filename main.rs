use std::time::Instant;
use colored::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Diagnostics::Debug::*;

/// Process information with PID and module base address.
struct ProcessInfo {
    pid: u32,
    base_address: usize,
}

/// Searches for a Roblox client process and returns its PID and module base address.
fn find_roblox_clients() -> Option<ProcessInfo> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let snapshot_handle = HANDLE(snapshot.0);
        
        struct SnapshotGuard(HANDLE);
        impl Drop for SnapshotGuard {
            fn drop(&mut self) {
                unsafe { let _ = CloseHandle(self.0); }
            }
        }
        let _guard = SnapshotGuard(snapshot_handle);

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(snapshot, &mut entry).is_err() {
            return None;
        }

        while Process32NextW(snapshot, &mut entry).is_ok() {
            let process_name = String::from_utf16_lossy(&entry.szExeFile)
                .trim_matches('\0')
                .to_lowercase();
            if process_name == "robloxplayerbeta.exe" {
                let pid = entry.th32ProcessID;
                let process_handle = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    false,
                    pid,
                ).ok()?;
                
                struct ProcessGuard(HANDLE);
                impl Drop for ProcessGuard {
                    fn drop(&mut self) {
                        unsafe { let _ = CloseHandle(self.0); }
                    }
                }
                let _guard = ProcessGuard(process_handle);
                
                let mut module_handles = [HMODULE::default(); 1024];
                let mut bytes_needed = 0;
                if K32EnumProcessModules(
                    process_handle,
                    module_handles.as_mut_ptr(),
                    std::mem::size_of_val(&module_handles) as u32,
                    &mut bytes_needed,
                ).as_bool() {
                    let base_address = module_handles[0].0 as usize;
                    return Some(ProcessInfo { pid, base_address });
                }
            }
        }
        None
    }
}

/// This function scans all memory regions of the target process (starting at the given base address)
/// and uses a simple heuristic to “extract” candidate patterns. In this example, if a byte equals 0x55,
/// we capture the next 16 bytes as a candidate pattern.
/// (You can adjust the heuristic and the pattern length as needed.)
fn auto_extract_patterns(process_handle: HANDLE, base_address: usize) -> Vec<(usize, Vec<u8>)> {
    let mut patterns = Vec::new();
    let mut address = base_address;
    unsafe {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        // Loop over memory regions using VirtualQueryEx
        while VirtualQueryEx(
            process_handle,
            Some(address as *const _),
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0 {
            if mem_info.State == MEM_COMMIT &&
               (mem_info.Protect & PAGE_PROTECTION_FLAGS(PAGE_GUARD.0)) == PAGE_PROTECTION_FLAGS(0) &&
               (mem_info.Protect & PAGE_PROTECTION_FLAGS(PAGE_NOACCESS.0)) == PAGE_PROTECTION_FLAGS(0) {
                
                let region_size = mem_info.RegionSize;
                let mut buffer = vec![0u8; region_size];
                let mut bytes_read = 0;
                if ReadProcessMemory(
                    process_handle,
                    address as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    region_size,
                    Some(&mut bytes_read),
                ).is_ok() && bytes_read > 0 {
                    let read_size = bytes_read as usize;
                    // Iterate over the region with a sliding window.
                    for i in 0..read_size.saturating_sub(16) {
                        // Simple heuristic: if the current byte equals 0x55 (a common function prologue opcode on x86),
                        // then capture the next 16 bytes as a candidate pattern.
                        if buffer[i] == 0x55 {
                            let pattern = buffer[i..i+16].to_vec();
                            patterns.push((address + i, pattern));
                        }
                    }
                }
            }
            address += mem_info.RegionSize;
        }
    }
    patterns
}

fn main() {
    control::set_virtual_terminal(true).unwrap_or_default();
    println!("{}", "=========================================".bold());
    println!("{}", "Roblox Pattern Scanner\nBy: 𝕷𝖔𝖘𝖙".bold());
    println!("{}", "=========================================".bold());
    println!("\n{}", "[Finding Roblox Process & Module Address]\n=========================================".bold());

    let process_info = match find_roblox_clients() {
        Some(info) => info,
        None => {
            println!("[-] {}", "Couldn't find any Roblox Clients to inject into!".red());
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    println!("[+] RobloxPlayerBeta PID: {}", process_info.pid.to_string().bright_cyan());
    println!("[+] RobloxPlayerBeta Module Address: {:#x}\n", process_info.base_address);

    println!("{}", "[Scanning for Candidate Patterns]\n===========================".bold());

    let process_handle = match unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process_info.pid,
        )
    } {
        Ok(handle) => handle,
        Err(e) => {
            println!("[-] {}: {:?}", "Failed to open process".red(), e);
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap_or_default();
            return;
        }
    };

    let start_time = Instant::now();
    let patterns = auto_extract_patterns(process_handle, process_info.base_address);
    let elapsed = start_time.elapsed();

    if patterns.is_empty() {
        println!("\n[-] {}: No candidate patterns found after scanning for {} seconds", "Scanning failed".red(), elapsed.as_secs_f64());
    } else {
        println!("\n[+] {} candidate patterns found in {} seconds", patterns.len().to_string().bright_green(), elapsed.as_secs_f64());
        for (addr, pat) in patterns {
            // Print the address and a hex string of the pattern bytes.
            let hex_string = pat.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ");
            println!("[Pattern] Address: {:#x} -> {}", addr, hex_string.bright_green());
        }
    }

    unsafe { let _ = CloseHandle(process_handle); }
    
    println!("\nPress Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or_default();
}
