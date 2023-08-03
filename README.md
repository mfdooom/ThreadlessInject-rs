
# ThreadlessInject-rs

A rust implementation of [ThreadlessInject](https://github.com/CCob/ThreadlessInject/). This implementation uses [Dinvoke_rs](https://github.com/Kudaes/DInvoke_rs/) to call the NTAPI functions directly rather than going through the Windows API. I wanted build this to get more familiar with the Rust programming language and function hooking. 

# About

Threadless Injection works by performing remote memory allocation and writing, however instead of remotley executing the code we hook a loaded DLL export function and wait for the process to legitimatley make the API call for that function. 

# Usage

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\ThreadlessInject-rs set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

```
Usage: threadless_inject_rs.exe [OPTIONS] --pid <PID> --dll <DLL> --export <EXPORT>

Options:
  -p, --pid <PID>
          Target process ID to inject
  -s, --shellcode-file <SHELLCODE_FILE>
          Path for x64 shellcode paylod (default calc payload will be used if not specified)
  -d, --dll <DLL>
          DLL that contains the export to patch
  -e, --export <EXPORT>
          Exported function that will be hijacked
  -h, --help
          Print help
  -V, --version
          Print version
```