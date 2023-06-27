
# ThreadlessInject-rs

Rust port of [ThreadlessInject](https://github.com/CCob/ThreadlessInject/)

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
