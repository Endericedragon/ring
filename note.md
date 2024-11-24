# ring 研究与改造

## 解决编译错误

### `build.rs` 改造

首先尝试编译，从报错信息中得知 `ASM_TARGETS` 中缺少 `riscv64` 编译目标。先手动添加，暂时绕过这个问题。

```rust
const ASM_TARGETS: &[(&str, Option<&str>, Option<&str>)] = &[
    // -- snip --
    ("riscv64", Some(LINUX), None), // 这就是我们要添加的编译目标
];
```

### `GFp/base.h` 改造

绕过上述问题后，编译仍然报错，这回错误提示出现在头文件 `modules/ring/include/GFp/base.h` 中。

```c
#if defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)
#define OPENSSL_64_BIT
#define OPENSSL_X86_64
#elif defined(__x86) || defined(__i386) || defined(__i386__) || defined(_M_IX86)
...
#else
// Note BoringSSL only supports standard 32-bit and 64-bit two's-complement,
// little-endian architectures. Functions will not produce the correct answer
// on other systems. Run the crypto_test binary, notably
// crypto/compiler_test.cc, before adding a new architecture.
#error "Unknown target CPU"
#endif
```

在这段宏定义中，检查了各种编译器内置的宏定义（例如这里的 `__x86_64` ），从而确定了自己的编译目标类型，然后根据不同的编译目标类型定义不同的宏。最后，若没有任何匹配上的宏，就报错。

运行 `riscv64-linux-musl-gcc -dM -E - < /dev/null` ，查看 `riscv64-linux-musl-gcc` 编译器中的内置宏定义，发现它定义了这个：

```c
#define __riscv 1
...
#define __li
```

于是，作为 workaround ，在上述宏定义中加入这个：

```c
#if defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)
#define OPENSSL_64_BIT
#define OPENSSL_X86_64
#elif ... // 其他的宏定义
#elif defined(__riscv)
#define OPENSSL_64_BIT
#define OPENSSL_RISCV64  // 我也不知道这个名字有没有用，Fitten自动填的
#else
// Note BoringSSL only supports ...
#error "Unknown target CPU"
#endif
```

> 在宏定义的注释中，有提到 `ring` 只支持标准的32位/64位的、用补码存储的、小端序的架构。经过查询，发现RISC-V同时支持小端序和大端序，并且通过查阅 `riscv64-linux-musl-gcc` 的预定义宏定义（下文有查看预定义宏定义的方法）发现如下内容：
>
> ```c
> #define __ORDER_LITTLE_ENDIAN__ 1234
> #define __ORDER_BIG_ENDIAN__ 4321
> #define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
> ```
>
> 这说明RISC-V默认使用小端序，符合BoringSSL的要求。

### `src/rand.rs` 改造

经过上述修改后再尝试编译，看到了新的错误：

```
   Compiling ring v0.16.20 (/home/endericedragon/repos/async-os/modules/ring)
error[E0425]: cannot find value `SYS_GETRANDOM` in this scope
   --> modules/ring/src/rand.rs:221:40
    |
221 |         let r = unsafe { libc::syscall(SYS_GETRANDOM, dest.as_mut_ptr(), chunk_len, 0) };
    |                                        ^^^^^^^^^^^^^ not found in this scope
```

查看源代码发现原来是这个常量没定义。

```rust
#[cfg(target_arch = "aarch64")]
const SYS_GETRANDOM: c_long = 278;

#[cfg(target_arch = "arm")]
const SYS_GETRANDOM: c_long = 384;

#[cfg(target_arch = "x86")]
const SYS_GETRANDOM: c_long = 355;

#[cfg(target_arch = "x86_64")]
const SYS_GETRANDOM: c_long = 318;

let chunk_len: c::size_t = dest.len();
let r = unsafe { libc::syscall(SYS_GETRANDOM, dest.as_mut_ptr(), chunk_len, 0) };
```

代码只为架构 `aarch64, arm, x86, x86_64` 定义了 `SYS_GETRANDOM`，而 `riscv64` 没有定义，于是手动添加：

```rust
#[cfg(target_arch = "riscv64")]
const SYS_GETRANDOM: c_long = 278; // https://jborza.com/post/2021-05-11-riscv-linux-syscalls/
```

### `modules/ring/src/lib.rs` 改造

下一个编译问题是这个：

```
error: unnecessary qualification
   --> modules/ring/src/digest.rs:447:38
    |
447 |     as64: [BigEndian<u64>; 512 / 8 / core::mem::size_of::<BigEndian<u64>>()],
    |                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
note: the lint level is defined here
   --> modules/ring/src/lib.rs:72:23
```

这是在 `modules/ring/src/lib.rs` 中设置的规则过于严格导致的，定位到该文件第72行，然后做如下替换：

```
- #![deny(missing_docs, unused_qualifications, variant_size_differences)]
+ #![deny(missing_docs, variant_size_differences)]
```

## 解决运行时错误

虽然现在编译不报错，但是显而易见地，程序不能运行。因为ring（和它依赖的BoringSSL）是为x86而作，后者在C语言中内联汇编还在使用EAX寄存器，这个寄存器显然不该出现在RISC-V中，因此需要继续修改。一个可能有借鉴意义的是这篇帖子：[Add Windows ARM32 (`thumbv7a-pc-windows-msvc`/`thumbv7a-uwp-windows-msvc`) support by bdbai](https://github.com/briansmith/ring/pull/1767)。虽然它的目标仍然是Windows，但起码给出了增加架构的思路。