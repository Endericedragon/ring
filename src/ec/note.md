# EC 模块的改造

## curve25519模块的改造

该模块共有两个对外公开的子模块：

```rust
pub mod ed25519;
pub mod x25519;
```

### x25519对外暴露的接口

```rust
pub static X25519: agreement::Algorithm = agreement::Algorithm {
    curve: &CURVE25519,
    ecdh: x25519_ecdh,
};
```