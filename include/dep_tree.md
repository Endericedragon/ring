```mermaid
graph LR
cpu --> base

aes --> base

check --> assert

mem --> base

poly1305 --> base

base --> type_check
base --> stddef
base --> stdint
```