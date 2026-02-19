Sentinel is a security property checker for programs.

### Roadmap

- [ ] Detect secret flowing to output (AST)
- [ ] Add DSL parser (Lark)
- [ ] Build symbolic IR
- [ ] Encode properties in Z3
- [ ] Generate counterexamples
- [ ] Add more properties

### Philosophy

Sentinel is based on a simple idea:

> Write what should never happen.  
> Let the tool prove whether it can.

It hides solver complexity and focuses on human-readable security intent.

### Status

*Early prototype (v0.1)*  
Expect breaking changes and limited language support.