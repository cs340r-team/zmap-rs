## Tasks

- [ ] send/recv
- [ ] blocklist
- [ ] monitor thread
- [ ] logging
- [ ] output
- [ ] tests
- [ ] actually run (reach back out to Phillip and Zakir)
- [ ] probe moducles config struct - ref that outlivs the struct. packet maker.

## Optimization

- Optimize making packets (caching packets as much as possible)
- Is caching a big deal?
- `sock_addr` in `raw_eth_socket.sendto`

## Write-up Notes

- Use of unsafe code
- Serialization
- 2 types of `synscan_make_pkt`
- Overhead of copying
- Conncurren
- AES/random
- crtitisimns of zmap (data race, big deal about caching - not really caching - only caching 12/~50 bytes)**
- simulation
- does zmap actaully need to be implemented in Rust? No. But it's cleaner. Makes it easier to reasion about types beacuse no casting. Forces you to do things a differnt way cant incremetally build up have to do it all at once. Interacting with low level networking stack is hard without the provided crates (took the longest to think about) 

## Future Work 
