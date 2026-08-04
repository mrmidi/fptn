# lwIP dependency record (PR-LW1)

## What is pinned

| Field | Value |
|---|---|
| Component | HEV lwIP fork (transparent TCP/UDP/ICMP for TUN-style proxies) |
| Upstream (canonical) | `https://gitlab.com/hev/lwip` |
| Fetch source (mirror) | `https://github.com/heiher/lwip.git` |
| Pinned commit | `2a11c14c7a32887af25a034e82ef18b0b12076ac` |
| Pinned commit subject | "ICMP: Allow responding to requests not destined for localhost." |
| lwIP baseline | 2.2.1 release (`LWIP_VERSION_*` in `src/include/lwip/init.h`) |
| Enabled via | Conan option `fptn/*:with_lwip` (default `False`) |

The pin lives in `depends/cmake/FetchLwip.cmake`
(`FPTN_LWIP_GIT_TAG`). Do not track a branch.

## Why this fork

Pristine lwIP only accepts traffic addressed to the stack's own addresses.
The HEV fork adds the transparent semantics FPTN's FlowProxy data plane needs:

- `NETIF_FLAG_PRETEND_TCP` / `NETIF_FLAG_PRETEND_UDP` / `NETIF_FLAG_PRETEND_ICMP`
  (`src/include/lwip/netif.h`);
- acceptance of TCP connections and UDP datagrams not destined for localhost;
- original destination preserved on accepted PCBs
  (`pcb->local_ip` / `pcb->local_port`);
- `udp_sendfrom()` for source-addressed UDP replies.

## Local patches

None at this pin. If patches become necessary:

1. add them as `depends/lwip/patches/NNNN-<slug>.patch` (git-format-patch);
2. apply them from `FetchLwip.cmake` via `PATCH_COMMAND` (git apply);
3. record each patch below with purpose and upstream status.

## License

lwIP is BSD-3-Clause-style licensed; the HEV fork retains the upstream
license (`LICENSE` in the fetched source). Full notice:

```text
Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
```

## FPTN port files (this directory)

- `CMakeLists.txt` — `fptn_lwip` OBJECT library; objects are absorbed into
  `fptn-protocol-lib_static`.
- `lwipopts.h` — NO_SYS raw-API configuration, bounded pools.
- `arch/cc.h`, `arch/sys_arch.h` — minimal port headers.
- `fptn_lwip_port.c` — `sys_now()`, `fptn_lwip_rand()`.
