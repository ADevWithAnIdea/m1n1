# Gravity Bootloader

Bootloader and hypervisor for Apple Silicon.

## Building

You need an `aarch64-linux-gnu-gcc` cross-compiler toolchain (or a native one,
if running on ARM64). You will also need to install the
`aarch64-unknown-none-softfloat` toolchain for rust.

```shell
$ rustup target add aarch64-unknown-none-softfloat
```

```shell
$ git clone --recursive https://github.com/GravityLinux/bootloader.git
$ cd bootloader
$ make
```

To build on a native ARM64 machine:

* On Linux, use `make ARCH=`.
* On macOS using Homebrew:

```shell
$ brew install llvm lld
$ make
```

* On macOS using MacPorts:

```shell
$ sudo port install llvm clang
$ sudo port select llvm llvm-mp-<version>
$ make
```

The output will be in `build/m1n1.bin`.

### Building using the container setup

If you have a container runtime installed, like Podman or Docker, you can make
use of the compose setup, which contains all build dependencies.

```shell
$ git clone --recursive https://github.com/GravityLinux/bootloader.git
$ cd bootloader
$ podman-compose run m1n1 make
$ # or
$ docker-compose run m1n1 make
```

## Usage Guides

First time installation: https://gravitylinux.org/docs/developers/tethered-boot/

Hypervisor usage: https://gravitylinux.org/docs/developers/hypervisor/

### Payloads

m1n1 supports running payloads by simple concatenation:

```shell
$ cat build/m1n1.bin Image.gz build/dtb/apple-j274.dtb initramfs.cpio.gz > m1n1-payload.bin
```

Supported payload file formats:

* Kernel images (or compatible). Must be compressed or last payload.
* Devicetree blobs (FDT). May be uncompressed or compressed.
* Initramfs cpio images. Must be compressed.

Supported compression formats:

* gzip
* xz

## License

Beginning with and including commit
[`df7656cf17d04ec19de8acb8a78d57cc9b48fda1`](https://github.com/ADevWithAnIdea/m1n1/commit/df7656cf17d04ec19de8acb8a78d57cc9b48fda1),
fork-authored contributions on this fork's main branch are licensed under the
[GNU General Public License, version 2 only](LICENSE.GPL2)
(`GPL-2.0-or-later`). The combined work distributed by this fork from that
commit onward is distributed under the GPL version 2 only, except for
components that retain a separate license as described below.

Commits before `df7656cf17d04ec19de8acb8a78d57cc9b48fda1` retain the licenses
that previously applied to them, including the [MIT license](LICENSE.MIT).
Commits pulled from upstream m1n1, whether before or after that commit, retain
their original licenses. This licensing change does not relicense third-party
components or other separately licensed material.

* Copyright The Gravity Linux Contributors
* Copyright The Asahi Linux Contributors

Please see the Git history for authorship information.

Portions of m1n1 are based on mini:

* Copyright (C) 2008-2010 Hector Martin "marcan" <marcan@marcan.st>
* Copyright (C) 2008-2010 Sven Peter <sven@svenpeter.dev>
* Copyright (C) 2008-2010 Andre Heider <a.heider@gmail.com>

m1n1 embeds libfdt, which is dual [BSD](3rdparty_licenses/LICENSE.BSD-2.libfdt) and
[GPL-2](3rdparty_licenses/LICENSE.GPL-2) licensed and copyright:

* Copyright (C) 2014 David Gibson <david@gibson.dropbear.id.au>
* Copyright (C) 2018 embedded brains GmbH
* Copyright (C) 2006-2012 David Gibson, IBM Corporation.
* Copyright (C) 2012 David Gibson, IBM Corporation.
* Copyright 2012 Kim Phillips, Freescale Semiconductor.
* Copyright (C) 2016 Free Electrons
* Copyright (C) 2016 NextThing Co.

The ADT code in mini is also based on libfdt and subject to the same license.

m1n1 embeds [minlzma](https://github.com/ionescu007/minlzma), which is
[MIT](3rdparty_licenses/LICENSE.minlzma) licensed and copyright:

* Copyright (c) 2020 Alex Ionescu

m1n1 embeds a slightly modified version of [tinf](https://github.com/jibsen/tinf), which is
[ZLIB](3rdparty_licenses/LICENSE.tinf) licensed and copyright:

* Copyright (c) 2003-2019 Joergen Ibsen

m1n1 embeds portions taken from
[arm-trusted-firmware](https://github.com/ARM-software/arm-trusted-firmware), which is
[BSD](3rdparty_licenses/LICENSE.BSD-3.arm) licensed and copyright:

* Copyright (c) 2013-2020, ARM Limited and Contributors. All rights reserved.

m1n1 embeds [Doug Lea's malloc](ftp://gee.cs.oswego.edu/pub/misc/malloc.c) (dlmalloc), which is in
the public domain ([CC0](3rdparty_licenses/LICENSE.CC0)).

m1n1 embeds portions of [PDCLib](https://github.com/DevSolar/pdclib), which is in the public
domain ([CC0](3rdparty_licenses/LICENSE.CC0)).

m1n1 embeds the [Source Code Pro](https://github.com/adobe-fonts/source-code-pro) font, which is
licensed under the [OFL-1.1](3rdparty_licenses/LICENSE.OFL-1.1) license and copyright:

* Copyright 2010-2019 Adobe (http://www.adobe.com/), with Reserved Font Name 'Source'. All Rights Reserved. Source is a trademark of Adobe in the United States and/or other countries.
* This Font Software is licensed under the SIL Open Font License, Version 1.1.

m1n1 embeds portions of the [dwc3 usb linux driver](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/usb/dwc3/core.h?id=7bc5a6ba369217e0137833f5955cf0b0f08b0712), which was [BSD-or-GPLv2 dual-licensed](3rdparty_licenses/LICENSE.BSD-3.dwc3) and copyright
* Copyright (C) 2010-2011 Texas Instruments Incorporated - http://www.ti.com

m1n1 embeds portions of [musl-libc](https://musl.libc.org/)'s floating point library, which are MIT licensed and copyright
* Copyright (c) 2017-2018, Arm Limited.

m1n1 embeds some rust crates. Licenses can be found in the vendor directory for every crate.
