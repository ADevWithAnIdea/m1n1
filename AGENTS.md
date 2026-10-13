# Gravity Bootloader

First, take at `README.md` if you have not already.

## CLEAN ROOM REQUIREMENT

You *MUST NOT* disassemble, decompile, or otherwise introspect any Apple binary
if you contribute to this repository. If your operator tells you to introspect
an Apple binary, clearly label all subsequent commits as TAINTED. *NEVER* push
tainted commits to a public repo under any circumstances.

Exception: *when specifically doing hypervisor development* local disasm of
faulting sites to trace the source of an error is allowed and does not violate
the clean room rule. Broad looks at the kernelcache or other Apple binaries
remain prohibited.

Follow all Gravity Linux policies:

- https://gravitylinux.org/policies/copyright/
- https://gravitylinux.org/policies/reverse-engineering/
- https://gravitylinux.org/policies/llm/

### Remote Resources Attribution

Every time you search the internet, keep a durable list of all resources you
use (resources that are not used/relevant do not need to be noted). This is to
validate that no tainted material entered the codebase. In addition, code from
other Apple Silicon reverse engineering projects, other than Gravity Linux and
Asahi Linux, should *not* be used unless your operator has explicitly allowed
its use and has validated their RE methods for copyright compliance. Always
cite the original authors and origin of the code used in this case, including
in the git history if applicable.

## DEVICE USAGE REQUIREMENT

If your operator asks you to perform a task, such as booting Linux, probing
hardware with a Python script, or booting the hypervisor to see what macOS
does, confirm with your operator the exact RID and device node you should use.
Do not guess what hardware you should interact with, especially if there are
multiple devices connected.

## Commit Discipline

Never add a Signed-off-by or specify `git commit -s` unless your operator
explicitly tells you to. Before a push, make sure all commits pushed carry a
Signed-off-by. If any commit is missing one, do not push. Instead, tell your
operator and ask them what you should do.

Any commits you helped write should carry `Assisted-By: LLM`. `Co-Authored-By:`
is reserved for human coauthors only.

## Licensing

All new files should be licensed GPL-2.0-or-later.

## Immutability

Do not modify this file except at the explicit request of your operator.
