# pyflirt for x64dbgpy3

This library provides IDA FLIRT (Fast Library Identification and Recognition Technology) signature matching capabilities for the [x64dbgpy3](https://github.com/nblog/x64dbgpy3) plugin.

The core Python code was adapted from the C implementation found in [radare2/libr/anal/flirt.c](https://github.com/radareorg/radare2/blob/master/libr/anal/flirt.c), primarily using AI for the initial translation.

## Signature Databases

FLIRT relies on signature files (`.sig`) to identify functions. Here are some sources for these files:

*   [rizin-sigdb](https://github.com/rizinorg/sigdb): Official signature database for the Rizin reverse engineering framework.
*   [flirt_signatures](https://github.com/angr/flirt_signatures): Signatures curated for use with the angr binary analysis framework.
*   [FLIRTDB](https://github.com/Maktm/FLIRTDB): A community-driven collection of IDA FLIRT signature files.
*   [sig-database](https://github.com/push0ebp/sig-database): Another collection of IDA FLIRT signatures by push0ebp.

## Related Tools

*   [rz-sign](https://github.com/rizinorg/rizin/releases): A utility within the Rizin framework used to generate `.sig` files from static library files (`.lib`, `.a`).

## Credits & References

*   **Original pyflirt (Python 2):** [mokhdzanifaeq/pyflirt](https://github.com/mokhdzanifaeq/pyflirt) - The initial Python 2 implementation this project was inspired by.
*   **Signature Parsing Logic:** [thebabush/nampa](https://github.com/thebabush/nampa) - Provided valuable insights into parsing the `.sig` file format.
*   **lancelot's pyflirt:** [williballenthin/lancelot/pyflirt](https://github.com/williballenthin/lancelot/tree/master/pyflirt) - Another Python FLIRT implementation, part of the lancelot project.