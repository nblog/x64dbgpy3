# pyflirt for x64dbgpy3

This directory contains a Python 3 port of the `pyflirt` library, originally developed by `mokhdzanifaeq`. It has been integrated into the `x64dbgpy3` project to provide FLIRT signature matching capabilities.

## Signature Databases

Here are some resources for finding FLIRT signature files (`.sig`):

*   [rizin-sigdb](https://github.com/rizinorg/sigdb): Rizin Signature Database
*   [flirt_signatures](https://github.com/angr/flirt_signatures): Signatures used by the angr framework
*   [FLIRTDB](https://github.com/Maktm/FLIRTDB): A community-driven collection of IDA FLIRT signature files
*   [sig-database](https://github.com/push0ebp/sig-database): IDA FLIRT Signature Database by push0ebp

## Related Tools & Libraries

*   [rz-sign](https://github.com/rizinorg/rizin/releases/tag/v0.4.0): A tool from the Rizin framework for creating `.sig` files from library files.
*   [pyflirt (lancelot)](https://github.com/williballenthin/lancelot/tree/master/pyflirt): Another Python implementation of FLIRT signature matching, part of the lancelot project.

## Credits

*   **Original pyflirt (Python 2):** [mokhdzanifaeq/pyflirt](https://github.com/mokhdzanifaeq/pyflirt)
*   **Signature Parsing Logic:** [thebabush/nampa](https://github.com/thebabush/nampa) (Used as a reference or basis for parts of the parsing logic)
