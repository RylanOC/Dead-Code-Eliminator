# Dead Code Eliminator (v1.0 alpha)
Author: **Rylan O'Connell**
_Detects and eliminates dead code in obfuscated binaries._
## Description:
This plugin recursively calculates a set of def-use chains in a binary. This allows us to segment the benign code from the interesting code by tracing these def-use chains backwards, as most of the dummy code should be fairly isolated from the malicious code.
## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * dev - 1.0.dev-576
 * release - 9999


## Required Dependencies

The following dependencies are required for this plugin:

 * pip - 
 * apt - 
 * installers - 
 * other - 


## License
This plugin is released under a [MIT](LICENSE) license.

