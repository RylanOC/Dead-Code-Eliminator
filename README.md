# Dead Code Eliminator (v1.0 alpha)
Author: **Rylan O'Connell**
_Detects and eliminates dead code in obfuscated binaries._
## Description:
This plugin attempts to de-obfuscate binaries with "dummy code" injected in them. Leveraging Binary Ninja's API, we can construct a series of def-use chains, isolating the "real" code from the "dummy" code. See the screenshot below for a basic example of this plugin in action:

![dead_code](dead_code.png)

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * dev - 1.0.dev-576
 * release - 9999


## Required Dependencies

The following dependencies are required for this plugin:

 * pip - NA
 * apt - NA
 * installers - NA
 * other - NA


## License
This plugin is released under a [MIT](LICENSE) license.

