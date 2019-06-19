# manticore-roadmap

Runs a program under Manticore and attempts to identify compatibility issues.

Each run reports:
* Syscall trace similarity from Manticore vs Native execution
* Most common unimplemented syscalls
* Exceptions encoutered 
* Return codes
* Errors and warning messages

This tool was used for the [System call audit](https://github.com/trailofbits/manticore/pull/1384) on Manticore 0.2.5. It's been partially updated to work with 0.3.0. 
