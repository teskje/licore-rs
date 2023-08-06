# licore

licore is a simple library for parsing Linux [core] files.

[core]: https://en.wikipedia.org/wiki/Core_dump

## Limitations

At the moment, licore is only able to parse core files for the `x86-64`
architecture. Support for over architectures is not planned, but PRs are
welcome!

licore also only supports 64-bit targets. This restriction exists just to make
the developer's life easier and may be lifted if there is sufficient demand.
