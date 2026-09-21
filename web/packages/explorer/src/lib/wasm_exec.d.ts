// The vendored glue has no exports: it is a classic script the toolchain
// writes for a <script> tag, and go.ts loads it for its effect on globalThis
// and then takes those names back. This file is here so that the load is an
// import of a module rather than of a file TypeScript has no shape for.
export {};
