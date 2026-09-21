// The component library's compiler configuration.
//
// No preprocessor: the templates are plain markup and the scripts are
// TypeScript, which svelte-package and Vite both strip on their own. A
// preprocessor here would be a build step with nothing to do.
export default {
	compilerOptions: {
		// Every space in a sentence is the engine's or the page's, and the
		// differential in web/text-diff.mjs reads the answer character for
		// character against the page as it shipped. The compiler's default is to
		// collapse runs of whitespace in markup, which is what this asks for:
		// what must not move is written as an expression rather than as
		// literal whitespace.
		preserveWhitespace: false,
	},
};
