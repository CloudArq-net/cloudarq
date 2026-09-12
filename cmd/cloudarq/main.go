// Command cloudarq turns a cloud trust policy into the list of who it admits.
package main

import (
	"fmt"
	"os"
)

var version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("cloudarq", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: cloudarq admits <policy>")
	os.Exit(2)
}
