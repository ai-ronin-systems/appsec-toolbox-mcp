package main

import (
	"os"
	"os/exec"
)

func main() {
	exec.Command("sh", "-c", os.Args[1]).Run() // #nosec
}
