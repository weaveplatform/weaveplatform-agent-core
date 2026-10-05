// Command rawmodule misbehaves at the handshake, one way per RAWMOD_MODE,
// so the supervisor's launch failure paths can be driven by a real process.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	switch os.Getenv("RAWMOD_MODE") {
	case "exit":
		os.Exit(3)
	case "hang":
		time.Sleep(time.Hour)
	case "garbage":
		fmt.Println("hello, I am not a handshake")
		time.Sleep(time.Hour)
	case "flood":
		fmt.Print(strings.Repeat("x", 1<<17))
		time.Sleep(time.Hour)
	case "wrong-protocol":
		fmt.Println("WEAVE|1|9|unix|/nonexistent")
		time.Sleep(time.Hour)
	case "nobody-home":
		// A well-formed line naming an address nothing listens on.
		network := "unix"
		addr := os.Getenv("WEAVE_SOCKET_DIR") + "/nobody.sock"
		if os.PathSeparator == '\\' {
			network, addr = "npipe", `\\.\pipe\weave-rawmodule-nobody`
		}
		fmt.Printf("WEAVE|1|1|%s|%s\n", network, addr)
		time.Sleep(time.Hour)
	case "die-after-handshake":
		// What a module whose listener fails after the handshake line does:
		// the address it named is gone before core dials it.
		network := "unix"
		addr := os.Getenv("WEAVE_SOCKET_DIR") + "/gone.sock"
		if os.PathSeparator == '\\' {
			network, addr = "npipe", `\\.\pipe\weave-rawmodule-gone`
		}
		fmt.Printf("WEAVE|1|1|%s|%s\n", network, addr)
		fmt.Fprintln(os.Stderr, "grpc server: listener: Access is denied.")
		os.Exit(1)
	}
}
