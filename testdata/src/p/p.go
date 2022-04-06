package p

import (
	"fmt"
	"net"
)

func _() {
	_ = fmt.Sprintf("gopher://%s/foo", net.JoinHostPort("foo", "80"))

	_ = fmt.Sprintf("http://%s/foo", net.JoinHostPort("foo", "80"))

	_ = fmt.Sprintf("telnet+ssl://%s/foo", net.JoinHostPort("foo", "80"))

	_ = fmt.Sprintf("http://%s/foo:bar", net.JoinHostPort("foo", "80"))

	_ = fmt.Sprintf("http://example.com:9211")

	_ = fmt.Sprintf("gopher://%s:%d", "myHost", 70) // want "should be constructed with net.JoinHostPort"

	_ = fmt.Sprintf("telnet+ssl://%s:%d", "myHost", 23) // want "should be constructed with net.JoinHostPort"

	_ = fmt.Sprintf("https://%s:%d", "myHost", 8443) // want "should be constructed with net.JoinHostPort"

	_ = fmt.Sprintf("https://%s:9211", "myHost") // want "should be constructed with net.JoinHostPort"
}