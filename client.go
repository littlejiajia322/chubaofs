package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// keep first n lines
func keepLines(s string, n int) string {
	result := strings.Join(strings.Split(s, "\n")[:n], "\n")
	return strings.Replace(result, "\r", "", -1)
}

func main() {
	// We can use POST form to get result, too.
	resp, err = http.PostForm("http://localhost:8080",
		url.Values{"q": {"github"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	fmt.Println("post:\n", keepLines(string(body), 3))
}
