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
	resp, err := http.PostForm("http://localhost:8080/client/getticket",
		url.Values{"clientID": {"client1"}, "service": {"master"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		panic(err2)
	}
	//fmt.Println("post:\n", keepLines(string(body), 3))
	fmt.Println("respose: %s", string(body))
}
