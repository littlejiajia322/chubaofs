package proto

import (
	"fmt"
	"github.com/chubaofs/chubaofs/util/cryptoutil"
	"testing"
)

func TestTicket(t *testing.T) {
	var (
		ticketStr string
		key       []byte
	)
	ticketStr = "0TszliLoGGRhjN71YtTFkQEAaa4MZHMvM6hpnIAojczyu9A8Qlyk2OJkm5AF/qW74tbxvEzRNcj14ZsAt3gE1xkhEFPYIhiaTxTFgx+C0vFeQLyoWBYWr1XpzH8JEVGYjsg22MjTt5h9wPi5xtd8+YDWv9UHHDT+cwTre5QkSB4hYt6WvsWg8pOJbI8sMitO98OYsWzQF1GMvbyGGEbFuFjw1bAHX9xuRUQ6RTnZboCxkxKWFurhD565pGXa9c9AQqGK0g7HmRP4yzY8qgsrWjAo0bYn3F8pmFYcg=="
	key, err := cryptoutil.Base64Decode("poMz6ISzeGq10pRNyDtz8AXHNVhtJh8ZvFv8JrGi3Ro=")
	fmt.Printf("key is %v, err is %v", key, err)
	ticket, err := ExtractTicket(ticketStr, key)
	if err != nil {
		fmt.Printf("extractTicket failed: %s", err.Error())
	}
	fmt.Printf("ticket: %v", ticket)
}
