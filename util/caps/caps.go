package caps

import (
	"encoding/json"
	"fmt"
	//"github.com/chubaofs/chubaofs/util/cryptoutil"
)

// Caps defines the capability type
type Caps struct {
	API []string
}

// ContainCaps whether contain a capability with kind
func (c *Caps) ContainCaps(kind string, cap string) (b bool) {
	b = false
	if kind == "API" {
		for _, s := range c.API {
			if s == "*" || s == cap {
				b = true
				return
			}
		}
	}
	return
}

// Init init a Caps instance
func (c *Caps) Init(b []byte) (err error) {
	fmt.Printf("Init %s\n", string(b))
	if err = json.Unmarshal(b, c); err != nil {
		return
	}
	c.cleanDup()
	fmt.Printf("Init %v\n", c)
	return
}

// DumpCaps dump the content of Caps
func (c *Caps) DumpCaps() {
	for _, s := range c.API {
		fmt.Printf("API:%s\n", s)
	}
	return
}

// Union union caps
func (c *Caps) Union(caps *Caps) {
	c.API = append(c.API, caps.API...)
	c.cleanDup()
}

func (c *Caps) cleanDup() {
	API := make([]string, 0)
	m := make(map[string]bool)
	for _, item := range c.API {
		if item == "*" {
			c.API = []string{"*"}
			return
		}
		if _, ok := m[item]; !ok {
			API = append(API, item)
			m[item] = true
		}
	}
	return
}
