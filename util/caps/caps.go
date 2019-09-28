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

// Dump dump the content of Caps
func (c *Caps) Dump() (d string) {
	for _, s := range c.API {
		d += fmt.Sprintf("API:%s\t", s)
	}
	return
}

// Union union caps
func (c *Caps) Union(caps *Caps) {
	c.API = append(c.API, caps.API...)
	c.cleanDup()
}

// Delete delete caps
func (c *Caps) Delete(caps *Caps) {
	m := make(map[string]bool)
	for _, item := range c.API {
		m[item] = true
	}
	c.API = []string{}
	for _, item := range caps.API {
		if item == "*" {
			return
		}
		if _, ok := m[item]; ok {
			delete(m, item)
		}
	}
	for k := range m {
		c.API = append(c.API, k)
	}
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
	c.API = API
	return
}
