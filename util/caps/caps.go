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
				b = true;
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
	fmt.Printf("Init %v\n", c)
	return
}
