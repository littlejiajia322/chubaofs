package caps

import (
	"encoding/json"

	//"github.com/chubaofs/chubaofs/util/cryptoutil"
)

type Caps struct {
	resources map[string](map[string]bool)
}

func (c *Caps) ContainCaps(kind string, cap string) (b bool) {
  b = false
  if _, ok := c.resources[kind]; ok {
    if _, ok := c.resources[kind]["*"]; ok {
      b = true;
    } else if _, ok := c.resources[kind][cap]; ok {
      b = true;
    }
  }
	return
}

// Init init a Caps instance
func (c *Caps) Init(b []byte) (err error) {
	/*var (
		jbytes []byte
	)
  
	if jbytes, err = cryptoutil.Base64Decode(str); err != nil {
		return
	}*/
	if err = json.Unmarshal(b, c); err != nil {
		return
	}
	return
}
