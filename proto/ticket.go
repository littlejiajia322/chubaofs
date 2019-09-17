package proto

/*
* MITM:
*      (1) talking to the right party (nonce)
*      (2) replay attack (Ip, timestamp constrains)
* client capability changes (ticket timestamp)
*/

type CryptoKey struct {
  C_time int64 `json:"c_time"`
  Key []byte `json:"key"`
}
type ticket struct {
  Session_key CryptoKey `json:"session_key"`
  Exp int64 `json:"exp"`
  Ip []byte `json:"ip"`
  Caps []byte `json:"caps"`
}