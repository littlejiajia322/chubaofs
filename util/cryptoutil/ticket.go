package cryptoutil

const (
	TicketVersion = 1
	TicketAge     = 6 * 60
	//TicketAge     = 24 * 60 * 60		//TODO 改回
)

// CryptoKey store the session key
type CryptoKey struct {
	Ctime int64  `json:"c_time"`
	Key   []byte `json:"key"`
}

/*
* MITM thread:
*      (1) talking to the right party (nonce, key encryption)
*      (2) replay attack (IP, timestamp constrains)
*
* Other thread: Client capability changes (ticket timestamp)
 */

// Ticket is a temperary struct to store the permission/caps for a client to
// access principle
type Ticket struct {
	Version    uint8     `json:"version"`
	ServiceID  string    `json:"service_id"`
	SessionKey CryptoKey `json:"session_key"`
	Exp        int64     `json:"exp"`
	IP         string    `json:"ip"`
	Caps       []byte    `json:"caps"`
}
