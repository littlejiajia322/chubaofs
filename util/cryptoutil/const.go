package cryptoutil

const (
	RandomNumberOffset  = 0
	RandomNumberSize    = 8
	CheckSumOffset      = RandomNumberOffset + RandomNumberSize
	CheckSumSize        = 16
	MessageOffset       = CheckSumOffset + CheckSumSize
	MessageMetaDataSize = RandomNumberSize + CheckSumSize
)
