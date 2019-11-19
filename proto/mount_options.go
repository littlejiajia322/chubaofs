package proto

const (
	// Mandatory
	MountPoint = "mountPoint"
	VolName    = "volName"
	Owner      = "owner"
	MasterAddr = "masterAddr"
	LogDir     = "logDir"
	WarnLogDir = "warnLogDir"
	// Optional
	LogLevel      = "logLevel"
	ProfPort      = "profPort"
	IcacheTimeout = "icacheTimeout"
	LookupValid   = "lookupValid"
	AttrValid     = "attrValid"
	ReadRate      = "readRate"
	WriteRate     = "writeRate"
	EnSyncWrite   = "enSyncWrite"
	AutoInvalData = "autoInvalData"
	Rdonly        = "rdonly"
	WriteCache    = "writecache"
	KeepCache     = "keepcache"
)
