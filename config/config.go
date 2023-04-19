package config

// ECSInfo 主机信息
type ECSInfo struct {
	//云主机ID
	Id string
	//订购用户名称
	UserName string
	//云主机名称
	Name string
	//云主机状态
	OpStatus string
	//云主机region信息
	Region string
	//云主机内网IP
	IntraIP string
	//云主机外网IP
	FIP string
	//云主机绑定秘钥名称
	KeyName string
}

type InputArgs struct {
	AK        string
	SK        string
	PoolID    string
	KeyName   string
	Region    string
	PublicKey string
	Mod       string
	ID        string
}

// KeyList 主机信息
type KeyList struct {
	//云主机ID

}
