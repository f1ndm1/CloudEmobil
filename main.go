// @Title Golang SDK Client
// @Description This code is auto generated
// @Author Ecloud SDK

package main

import (
	config2 "ecloud/config"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"gitlab.ecloud.com/ecloud/ecloudsdkcore/config"
	"gitlab.ecloud.com/ecloud/ecloudsdkcore/position"
	"gitlab.ecloud.com/ecloud/ecloudsdkecs"
	"gitlab.ecloud.com/ecloud/ecloudsdkecs/model"
	"os"
)

// 使用AK&SK初始化账号Client
// @param accessKey
// @param secretKey
// @param poolId
// @return Client
func createClient(accessKey string, secretKey string, poolId string) *ecloudsdkecs.Client {
	config := &config.Config{
		AccessKey: accessKey,
		SecretKey: secretKey,
		PoolId:    poolId,
	}
	return ecloudsdkecs.NewClient(config)
}

// ListKey 列表创建的秘钥有哪些
func ListKey(ak string, sk string, pid string) {
	//创建客户端
	client := createClient(ak, sk, pid)
	request := &model.VmListKeyPairRequest{}
	response, err := client.VmListKeyPair(request)

	if err != nil {
		fmt.Printf("查询SSH密钥列表出现错误：%+v", err)
	} else {
		content := *response.Body.Content
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"SSH密钥名称", "Region"})
		for i := range content {
			table.Append([]string{content[i].Name, content[i].Region})
		}
		table.Render()
	}
}

// GetECSInfo 获取绑定的ECS信息
func GetECSInfo(ak string, sk string, pid string) (*[]config2.ECSInfo, error) {
	var ECSInfo []config2.ECSInfo
	//创建客户端
	client := createClient(ak, sk, pid)
	//信息查询
	request := &model.VmListServeRequest{}
	response, err := client.VmListServe(request)
	if err != nil {
		return nil, err
	} else {
		Total := *response.Body.Total
		content := *response.Body.Content
		fmt.Printf("此密钥关联云主机数量: %+v\n", Total)
		for i := range content {
			var ip = *content[i].PortDetail
			ecs := config2.ECSInfo{
				Id:       content[i].Id,
				UserName: content[i].UserName,
				Name:     content[i].Name,
				OpStatus: string(content[i].OpStatus),
				Region:   content[i].Region,
				FIP:      ip[0].FipAddress,
				IntraIP:  ip[0].PrivateIp,
				KeyName:  content[i].KeyName,
			}
			ECSInfo = append(ECSInfo, ecs)
		}
		return &ECSInfo, nil
	}
}

// CreatKey 创建SSH秘钥
func CreatKey(ak string, sk string, pid string, keyName string, region string, publicKey string) {
	//创建客户端
	client := createClient(ak, sk, pid)
	request := &model.VmInputKeyPairRequest{
		VmInputKeyPairBody: &model.VmInputKeyPairBody{Name: keyName, PublicKey: publicKey, Region: region},
	}
	response, err := client.VmInputKeyPair(request)
	if err == nil && response.State != "ERROR" {
		fmt.Printf("创建密钥成功！密钥名称：%+v", keyName)
	} else {
		fmt.Printf("创建密钥失败！%+v", response.ErrorMessage)
	}
}

// BindKeToECS 将SSH秘钥导入到ECS
func BindKeToECS(ak string, sk string, pid string, keyName string, id string) {
	client := createClient(ak, sk, pid)
	request := &model.VmBindServerKeypairRequest{
		VmBindServerKeypairBody: &model.VmBindServerKeypairBody{
			Body:     position.Body{},
			KeyName:  keyName,
			ServerId: id,
		},
	}
	response, err := client.VmBindServerKeypair(request)
	if err == nil && response.State != "ERROR" {
		fmt.Printf("成功将SSH密钥%+v绑定到云主机", keyName)
	} else {
		fmt.Println("绑定失败：", response.ErrorMessage)
	}
}

func main() {
	//1、初始化flag
	args := InitFlag()

	//判断flag执行相应的命令
	switch {
	case args.Mod == "info":
		//表格输出ECS信息
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"云主机Id", "订购用户名", "ECS名称", "状态", "Region", "内网IP", "开放IP", "绑定秘钥名称"})
		info, err := GetECSInfo(args.AK, args.SK, args.PoolID)
		for _, ecs := range *info {
			table.Append([]string{ecs.Id, ecs.UserName, ecs.Name, ecs.OpStatus, ecs.Region, ecs.IntraIP, ecs.FIP, ecs.KeyName})
		}
		table.Render()
		if err != nil {
			gologger.Error().Msgf(err.Error())
		}
	case args.Mod == "ck":
		//创建密钥
		CreatKey(args.AK, args.SK, args.PoolID, args.KeyName, args.Region, args.PublicKey)
		//输出秘钥列表信息
	case args.Mod == "lk":
		//列举密钥
		ListKey(args.AK, args.SK, args.PoolID)
	case args.Mod == "bd":
		BindKeToECS(args.AK, args.SK, args.PoolID, args.KeyName, args.ID)
	default:
		fmt.Printf("请通过-mod选择模式！\ninfo  查询绑定的所有ecs基本信息\nlk 列表ssh密钥\nck 创建ssh密钥\nbd 将SSH密钥绑定ECS")
	}
}

// Flag 标志
func Flag(args *config2.InputArgs) {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`ECloud Script Usage: 
1、帮助信息 eCloud.exe -h
2、查询绑定的ECS基本信息：eCloud.exe -mod info -ak 123 -sk 123 -pid 123
3、列表SSH密钥：eCloud.exe -mod lk -ak 123 -sk 123 -pid 123
3、创建SSH密钥：eCloud.exe -mod ck -ak 123 -sk 123 -pid 123 -name {SSH密钥名称} -region BJJD -pk "ssh-rsa AAAAB3"
4、SSH密钥绑定ECS：eCloud.exe -mod bd -ak 123 -sk 123 -pid 123 -name {SSH密钥名称} -id {云主机ID}
`)

	flagSet.CreateGroup("Mod", "执行模式",
		flagSet.StringVarP(&args.Mod, "Mod", "mod", "", "\n 执行模式设置"),
	)

	flagSet.CreateGroup("ECSInfo", "ECS信息查询",
		flagSet.StringVarP(&args.AK, "AccessKey", "ak", "", "\n Access Key设置"),
		flagSet.StringVarP(&args.SK, "SecretKey", "sk", "", "\n  Secret Key设置"),
		flagSet.StringVarP(&args.PoolID, "PoolID", "pid", "", "\n  区域ID设置"),
	)

	flagSet.CreateGroup("SSHKeyCreat", "创建SSHKey",
		flagSet.StringVarP(&args.KeyName, "KeyName", "name", "", "\n  公钥导入名称设置"),
		flagSet.StringVarP(&args.Region, "Region", "rg", "", "\n  Region设置"),
		flagSet.StringVarP(&args.PublicKey, "PublicKey", "pk", "", "\n  公钥值设置"),
	)

	flagSet.CreateGroup("SSHKeyBind", "绑定SSHKey",
		flagSet.StringVarP(&args.ID, "ID", "id", "", "\n  ECS ID"),
	)
	_ = flagSet.Parse()
}

func InitFlag() *config2.InputArgs {
	var banner = fmt.Sprintf(`
                  ██                       ██
                 ░██                      ░██
  █████   █████  ░██  ██████  ██   ██     ░██
 ██░░░██ ██░░░██ ░██ ██░░░░██░██  ░██  ██████
░███████░██  ░░  ░██░██   ░██░██  ░██ ██░░░██
░██░░░░ ░██   ██ ░██░██   ░██░██  ░██░██  ░██
░░██████░░█████  ███░░██████ ░░██████░░██████
 ░░░░░░  ░░░░░  ░░░  ░░░░░░   ░░░░░░  ░░░░░░ 
	`)
	gologger.Print().Msgf("%s\n", banner)
	//初始化flag
	var args config2.InputArgs
	Flag(&args)
	return &args
}
