package utils

import (
	"fmt"
	"os"
	"path"
	"strings"

	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	packager "github.com/hyperledger/fabric-sdk-go/pkg/fab/ccpackager/gopackager"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"

	"github.com/pkg/errors"
)

func CreateChannel(chId, chCfgPath, targetOrder string, signIdentity []msp.SigningIdentity, peerResMgmt *resmgmt.Client) error {

	// 判断是否已经创建
	created, err := IsCreatedChannel(chId, peerResMgmt, targetOrder)
	if err != nil {
		return errors.Wrap(err, "error check if channel created")
	}
	if created {
		Log.Info(fmt.Sprintf("channel %s has already created ", chId))
		return nil
	}

	//var lastConfigBlockNum uint64

	// 构建请求
	req := resmgmt.SaveChannelRequest{
		ChannelID:         chId,
		ChannelConfigPath: chCfgPath,
		SigningIdentities: signIdentity,
	}

	// 发送创建请求
	_, err = peerResMgmt.SaveChannel(req, resmgmt.WithOrdererEndpoint(targetOrder))
	if err != nil {
		return errors.Wrap(err, "error SaveChannel when CreateChannel")
	}

	return nil

}

func UpdateAnchorPeer(chId, chCfgPath, targetOrder string, signIdentity []msp.SigningIdentity, peerResMgmt *resmgmt.Client) error {

	// 构建请求
	req := resmgmt.SaveChannelRequest{
		ChannelID:         chId,
		ChannelConfigPath: chCfgPath,
		SigningIdentities: signIdentity,
	}

	// 发送创建请求
	_, err := peerResMgmt.SaveChannel(req, resmgmt.WithOrdererEndpoint(targetOrder))
	if err != nil {
		return errors.Wrap(err, "error SaveChannel when UpdateAnchorPeer")
	}

	return nil

}

// targetPeers与peerOrgResMgmt需是同一个org下的
// 指定身份：signPayload中选择fabsdk.context中的用户
func JoinChannel(chId, targetOrder string, targetPeers []string, peerOrgResMgmt *resmgmt.Client) error {
	var err error
	realTargets := make([]string, 0)
	// 判断是否已经加入过
	for _, target := range targetPeers {
		joined, err := IsJoinedChannel(chId, peerOrgResMgmt, target)
		if err != nil {
			return err
		}
		if joined {
			Log.Info(fmt.Sprintf("%s has already joined channel %s", target, chId))
			return nil
		} else {
			realTargets = append(realTargets, target)
		}
	}

	// 加入通道
	if len(realTargets) > 0 {
		err = peerOrgResMgmt.JoinChannel(
			chId,
			resmgmt.WithRetry(retry.DefaultResMgmtOpts),
			resmgmt.WithOrdererEndpoint(targetOrder),
			resmgmt.WithTargetEndpoints(realTargets...),
		)
		if err != nil {
			return errors.Wrap(err, "error JoinChannel")
		}

	}

	return nil
}

// targetPeers与peerOrgResMgmt需是同一个org下的
// cc install是针对peer的，每个peer都得执行一遍
// 指定身份：signProposal中选择fabsdk.context中的用户
func InstallCC(ccId, ccVersion, ccPath string, targetPeers []string, peerOrgResMgmt *resmgmt.Client) error {

	realTargets := make([]string, 0)
	// 判断是否已经install
	for _, target := range targetPeers {
		installed, err := IsCCInstalled(peerOrgResMgmt, ccId, ccVersion, target)
		if err != nil {
			return errors.Wrap(err, "error check if cc installed")
		}
		if installed {
			Log.Info(fmt.Sprintf("%s has already installed cc %s:%s", target, ccId, ccVersion))
			return nil
		} else {
			realTargets = append(realTargets, target)
		}
	}

	if len(realTargets) > 0 {
		ccPkg, err := packager.NewCCPackage(ccPath, "")
		if err != nil {
			return errors.Wrap(err, "error NewCCPackage when InstallCC")
		}

		// 构建请求
		pwd, _ := os.Getwd()
		ccAbsPath := path.Join(pwd, ccPath)
		req := resmgmt.InstallCCRequest{
			Name:    ccId,
			Path:    ccAbsPath,
			Version: ccVersion,
			Package: ccPkg,
		}

		// install cc
		_, err = peerOrgResMgmt.InstallCC(req, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(realTargets...))
		if err != nil {
			return errors.Wrap(err, "error InstallCC function when InstallCC")
		}

	}

	return nil
}

// targetPeers与peerOrgResMgmt需是同一个org下的
// cc instantiate是针对channel的，只需执行一遍
// 指定身份：signProposal中选择fabsdk.context中的用户
func InstantiateCC(chId, ccId, ccVersion, ccPath string, ccPolicy *cb.SignaturePolicyEnvelope, targetPeers []string, peerOrgResMgmt *resmgmt.Client) error {

	// 判断是否已经instantiated
	var code string
	var err error
	for _, target := range targetPeers {
		code, err = InstantiateOrUpdate(peerOrgResMgmt, chId, ccId, ccVersion, target)
		if err != nil {
			return errors.Wrap(err, "error check if instantiate or update CC")
		}
		break // 针对channel而言，instantiated判断执行一遍即可
	}

	pwd, _ := os.Getwd()
	ccAbsPath := path.Join(pwd, ccPath)
	switch code {
	case "0":
		Log.Info(fmt.Sprintf("channel %s has already instantiate cc %s:%s ", chId, ccId, ccVersion))
	case "1":
		// 构建请求
		req := resmgmt.InstantiateCCRequest{
			Name:    ccId,
			Path:    ccAbsPath,
			Version: ccVersion,
			Policy:  ccPolicy,
		}
		// instantiate cc
		_, err := peerOrgResMgmt.InstantiateCC(chId, req, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(targetPeers...))
		if err != nil {
			return errors.Wrap(err, "error InstantiateCC function when InstantiateCC")
		}
		//log.Println(fmt.Sprintf("%v in channel %s instantiate cc %s:%s success, txId is %s", targetPeers, chId, ccId, ccVersion, resp.TransactionID))
	case "2":
		req := resmgmt.UpgradeCCRequest{
			Name:    ccId,
			Path:    ccAbsPath,
			Version: ccVersion,
			Policy:  ccPolicy,
		}
		// upgrade cc
		_, err := peerOrgResMgmt.UpgradeCC(chId, req, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(targetPeers...))
		if err != nil {
			return errors.Wrap(err, "error UpgradeCC function when InstantiateCC")
		}
		//log.Println(fmt.Sprintf("%v in channel %s upgrade cc %s:%s success, txId is %s", targetPeers, chId, ccId, ccVersion, resp.TransactionID))
	}

	return nil
}

// 若不指定targetpeer，则从配置文件中取
// 指定身份：signProposal中选择fabsdk.context中的用户
func InvokeCC(chClient *channel.Client, req channel.Request, targetPeers []string) (*channel.Response, error) {

	response, err := chClient.Execute(req, channel.WithTargetEndpoints(targetPeers...))
	if err != nil {
		return nil, errors.Wrap(err, "error Execute when InvokeCC")
	}

	return &response, nil
}

// 指定身份：signProposal中选择fabsdk.context中的用户
func QueryCC(chClient *channel.Client, req channel.Request, targetPeers []string) (*channel.Response, error) {

	response, err := chClient.Query(req, channel.WithTargetEndpoints(targetPeers...))
	if err != nil {
		return nil, errors.Wrap(err, "error Query when QueryCC")
	}

	return &response, nil
}

func QueryBlockByNum(ldgCLient *ledger.Client, num uint64, targetPeer string) (*cb.Block, error) {

	block, err := ldgCLient.QueryBlock(num, ledger.WithTargetEndpoints(targetPeer))
	if err != nil {
		return nil, errors.Wrap(err, "error QueryBlock when QueryBlockByNum")
	}

	return block, nil

}

func QueryBlockByTxId(ldgCLient *ledger.Client, txId string, targetPeer string) (*cb.Block, error) {

	txID := fab.TransactionID(txId)

	block, err := ldgCLient.QueryBlockByTxID(txID, ledger.WithTargetEndpoints(targetPeer))
	if err != nil {
		return nil, errors.Wrap(err, "error QueryBlockByTxID function when QueryBlockByTxId")
	}

	return block, nil

}

// peer resMgmt
func IsCreatedChannel(channelID string, resMgmtClient *resmgmt.Client, targetOrder string) (bool, error) {

	chCfg, err := resMgmtClient.QueryConfigFromOrderer(channelID, resmgmt.WithOrdererEndpoint(targetOrder))
	if err != nil {
		if strings.Contains(err.Error(), "NOT_FOUND") {
			return false, nil
		}
		return false, err
	}

	if chCfg.ID() == channelID {
		return true, nil
	}

	return false, nil
}

// peer resMgmt
// 只能一个一个peer的查询
func IsJoinedChannel(channelID string, resMgmtClient *resmgmt.Client, targetPeer string) (bool, error) {

	resp, err := resMgmtClient.QueryChannels(resmgmt.WithTargetEndpoints(targetPeer))
	if err != nil {
		return false, err
	}
	for _, chInfo := range resp.Channels {
		if chInfo.ChannelId == channelID {
			return true, nil
		}
	}
	return false, nil
}

// peer resMgmt
// 只能一个一个peer的查询
func IsCCInstalled(resMgmt *resmgmt.Client, ccName, ccVersion string, targetPeer string) (bool, error) {

	resp, err := resMgmt.QueryInstalledChaincodes(resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(targetPeer))
	if err != nil {
		return false, err
	}
	found := false
	for _, ccInfo := range resp.Chaincodes {
		if ccInfo.Name == ccName && ccInfo.Version == ccVersion {
			found = true
			break
		}
	}

	return found, nil
}

// peer resMgmt
// 只能一个一个peer的查询
func IsCCInstantiated(resMgmt *resmgmt.Client, channelId, ccName, ccVersion string, targetPeer string) (bool, error) {

	resp, err := resMgmt.QueryInstantiatedChaincodes(channelId, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(targetPeer))
	if err != nil {
		return false, err
	}
	instantiated := false
	for _, ccInfo := range resp.Chaincodes {
		if ccInfo.Name == ccName && ccInfo.Version == ccVersion {
			instantiated = true
			break
		}
	}

	return instantiated, nil
}

// peer resMgmt
// 只能一个一个peer的查询: 0，已instantiated；1，需要instantiate；2，需要update
func InstantiateOrUpdate(resMgmt *resmgmt.Client, channelId, ccName, ccVersion string, targetPeer string) (string, error) {
	if resMgmt == nil || channelId == "" || ccName == "" || ccVersion == "" || targetPeer == "" {
		return "", errors.New("InstantiateOrUpdate failed. some arg is null. ")
	}

	resp, err := resMgmt.QueryInstantiatedChaincodes(channelId, resmgmt.WithRetry(retry.DefaultResMgmtOpts), resmgmt.WithTargetEndpoints(targetPeer))
	if err != nil {
		return "", errors.Wrap(err, "error QueryInstantiatedChaincodes")
	}
	instantiated := false
	upgrade := false
	for _, ccInfo := range resp.Chaincodes {
		if ccInfo.Name == ccName && ccInfo.Version == ccVersion {
			instantiated = true
			break
		}
	}
	for _, ccInfo := range resp.Chaincodes {
		if ccInfo.Name == ccName && ccInfo.Version != ccVersion {
			upgrade = true
			break
		}
	}

	if instantiated {
		return "0", nil
	}
	if !instantiated && !upgrade {
		return "1", nil
	}
	if !instantiated && upgrade {
		return "2", nil
	}

	return "", nil
}
