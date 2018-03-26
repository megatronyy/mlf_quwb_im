package main

import (
	"bufio"
	"os"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"strings"
	"time"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/discover"
	ethparams "github.com/ethereum/go-ethereum/params"
	whisper "github.com/ethereum/go-ethereum/whisper/whisperv5"
	"github.com/urfave/cli"
)

const (
	quitCommand = "~Q"
)

// singletons
var (
	server *p2p.Server
	shh    *whisper.Whisper
	done   chan struct{}

	input = bufio.NewReader(os.Stdin)
)

//encryption
var (
	symKey   []byte
	asymKey  *ecdsa.PrivateKey
	topic    whisper.TopicType
	filterID string
)

var (
	DataDirFlag = utils.DirectoryFlag{
		Name:  "datadir",
		Usage: "Data directory for the databases and keystore",
		Value: utils.DirectoryString{ "datadir" },
	}
)

//cmd arguments
var (
	argVerbosity = flag.Int("verbosity", int(log.LvlError), "log verbosity level")
	argTopic     = flag.String("topic", "44c7429f", "topic in hexadecimal format (e.g. 70a4beef)")
	argPass      = flag.String("password", "123456", "message's encryption password")
)

var (
	initCommand = cli.Command{
		Name:  "init",
		Usage: "初始化程序",
		Action: func(c *cli.Context) error {
			fmt.Println("命令测试")
			return nil
		},
	}

	nodeFlags = []cli.Flag{
		DataDirFlag,
	}

	app = cli.NewApp()
)

func init() {
	app.Version = "0.0.1"
	app.Action = goIM
	app.Copyright = "Copyright 2018-2020 The go-im Authors"
	app.Usage = "this is a IM tool"
	app.Commands = []cli.Command{
		initCommand,
	}

	app.Flags = append(app.Flags, nodeFlags...)
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Println(os.Stderr, err)
		os.Exit(1)
	}
}

func goIM(ctx *cli.Context) error {
	flag.Parse()
	initialize()
	run()

	return nil
}

func initialize() {
	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(*argVerbosity), log.StreamHandler(os.Stderr, log.TerminalFormat(true))))

	done = make(chan struct{})
	var peers []*discover.Node
	var err error
	var asymKeyID string

	//connect to mainnet
	for _, node := range ethparams.MainnetBootnodes {
		peer := discover.MustParseNode(node)
		peers = append(peers, peer)
	}
	peer := discover.MustParseNode("enode://1aced74994e515cf276961031f1ff5b9046cf905f5cf717d8af7baac9a90a5be5fc5363c6e52eb6ec886c7390a225e520f7940dbb73c0312a1a20565ef2aabea@172.20.16.183:30303")
	peers = append(peers, peer)
	shh = whisper.New(nil)

	asymKeyID, err = shh.NewKeyPair()
	if err != nil {
		utils.Fatalf("Failed to generate a new key pair: %s", err)
	}

	asymKey, err = shh.GetPrivateKey(asymKeyID)
	if err != nil {
		utils.Fatalf("Failed to retrieve a new key pair: %s", err)
	}

	maxPeers := 80

	server = &p2p.Server{
		Config: p2p.Config{
			PrivateKey:     asymKey,
			MaxPeers:       maxPeers,
			Name:           common.MakeName("p2p chat group", "5.0"),
			Protocols:      shh.Protocols(),
			NAT:            nat.Any(),
			BootstrapNodes: peers,
			StaticNodes:    peers,
			TrustedNodes:   peers,
		},
	}
}

func run() {
	startServer()
	defer server.Stop()

	shh.Start(nil)
	defer shh.Stop()
	//接收消息
	go messageLoop()
	//控制台发送消息
	sendLoop()
}

//开启p2p.server
func startServer() {
	err := server.Start()
	if err != nil {
		utils.Fatalf("Failed to start Whisper peer: %s.", err)
	}

	fmt.Println("Whisper node started,please send message after connect to other nodes")
	// first see if we can establish connection, then ask for user input
	waitForConnection(false)
	configureNode()
	subscribeMessage()

	fmt.Printf("Please type the message. To quit type: '%s'\n", quitCommand)
}

//配置节点相关属性
func configureNode() {
	symKeyID, err := shh.AddSymKeyFromPassword(*argPass)
	if err != nil {
		utils.Fatalf("Failed to create symmetric key: %s", err)
	}
	symKey, err = shh.GetSymKey(symKeyID)
	if err != nil {
		utils.Fatalf("Failed to save symmetric key: %s", err)
	}
	copy(topic[:], common.FromHex(*argTopic))
	fmt.Printf("Filter is configured for the topic: %x \n", topic)
}

//订阅关注的消息
func subscribeMessage() {
	var err error

	filter := whisper.Filter{
		KeySym:   symKey,
		KeyAsym:  asymKey,
		Topics:   [][]byte{topic[:]},
		AllowP2P: true,
	}

	filterID, err = shh.Subscribe(&filter)
	if err != nil {
		utils.Fatalf("Failed to install filter: %s", err)
	}
}

//等待节点连接
func waitForConnection(timeout bool) {
	var cnt int
	var connected bool
	for !connected {
		time.Sleep(time.Millisecond * 500)
		connected = server.PeerCount() > 0
		if timeout {
			cnt++
			if cnt > 1000 {
				utils.Fatalf("Timeout expired, failed to connect")
			}
		}
	}

	fmt.Println("Connected to peer,you can type message now.")
}

//等待消息输入并发送
func sendLoop() {
	for {
		s := scanLine(fmt.Sprintf("input %s to quit>", quitCommand))
		if s == quitCommand {
			fmt.Println("Quit command received")
			close(done)
			break
		}

		sendMsg([]byte(s))
	}
}

//发送消息
func sendMsg(payload []byte) common.Hash {
	params := whisper.MessageParams{
		Src:      asymKey,
		KeySym:   symKey,
		Payload:  payload,
		Topic:    topic,
		TTL:      whisper.DefaultTTL,
		PoW:      whisper.DefaultMinimumPoW,
		WorkTime: 5,
	}

	msg, err := whisper.NewSentMessage(&params)
	if err != nil {
		utils.Fatalf("failed to create new message: %s", err)
	}

	envelope, err := msg.Wrap(&params)

	if err != nil {
		fmt.Printf("failed to seal message: %v \n", err)
		return common.Hash{}
	}

	err = shh.Send(envelope)

	if err != nil {
		fmt.Printf("failed to send message: %v \n", err)
		return common.Hash{}
	}

	return envelope.Hash()
}

//等待消息
func messageLoop() {
	f := shh.GetFilter(filterID)
	if f == nil {
		utils.Fatalf("filter is not installed")
	}
	//生成一个50毫秒的ticker
	ticker := time.NewTicker(time.Millisecond * 50)

	for {
		select {
		case <-ticker.C: //chan Time
			messages := f.Retrieve()
			for _, msg := range messages {
				printMessageInfo(msg)
			}
		case <-done:
			return
		}
	}
}

//界面输出消息
func printMessageInfo(msg *whisper.ReceivedMessage) {
	text := string(msg.Payload)
	timestamp := time.Unix(int64(msg.Sent), 0).Format("2006-01-02 15:04:05")
	var address common.Address
	if msg.Src != nil {
		address = crypto.PubkeyToAddress(*msg.Src)
	}

	if whisper.IsPubKeyEqual(msg.Src, &asymKey.PublicKey) {
		fmt.Printf("\n%s <mine>: %s\n", timestamp, text) // message from myself
	} else {
		fmt.Printf("\n%s [%x]: %s\n", timestamp, address, text) // message from a peer
	}
	fmt.Printf("input %s to quit>", quitCommand)
}

func scanLine(prompt string) string {
	if len(prompt) > 0 {
		fmt.Print(prompt)
	}

	txt, err := input.ReadString('\n')
	if err != nil {
		utils.Fatalf("input error：%s", err)
	}
	txt = strings.TrimRight(txt, "\n\r")
	return txt
}
