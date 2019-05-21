package main

import (
	"flag"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sevlyar/go-daemon"
	"github.com/sirupsen/logrus"
	"github.com/jschintag/notary-yubikey-adapter/yubikey"
)

// The Path of the Socket
const (
	SocketPath = "/var/run/notary"
	SocketName = "hardwarestore.sock"
	Socket     = SocketPath + "/" + SocketName
)

var (
	appName      string
	logLevel     string
	keymode      int
	keymodePin   string
	keymodeTouch bool
	stopSignal   *bool
	flagset      = make(map[string]bool)
	stop         = make(chan bool)
	done         = make(chan bool)
)

func setLogLevel() {
	switch logLevel {
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	default:
		invalidFlag("Invalid Log-Level")
	}
}

func invalidFlag(msg string) {
	fmt.Println(msg)
	flag.Usage()
	os.Exit(1)
}

func hasUtilityFlag() bool {
	return (flagset["stop"])
}

func checkRequiredFlags() {
	// no required Flags
}

func parseFlags() {
	flag.StringVar(&logLevel, "log", "error", "Set Log-Level")
	flag.StringVar(&keymodePin, "pin", "once", "Set the mode for the Pin [none | once | always], default: once")
	flag.BoolVar(&keymodeTouch, "touch", true, "Requires to touch the yubikey to sign")
	stopSignal = flag.Bool("stop", false, "Stop the daemon")

	flag.Parse()
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })
	appName = filepath.Base(os.Args[0])

	if !hasUtilityFlag() {
		checkRequiredFlags()
	}

	if flagset["pin"] {
		switch keymodePin {
		case "none":
			keymode = yubikey.KEYMODE_NONE
		case "once":
			keymode = yubikey.KEYMODE_PIN_ONCE
		case "always":
			keymode = yubikey.KEYMODE_PIN_ALWAYS
		default:
			invalidFlag(fmt.Sprintf("Wrong value '%s' for pin", keymodePin))
		}
	} else {
		keymode = yubikey.KEYMODE_PIN_ONCE
	}
	if flagset["touch"] {
		keymode = keymode | yubikey.KEYMODE_TOUCH
	}

	setLogLevel()
}

func socketExists() bool {
	_, err := os.Stat(Socket)
	return err == nil
}

func removeSocket() {
	if socketExists() {
		if err := os.Remove(Socket); err != nil {
			logrus.Errorf("Could not remove socket: %v", err)
		}
	}
}

func cleanup(listener net.Listener) {
	listener.Close()
	yubikey.Cleanup()
	removeSocket()
	done <- true
}

func worker() {
	err := yubikey.SetYubikeyKeyMode(keymode)
	if err != nil {
		logrus.Fatalf("Failed to set Yubikey Keymode: %v", err)
	}
	_ = os.MkdirAll(SocketPath, os.ModeDir)
	server := NewServer()
	rpc.Register(server)
	listener, err := net.Listen("unix", Socket)
	if err != nil {
		logrus.Fatalf("Failed to create Socket. %v", err)
	}
	defer cleanup(listener)
	logrus.Infof("Starting Server...")
	go rpc.Accept(listener)

	// wait for termination
	<-stop
}

func termHandler(sig os.Signal) error {
	logrus.Infof("Terminating daemon")
	stop <- true
	if sig == syscall.SIGQUIT {
		<-done
	}
	return daemon.ErrStop
}

func main() {
	parseFlags()
	daemon.AddCommand(daemon.BoolFlag(stopSignal), syscall.SIGTERM, termHandler)

	cntxt := &daemon.Context{
		PidFileName: (appName + ".pid"),
		PidFilePerm: 0644,
		LogFileName: (appName + ".log"),
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			logrus.Fatalf("Unable send signal to the daemon: %v", err)
		}
		daemon.SendCommands(d)
		return
	}

	d, err := cntxt.Reborn()
	if err != nil {
		logrus.Fatalf("Error: %v", err)
	}
	if d != nil {
		fmt.Printf("Started Adapter, to stop the daemon use '%s -stop'\n", appName)
		return
	}
	defer cntxt.Release()

	logrus.Infof("daemon started")

	go worker()

	err = daemon.ServeSignals()
	if err != nil {
		logrus.Errorf("Error: %v", err)
	}
	logrus.Infof("daemon terminated")
}
