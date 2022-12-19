// package logsec provides unix log & chroot services
package logsec

import (
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Global Shared Locks & [Info|Error|Debug} Channel
var (
	mutexLogD sync.Mutex
	waitLogD  sync.WaitGroup
	LogErr    = make(chan string, 100)
	LogInfo   = make(chan string, 100)
	LogDebug  = make(chan string, 100)
	fileCons  = make(chan string, 100)
)

//
// TYPES
//

// LogD ...
type LogD struct {
	App            string        // Log App Name
	LogMode        string        // backend event log target [SYSLOG|CONSOLE|MUTE] [disable: <empty>]
	FileName       string        // backend event log target [SYSLOG|CONSOLE|MUTE] [disable: <empty>]
	ErrorRateLimit time.Duration // global ddos protection via error event sender
}

// ChrootD ...
type ChrootD struct {
	DIR string // ch-root directory [disable: <empty>]
	UID int    // chroot user UID number [disable: 0]
	GID int    // chroot user GID number [disable: 0]
}

//
// API
//

// LogDaemon ...
func LogDaemon(c *LogD) {
	switch {
	case c.LogMode == "":
		return
	case !mutexLogD.TryLock():
		LogInfo <- "LogD already up & running"
		return
	}
	waitLogD.Add(3)
	switch c.LogMode {
	case "MUTE":
		mute(c)
	case "CONSOLE":
		cons(c)
	case "SYSLOG":
		sysl(c)
	case "FILE":
		file(c)
	default:
		panic("log daemon - unable to continue [logmode:invalid:" + c.LogMode + "]")
	}
	waitLogD.Wait()
}

// Chroot ...
func Chroot(c *ChrootD) bool {
	switch c.DIR {
	case "":
		ShowInf("UNSAFE MODE: CHANGEROOT IS DISABLED VIA CONFIG!")
	default:
		if !isDir(c.DIR) {
			if err := os.Mkdir(c.DIR, 0o770); err != nil {
				ShowErr("unable to create chroot dir [" + c.DIR + "]")
				return false
			}
		}
		if err := os.Chdir(c.DIR); err != nil {
			ShowErr("unable to change to [" + c.DIR + "]")
			return false
		}
		waitLogD.Wait() // [avoid init race with logD]
		if err := syscall.Chroot("."); err != nil {
			ShowErr("chroot error [" + c.DIR + "]")
			return false
		}
		LogInfo <- "[chroot:success] [chrootdir:" + c.DIR + "] [pid:" + strconv.Itoa(os.Getpid()) + "]"
	}
	if c.UID != 0 && c.GID != 0 && !changeID(c) {
		return false
	}
	if !isWriteable("testfile") {
		ShowInf("unable to write within [current dir]")
	}
	LogInfo <- "[uid:" + strconv.Itoa(c.UID) + "] [gid:" + strconv.Itoa(c.GID) + "]"
	return true
}

//
// CONSOLE IO
//

// ShowInf ...
func ShowInf(in string) {
	Show("[INFO]  : " + in)
}

// ShowErr ...
func ShowErr(in string) {
	Show("[ERROR] : " + in)
}

// ShowDebug ...
func ShowDebug(in string) {
	Show("[DEBUG] : " + in)
}

//
// DISPLAY IO
//

// Show ...
func Show(in string) {
	os.Stdout.Write([]byte(in + "\n"))
}

//
// INTERNAL BACKEND
//

// mute ...
func mute(c *LogD) {
	defer mutexLogD.Unlock()
	ShowInf("syslog events disabled - unable to log any backend events")
	go func() {
		waitLogD.Done()
		for x := range LogInfo {
			_ = x
		}
	}()
	go func() {
		waitLogD.Done()
		for range LogErr {
			time.Sleep(c.ErrorRateLimit) // global err rate limit lock
		}
	}()
	go func() {
		waitLogD.Done()
		for x := range LogDebug {
			_ = x
		}
	}()
}

// cons ...
func cons(c *LogD) {
	defer mutexLogD.Unlock()
	go func() {
		waitLogD.Done()
		for msg := range LogInfo {
			ShowInf(msg)
		}
	}()
	go func() {
		waitLogD.Done()
		for msg := range LogErr {
			ShowErr(msg)
			time.Sleep(c.ErrorRateLimit) // global err rate limit lock
		}
	}()
	go func() {
		waitLogD.Done()
		for msg := range LogDebug {
			ShowDebug(msg)
		}
	}()
}

// sysl ...
func sysl(c *LogD) {
	defer mutexLogD.Unlock()
	go func() {
		l := slog(syslog.LOG_INFO, c.App)
		waitLogD.Done()
		for msg := range LogInfo {
			array := strings.Split(msg, "\n")
			for _, s := range array {
				l.Info(s)
			}
		}
	}()
	go func() {
		l := slog(syslog.LOG_ERR, c.App)
		waitLogD.Done()
		for msg := range LogErr {
			array := strings.Split(msg, "\n")
			for _, s := range array {
				l.Err(s)
			}
			time.Sleep(c.ErrorRateLimit) // global err rate limit lock
		}
	}()
	go func() {
		l := slog(syslog.LOG_DEBUG, c.App)
		waitLogD.Done()
		for msg := range LogDebug {
			array := strings.Split(msg, "\n")
			for _, s := range array {
				l.Debug(s)
			}
		}
	}()
}

// file ...
func file(c *LogD) {
	defer mutexLogD.Unlock()
	go func() {
		f, err := os.OpenFile(c.FileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			panic("log daemon - unable to continue [log:file] [unable to create log file]")
		}
		defer f.Close()
		for msg := range fileCons {
			if _, err := f.Write([]byte(msg + "\n")); err != nil {
				panic("log daemon - unable to continue [log:file] [unable to write to log file] [" + c.FileName + "]")
			}
		}
	}()
	go func() {
		waitLogD.Done()
		for msg := range LogInfo {
			fileCons <- "[" + time.Now().Format(time.RFC3339) + "] [INFO]  : " + msg
		}
	}()
	go func() {
		waitLogD.Done()
		for msg := range LogDebug {
			fileCons <- "[" + time.Now().Format(time.RFC3339) + "] [DEBUG] : " + msg
		}
	}()
	go func() {
		waitLogD.Done()
		for msg := range LogErr {
			fileCons <- "[" + time.Now().Format(time.RFC3339) + "] [ERROR] : " + msg
			time.Sleep(c.ErrorRateLimit) // global err rate limit lock
		}
	}()
}

//
// PROCESS HELPER
//

func changeID(c *ChrootD) bool {
	if c.DIR != "" {
		if err := os.Chown(".", c.UID, c.GID); err != nil {
			ShowErr("unable to change owner/group for chroot folder")
			return false
		}
		if err := os.Chmod(".", 0o770); err != nil {
			ShowErr("unable to change owner/group for store")
			return false
		}
	}
	if err := syscall.Setgid(c.GID); err != nil {
		ShowErr("priv drop gid number error")
		return false
	}
	if err := syscall.Setuid(c.UID); err != nil {
		ShowErr("priv drop uid number error")
		return false
	}
	return true
}

//
// SYSLOG IO
//

func slog(target syslog.Priority, appname string) *syslog.Writer {
	log, err := syslog.Dial("", "", target, appname)
	if err != nil {
		ShowErr("unable to create info log [" + err.Error() + "]")
		panic("log deamon terminated - unable to continue")
	}
	return log
}

//
// FILE IO
//

func isDir(filename string) bool {
	inf, err := os.Lstat(filename)
	if err != nil {
		return false
	}
	mode := inf.Mode()
	if !mode.IsDir() {
		return false
	}
	return true
}

func isWriteable(file string) bool {
	defer os.Remove(file)
	if err := os.WriteFile(file, []byte("test"), 0o660); err != nil {
		return false
	}
	return true
}

func isSymlink(filename string) bool {
	if _, err := os.Readlink(filename); err != nil {
		return false
	}
	return true
}
