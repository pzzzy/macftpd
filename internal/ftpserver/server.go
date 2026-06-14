package ftpserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"macftpd/internal/activity"
	"macftpd/internal/auth"
	"macftpd/internal/config"
	"macftpd/internal/natpmp"
	"macftpd/internal/ratelimit"
	"macftpd/internal/status"
	"macftpd/internal/storage"
	"macftpd/internal/upnpigd"
)

type Server struct {
	cfg         config.FTPConfig
	auth        *auth.Store
	root        *storage.Root
	ports       []int
	portMu      sync.Mutex
	nextPort    int
	addrMu      sync.RWMutex
	listener    net.Listener
	localAddr   string
	externalMu  sync.RWMutex
	externalIP  string
	natMu       sync.Mutex
	natGateway  string
	upnpMu      sync.Mutex
	upnpClient  *upnpigd.Client
	limiter     *ratelimit.Limiter
	activity    *activity.Store
	tracker     *status.Tracker
	tlsConfig   *tls.Config
	readNoiseMu sync.Mutex
	readNoise   map[string]readNoiseEvent
}

type readNoiseEvent struct {
	count   int
	last    time.Time
	nextLog time.Time
}

const readNoiseReportInterval = 10 * time.Minute

type session struct {
	server        *Server
	conn          net.Conn
	reader        *bufio.Reader
	writer        *bufio.Writer
	username      string
	user          auth.User
	perms         auth.PermissionSet
	authenticated bool
	cwd           string
	typ           string
	passive       net.Listener
	passivePort   int
	activeAddr    string
	renameFrom    string
	restartOffset int64
	restartSet    bool
	secure        bool
	protPrivate   bool
	statusID      int64
}

func New(cfg config.FTPConfig, store *auth.Store, root *storage.Root, activityLog *activity.Store, tracker *status.Tracker) (*Server, error) {
	ports, err := parsePorts(cfg.PassivePorts)
	if err != nil {
		return nil, err
	}
	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, errors.New("both ftp.tls_cert_file and ftp.tls_key_file are required for FTPS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	return &Server{cfg: cfg, auth: store, root: root, ports: ports, limiter: ratelimit.New(5, 10*time.Minute, 5*time.Minute), activity: activityLog, tracker: tracker, tlsConfig: tlsConfig, readNoise: make(map[string]readNoiseEvent)}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.addrMu.Lock()
	s.listener = ln
	s.localAddr = ln.Addr().String()
	s.addrMu.Unlock()
	log.Printf("ftp listening on %s", ln.Addr())
	if s.cfg.AutoMap && !listenIsLoopback(ln.Addr()) {
		ports := []int{}
		if tcp, ok := ln.Addr().(*net.TCPAddr); ok && tcp.Port > 0 {
			ports = append(ports, tcp.Port)
		}
		go natpmp.MaintainTCP(ctx, s.cfg.NATGateway, ports, s.cfg.MappingLifetime.Std(time.Hour), s.setMappedExternalIP)
		go s.maintainUPnPTCP(ctx, ports)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("ftp accept: %v", err)
			continue
		}
		go s.handle(conn)
	}
}

func listenIsLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	return tcp.IP.IsLoopback()
}

func (s *Server) Addr() string {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	if s.listener == nil {
		return s.cfg.Listen
	}
	return s.localAddr
}

func (s *Server) logReadError(addr net.Addr, err error) {
	kind, noisy := classifyReadError(err)
	if !noisy {
		log.Printf("ftp read %s: %v", addr, err)
		return
	}
	remote := remoteHost(addr)
	key := remote + "\t" + kind
	now := time.Now()
	s.readNoiseMu.Lock()
	if s.readNoise == nil {
		s.readNoise = make(map[string]readNoiseEvent)
	}
	event := s.readNoise[key]
	event.count++
	event.last = now
	if event.nextLog.IsZero() {
		event.nextLog = now.Add(readNoiseReportInterval)
	}
	if len(s.readNoise) > 1000 {
		for k, v := range s.readNoise {
			if now.Sub(v.last) > time.Hour {
				delete(s.readNoise, k)
			}
		}
	}
	if event.count == 1 {
		s.readNoise[key] = event
		s.readNoiseMu.Unlock()
		log.Printf("ftp read remote=%s error=%s", remote, kind)
		return
	}
	if !now.Before(event.nextLog) {
		suppressed := event.count - 1
		event.count = 1
		event.nextLog = now.Add(readNoiseReportInterval)
		s.readNoise[key] = event
		s.readNoiseMu.Unlock()
		log.Printf("ftp read noise remote=%s error=%s suppressed=%d window=%s", remote, kind, suppressed, readNoiseReportInterval)
		return
	}
	s.readNoise[key] = event
	s.readNoiseMu.Unlock()
}

func classifyReadError(err error) (string, bool) {
	if err == nil {
		return "", true
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, net.ErrClosed), strings.Contains(text, "use of closed network connection"):
		return "closed_connection", true
	case strings.Contains(text, "connection reset by peer"):
		return "connection_reset", true
	case errors.Is(err, os.ErrDeadlineExceeded), strings.Contains(text, "i/o timeout"):
		return "timeout", true
	default:
		return "", false
	}
}

func remoteHost(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (s *Server) handle(conn net.Conn) {
	idle := s.cfg.IdleTimeout.Std(10 * time.Minute)
	statusID := int64(0)
	if s.tracker != nil {
		statusID = s.tracker.Add("ftp", conn.RemoteAddr().String())
	}
	ss := &session{server: s, conn: conn, reader: bufio.NewReader(conn), writer: bufio.NewWriter(conn), cwd: "/", typ: "A", statusID: statusID}
	defer ss.close()
	ss.reply(220, s.cfg.Welcome)
	for {
		_ = conn.SetDeadline(time.Now().Add(idle))
		line, err := ss.reader.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logReadError(conn.RemoteAddr(), err)
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg := splitCommand(line)
		if ss.dispatch(strings.ToUpper(cmd), arg) {
			return
		}
	}
}

func (s *session) dispatch(cmd, arg string) bool {
	switch cmd {
	case "USER":
		s.username = strings.TrimSpace(arg)
		s.reply(331, "Password required")
	case "PASS":
		if s.server.cfg.RequireTLS && s.server.tlsConfig != nil && !s.secure {
			s.reply(534, "TLS required")
			return false
		}
		limitKey := s.loginLimitKey()
		if !s.server.limiter.Allow(limitKey) {
			s.logActivity("login", "limited", "", "", 0, "too many failed FTP login attempts")
			s.reply(421, "Too many failed login attempts; try again later")
			return true
		}
		user, perms, ok := s.server.auth.Authenticate(s.username, arg)
		if !ok {
			s.server.limiter.Fail(limitKey)
			s.logActivity("login", "failed", "", "", 0, "bad FTP credentials")
			s.reply(530, "Login incorrect")
			return false
		}
		s.server.limiter.Reset(limitKey)
		user.Permissions = perms
		s.user, s.perms, s.authenticated = user, perms, true
		s.cwd = user.Home
		if s.cwd == "" {
			s.cwd = "/"
		}
		_ = s.server.root.EnsureUserHome(user)
		s.updateStatus(func(st *status.Session) {
			st.User = user.Username
			st.Action = "idle"
			st.Path = s.cwd
			st.Secure = s.secure
		})
		s.logActivity("login", "ok", s.cwd, "", 0, "FTP login")
		s.reply(230, "Login successful")
	case "AUTH":
		s.authTLS(arg)
	case "PBSZ":
		if !s.secure {
			s.reply(503, "Send AUTH TLS first")
			return false
		}
		s.reply(200, "PBSZ=0")
	case "PROT":
		if !s.secure {
			s.reply(503, "Send AUTH TLS first")
			return false
		}
		switch strings.ToUpper(strings.TrimSpace(arg)) {
		case "P":
			s.protPrivate = true
			s.reply(200, "Data channel protection set to private")
		case "C":
			s.protPrivate = false
			s.reply(200, "Data channel protection set to clear")
		default:
			s.reply(536, "Unsupported protection level")
		}
	case "SYST":
		s.reply(215, "UNIX Type: L8")
	case "FEAT":
		features := []string{"UTF8", "EPSV", "PASV", "REST STREAM", "SIZE", "MDTM", "MLST type*;size*;modify*;perm*;", "MLSD"}
		if s.server.tlsConfig != nil {
			features = append(features, "AUTH TLS", "PBSZ", "PROT")
		}
		s.multiline(211, features, "End")
	case "OPTS":
		s.reply(200, "OK")
	case "PWD", "XPWD":
		if !s.requireAuth() {
			return false
		}
		s.reply(257, fmt.Sprintf("\"%s\" is current directory", s.cwd))
	case "CWD":
		if !s.requireAuthPerm(s.perms.List, "list") {
			return false
		}
		s.changeDir(arg)
	case "CDUP":
		if !s.requireAuthPerm(s.perms.List, "list") {
			return false
		}
		s.changeDir("..")
	case "TYPE":
		if strings.HasPrefix(strings.ToUpper(arg), "I") {
			s.typ = "I"
		} else {
			s.typ = "A"
		}
		s.reply(200, "Type set to "+s.typ)
	case "MODE", "STRU":
		s.reply(200, "OK")
	case "NOOP":
		s.reply(200, "OK")
	case "QUIT":
		s.reply(221, "Goodbye")
		return true
	case "PASV":
		if !s.requireAuth() {
			return false
		}
		s.enterPassive(false)
	case "EPSV":
		if !s.requireAuth() {
			return false
		}
		s.enterPassive(true)
	case "PORT":
		if !s.requireAuth() {
			return false
		}
		s.enterActive(arg)
	case "EPRT":
		if !s.requireAuth() {
			return false
		}
		s.enterExtendedActive(arg)
	case "LIST", "NLST":
		if !s.requireAuthPerm(s.perms.List, "list") {
			return false
		}
		s.list(arg, cmd == "NLST")
	case "MLSD":
		if !s.requireAuthPerm(s.perms.List, "list") {
			return false
		}
		s.mlsd(arg)
	case "MLST":
		if !s.requireAuthPerm(s.perms.List, "list") {
			return false
		}
		s.mlst(arg)
	case "RETR":
		if !s.requireAuthPerm(s.perms.Download, "download") {
			return false
		}
		s.retrieve(arg)
	case "STOR", "APPE":
		if !s.requireAuthPerm(s.perms.Upload, "upload") {
			return false
		}
		s.store(arg, cmd == "APPE")
	case "REST":
		if !s.requireAuth() {
			return false
		}
		s.restart(arg)
	case "DELE":
		if !s.requireAuthPerm(s.perms.Delete, "delete") {
			return false
		}
		s.delete(arg)
	case "MKD", "XMKD":
		if !s.requireAuthPerm(s.perms.Mkdir, "mkdir") {
			return false
		}
		s.mkdir(arg)
	case "RMD", "XRMD":
		if !s.requireAuthPerm(s.perms.Delete, "delete") {
			return false
		}
		s.rmdir(arg)
	case "RNFR":
		if !s.requireAuthPerm(s.perms.Rename, "rename") {
			return false
		}
		s.renameFromPath(arg)
	case "RNTO":
		if !s.requireAuthPerm(s.perms.Rename, "rename") {
			return false
		}
		s.renameToPath(arg)
	case "SIZE":
		if !s.requireAuthPerm(s.perms.Download, "download") {
			return false
		}
		s.size(arg)
	case "MDTM":
		if !s.requireAuthPerm(s.perms.Download, "download") {
			return false
		}
		s.mdtm(arg)
	default:
		s.reply(502, "Command not implemented")
	}
	return false
}

func (s *session) changeDir(arg string) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	info, err := s.server.root.Stat(realPath)
	if err != nil || !info.IsDir() {
		s.reply(550, "Not a directory")
		return
	}
	s.cwd = virtual
	s.updateStatus(func(st *status.Session) { st.Path = s.cwd })
	s.reply(250, "Directory changed")
}

func (s *session) authTLS(arg string) {
	if s.server.tlsConfig == nil {
		s.reply(502, "TLS not configured")
		return
	}
	if s.secure {
		s.reply(503, "TLS already active")
		return
	}
	if upper := strings.ToUpper(strings.TrimSpace(arg)); upper != "TLS" && upper != "SSL" {
		s.reply(504, "Use AUTH TLS")
		return
	}
	s.reply(234, "Starting TLS")
	tlsConn := tls.Server(s.conn, s.server.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		_ = s.conn.Close()
		return
	}
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.secure = true
	s.protPrivate = true
	s.updateStatus(func(st *status.Session) { st.Secure = true })
}

func (s *session) list(arg string, namesOnly bool) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, scrubListArg(arg))
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	info, err := s.server.root.Stat(realPath)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	conn, ok := s.beginDataTransfer()
	if !ok {
		return
	}
	defer conn.Close()
	w := bufio.NewWriter(conn)
	if info.IsDir() {
		entries, err := s.server.root.ListForUser(s.user, realPath, virtual)
		if err != nil {
			s.reply(550, "List failed")
			return
		}
		for _, entry := range entries {
			if namesOnly {
				fmt.Fprintf(w, "%s\r\n", entry.Name)
			} else {
				fmt.Fprintf(w, "%s\r\n", formatList(entry.Name, entry.Mode, entry.Size, entry.ModTime))
			}
		}
	} else if namesOnly {
		fmt.Fprintf(w, "%s\r\n", info.Name())
	} else {
		fmt.Fprintf(w, "%s\r\n", formatList(info.Name(), info.Mode().String(), info.Size(), info.ModTime()))
	}
	_ = w.Flush()
	s.reply(226, "Transfer complete")
}

func (s *session) mlsd(arg string) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, scrubListArg(arg))
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	info, err := s.server.root.Stat(realPath)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	conn, ok := s.beginDataTransfer()
	if !ok {
		return
	}
	defer conn.Close()
	w := bufio.NewWriter(conn)
	if info.IsDir() {
		entries, err := s.server.root.ListForUser(s.user, realPath, virtual)
		if err != nil {
			s.reply(550, "List failed")
			return
		}
		for _, entry := range entries {
			fmt.Fprintf(w, "%s %s\r\n", mlsxFacts(entry), entry.Name)
		}
	} else {
		fmt.Fprintf(w, "%s %s\r\n", mlsxFacts(storage.Entry{Name: info.Name(), Path: virtual, Size: info.Size(), Mode: info.Mode().String(), IsDir: info.IsDir(), ModTime: info.ModTime()}), info.Name())
	}
	_ = w.Flush()
	s.reply(226, "Transfer complete")
}

func (s *session) mlst(arg string) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	info, err := s.server.root.Stat(realPath)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	entry := storage.Entry{Name: info.Name(), Path: virtual, Size: info.Size(), Mode: info.Mode().String(), IsDir: info.IsDir(), ModTime: info.ModTime()}
	s.multiline(250, []string{fmt.Sprintf("%s %s", mlsxFacts(entry), virtual)}, "Listing")
}

func (s *session) retrieve(arg string) {
	offset, restarting := s.consumeRestart()
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.closeDataSetup()
		s.reply(550, "Path unavailable")
		return
	}
	file, err := s.server.root.Open(realPath)
	if err != nil {
		s.closeDataSetup()
		s.reply(550, "Open failed")
		return
	}
	defer file.Close()
	if restarting {
		info, err := file.Stat()
		if err != nil || info.IsDir() {
			s.closeDataSetup()
			s.reply(550, "Path unavailable")
			return
		}
		if offset > info.Size() {
			s.closeDataSetup()
			s.reply(554, "Restart offset exceeds file size")
			return
		}
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			s.closeDataSetup()
			s.reply(550, "Restart seek failed")
			return
		}
	}
	conn, ok := s.beginDataTransfer()
	if !ok {
		return
	}
	defer conn.Close()
	s.updateStatus(func(st *status.Session) {
		st.Action = "download"
		st.Path = virtual
		st.Mode = "retr"
		st.Bytes = 0
	})
	n, err := io.Copy(conn, file)
	s.updateStatus(func(st *status.Session) {
		st.Action = "idle"
		st.Bytes = n
	})
	if err != nil {
		s.logActivity("download", "failed", arg, "", n, err.Error())
		s.reply(426, "Transfer aborted")
		return
	}
	detail := "FTP download"
	if restarting {
		detail = fmt.Sprintf("FTP download resumed at offset %d", offset)
	}
	s.logActivity("download", "ok", arg, "", n, detail)
	s.reply(226, "Transfer complete")
}

func (s *session) store(arg string, appendMode bool) {
	offset, restarting := s.consumeRestart()
	if appendMode && restarting {
		s.closeDataSetup()
		s.reply(503, "REST is not valid with APPE")
		return
	}
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.closeDataSetup()
		s.reply(550, "Path unavailable")
		return
	}
	if err := s.server.root.MkdirAllParent(realPath, 0o750); err != nil {
		s.closeDataSetup()
		s.reply(550, "Cannot create directory")
		return
	}
	flag := os.O_WRONLY | os.O_CREATE
	if appendMode {
		flag |= os.O_APPEND
	} else if restarting && offset > 0 {
		flag = os.O_WRONLY
	} else {
		flag |= os.O_TRUNC
	}
	if !appendMode && !restarting {
		if info, err := s.server.root.Stat(realPath); err == nil && !info.IsDir() {
			_, _ = s.server.root.Version(realPath, virtual, s.user.Username)
		}
	}
	if restarting && offset > 0 {
		info, err := s.server.root.Stat(realPath)
		if err != nil || info.IsDir() {
			s.closeDataSetup()
			s.reply(550, "Resume target unavailable")
			return
		}
		if offset > info.Size() {
			s.closeDataSetup()
			s.reply(554, "Restart offset exceeds file size")
			return
		}
	}
	file, err := s.server.root.OpenFile(realPath, flag, 0o640)
	if err != nil {
		s.closeDataSetup()
		s.reply(550, "Open failed")
		return
	}
	defer file.Close()
	if restarting {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			s.closeDataSetup()
			s.reply(550, "Restart seek failed")
			return
		}
		if err := file.Truncate(offset); err != nil {
			s.closeDataSetup()
			s.reply(550, "Restart truncate failed")
			return
		}
	}
	conn, ok := s.beginDataTransfer()
	if !ok {
		return
	}
	defer conn.Close()
	s.updateStatus(func(st *status.Session) {
		st.Action = "upload"
		st.Path = virtual
		st.Mode = "stor"
		st.Bytes = 0
	})
	n, err := io.Copy(file, conn)
	s.updateStatus(func(st *status.Session) {
		st.Action = "idle"
		st.Bytes = n
	})
	if err != nil {
		s.logActivity("upload", "failed", arg, "", n, err.Error())
		s.reply(426, "Transfer aborted")
		return
	}
	detail := "FTP upload"
	if restarting {
		detail = fmt.Sprintf("FTP upload resumed at offset %d", offset)
	}
	s.logActivity("upload", "ok", arg, "", n, detail)
	s.reply(226, "Transfer complete")
}

func (s *session) restart(arg string) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		s.reply(501, "Restart offset required")
		return
	}
	offset, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || offset < 0 {
		s.reply(501, "Bad restart offset")
		return
	}
	s.restartOffset = offset
	s.restartSet = true
	s.reply(350, fmt.Sprintf("Restarting at %d. Send STORE or RETRIEVE to initiate transfer", offset))
}

func (s *session) consumeRestart() (int64, bool) {
	offset, ok := s.restartOffset, s.restartSet
	s.restartOffset, s.restartSet = 0, false
	return offset, ok
}

func (s *session) delete(arg string) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	if s.server.root.IsPublicReal(realPath) && !s.perms.Admin {
		s.reply(550, "Permission denied: public files are admin-managed")
		return
	}
	if isMonitorVirtual(virtual) {
		if err := s.server.root.Remove(realPath); err != nil {
			s.logActivity("delete", "failed", arg, "", 0, err.Error())
			s.reply(550, "Delete failed")
			return
		}
		s.logActivity("delete", "ok", arg, "", 0, "FTP monitor cleanup removed permanently")
		s.reply(250, "Deleted")
		return
	}
	if _, err := s.server.root.Trash(realPath, virtual, s.user.Username); err != nil {
		s.logActivity("delete", "failed", arg, "", 0, err.Error())
		s.reply(550, "Delete failed")
		return
	}
	s.logActivity("delete", "ok", arg, "", 0, "FTP delete moved to trash")
	s.reply(250, "Deleted")
}

func (s *session) mkdir(arg string) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	if err := s.server.root.MkdirAll(realPath, 0o750); err != nil {
		s.logActivity("mkdir", "failed", virtual, "", 0, err.Error())
		s.reply(550, "Create failed")
		return
	}
	s.logActivity("mkdir", "ok", virtual, "", 0, "FTP folder created")
	s.reply(257, fmt.Sprintf("\"%s\" created", virtual))
}

func (s *session) rmdir(arg string) {
	realPath, virtual, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	if s.server.root.IsPublicReal(realPath) && !s.perms.Admin {
		s.reply(550, "Permission denied: public folders are admin-managed")
		return
	}
	if isMonitorVirtual(virtual) {
		if err := s.server.root.RemoveAll(realPath); err != nil {
			s.logActivity("delete", "failed", arg, "", 0, err.Error())
			s.reply(550, "Remove failed")
			return
		}
		s.logActivity("delete", "ok", arg, "", 0, "FTP monitor folder removed permanently")
		s.reply(250, "Removed")
		return
	}
	if _, err := s.server.root.Trash(realPath, virtual, s.user.Username); err != nil {
		s.logActivity("delete", "failed", arg, "", 0, err.Error())
		s.reply(550, "Remove failed")
		return
	}
	s.logActivity("delete", "ok", arg, "", 0, "FTP folder moved to trash")
	s.reply(250, "Removed")
}

func isMonitorVirtual(virtual string) bool {
	virtual = strings.ReplaceAll(virtual, "\\", "/")
	virtual = "/" + strings.Trim(virtual, "/")
	return virtual == "/_monitor" || strings.HasPrefix(virtual, "/_monitor/")
}

func (s *session) renameFromPath(arg string) {
	realPath, _, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	if _, err := s.server.root.Stat(realPath); err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	if s.server.root.IsPublicReal(realPath) && !s.perms.Admin {
		s.reply(550, "Permission denied: public files are admin-managed")
		return
	}
	s.renameFrom = realPath
	s.reply(350, "Ready for destination")
}

func (s *session) renameToPath(arg string) {
	if s.renameFrom == "" {
		s.reply(503, "RNFR required")
		return
	}
	realPath, _, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	if s.server.root.IsPublicReal(realPath) && !s.perms.Admin {
		s.reply(550, "Permission denied: public files are admin-managed")
		return
	}
	defer func() { s.renameFrom = "" }()
	if err := s.server.root.Rename(s.renameFrom, realPath); err != nil {
		s.logActivity("move", "failed", s.renameFrom, arg, 0, err.Error())
		s.reply(550, "Rename failed")
		return
	}
	s.logActivity("move", "ok", s.renameFrom, arg, 0, "FTP rename")
	s.reply(250, "Renamed")
}

func (s *session) size(arg string) {
	realPath, _, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	info, err := s.server.root.Stat(realPath)
	if err != nil || info.IsDir() {
		s.reply(550, "Path unavailable")
		return
	}
	s.reply(213, strconv.FormatInt(info.Size(), 10))
}

func (s *session) mdtm(arg string) {
	realPath, _, err := s.server.root.Resolve(s.user, s.cwd, arg)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	info, err := s.server.root.Stat(realPath)
	if err != nil {
		s.reply(550, "Path unavailable")
		return
	}
	s.reply(213, info.ModTime().UTC().Format("20060102150405"))
}

func (s *session) enterPassive(extended bool) {
	s.closePassive()
	port, ln, err := s.server.listenPassive()
	if err != nil {
		s.reply(421, "No passive ports available")
		return
	}
	if err := s.server.mapPassivePort(port); err != nil {
		log.Printf("natpmp: passive map tcp %d failed: %v", port, err)
	}
	s.passive = ln
	s.passivePort = port
	s.activeAddr = ""
	if extended {
		s.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
		return
	}
	host := s.server.cfg.ExternalIP
	if host == "" || strings.EqualFold(host, "auto") {
		host = s.server.mappedExternalIP()
	}
	if host == "" {
		if tcp, ok := s.conn.LocalAddr().(*net.TCPAddr); ok {
			host = tcp.IP.String()
		}
	}
	if host == "" || host == "::" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		ip = net.ParseIP("127.0.0.1").To4()
	}
	s.reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip[0], ip[1], ip[2], ip[3], port/256, port%256))
}

func (s *Server) setMappedExternalIP(ip string) {
	s.externalMu.Lock()
	defer s.externalMu.Unlock()
	s.externalIP = ip
}

func (s *Server) mappedExternalIP() string {
	s.externalMu.RLock()
	defer s.externalMu.RUnlock()
	return s.externalIP
}

func (s *Server) mapPassivePort(port int) error {
	if !s.cfg.AutoMap || s.isLoopbackListener() {
		return nil
	}
	var errs []string
	mapped := false
	gateway, err := s.natGatewayAddress()
	if err != nil {
		errs = append(errs, fmt.Sprintf("natpmp gateway: %v", err))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		client := natpmp.Client{Gateway: gateway, Timeout: 1200 * time.Millisecond}
		if s.mappedExternalIP() == "" {
			if ip, err := client.PublicAddress(ctx); err == nil {
				s.setMappedExternalIP(ip.String())
			}
		}
		mapping, err := client.MapTCP(ctx, port, port, s.cfg.MappingLifetime.Std(time.Hour))
		cancel()
		if err != nil {
			errs = append(errs, fmt.Sprintf("natpmp: %v", err))
		} else if mapping.ExternalPort != port {
			errs = append(errs, fmt.Sprintf("natpmp external port %d does not match passive port %d", mapping.ExternalPort, port))
		} else {
			mapped = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := s.mapUPnPTCP(ctx, port); err != nil {
		errs = append(errs, fmt.Sprintf("upnp: %v", err))
	} else {
		mapped = true
	}
	if !mapped && len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) unmapPassivePort(port int) error {
	if port <= 0 || !s.cfg.AutoMap || s.isLoopbackListener() {
		return nil
	}
	var errs []string
	unmapped := false
	gateway, err := s.natGatewayAddress()
	if err != nil {
		errs = append(errs, fmt.Sprintf("natpmp gateway: %v", err))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		client := natpmp.Client{Gateway: gateway, Timeout: 1200 * time.Millisecond}
		if err := client.DeleteTCP(ctx, port, port); err != nil {
			errs = append(errs, fmt.Sprintf("natpmp: %v", err))
		} else {
			unmapped = true
		}
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := s.deleteUPnPTCP(ctx, port); err != nil {
		errs = append(errs, fmt.Sprintf("upnp: %v", err))
	} else {
		unmapped = true
	}
	cancel()
	if !unmapped && len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) isLoopbackListener() bool {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	if s.listener == nil {
		return true
	}
	return listenIsLoopback(s.listener.Addr())
}

func (s *Server) natGatewayAddress() (string, error) {
	if s.cfg.NATGateway != "" {
		return s.cfg.NATGateway, nil
	}
	s.natMu.Lock()
	defer s.natMu.Unlock()
	if s.natGateway != "" {
		return s.natGateway, nil
	}
	gateway, err := natpmp.DiscoverGateway()
	if err != nil {
		return "", err
	}
	s.natGateway = gateway
	return gateway, nil
}

func (s *Server) maintainUPnPTCP(ctx context.Context, ports []int) {
	lifetime := s.cfg.MappingLifetime.Std(time.Hour)
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	var lastFailureLog time.Time
	var lastFailure string
	var suppressedFailures int
	for {
		renewEvery := lifetime / 2
		if renewEvery < 5*time.Minute {
			renewEvery = 5 * time.Minute
		}
		hadFailure := false
		for _, port := range ports {
			attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := s.mapUPnPTCP(attemptCtx, port)
			cancel()
			if err != nil {
				hadFailure = true
				msg := fmt.Sprintf("upnp: map tcp %d failed: %v", port, err)
				now := time.Now()
				if msg != lastFailure || now.Sub(lastFailureLog) >= 30*time.Minute {
					if suppressedFailures > 0 {
						log.Printf("%s; suppressed %d repeated UPnP mapping failures", msg, suppressedFailures)
					} else {
						log.Print(msg)
					}
					lastFailure = msg
					lastFailureLog = now
					suppressedFailures = 0
				} else {
					suppressedFailures++
				}
			}
		}
		if hadFailure {
			renewEvery = 5 * time.Minute
		} else if len(ports) > 0 {
			if suppressedFailures > 0 {
				log.Printf("upnp: mapped %d tcp ports after suppressing %d repeated failures", len(ports), suppressedFailures)
				suppressedFailures = 0
			}
			log.Printf("upnp: mapped %d tcp ports", len(ports))
		}
		timer := time.NewTimer(renewEvery)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Server) mapUPnPTCP(ctx context.Context, port int) error {
	client, err := s.upnp()
	if err != nil {
		return err
	}
	if s.mappedExternalIP() == "" {
		if ip, err := client.PublicAddress(ctx); err == nil {
			s.setMappedExternalIP(ip.String())
		}
	}
	_, err = client.MapTCP(ctx, port, port, s.cfg.MappingLifetime.Std(time.Hour), "macftpd")
	if err != nil {
		s.clearUPnP(client)
	}
	return err
}

func (s *Server) deleteUPnPTCP(ctx context.Context, port int) error {
	client, err := s.upnp()
	if err != nil {
		return err
	}
	err = client.DeleteTCP(ctx, port)
	if err != nil {
		s.clearUPnP(client)
	}
	return err
}

func (s *Server) upnp() (*upnpigd.Client, error) {
	s.upnpMu.Lock()
	defer s.upnpMu.Unlock()
	if s.upnpClient != nil {
		return s.upnpClient, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client, err := upnpigd.Discover(ctx)
	if err != nil {
		return nil, err
	}
	log.Printf("upnp: discovered %s service %s for local %s", client.ControlURL, client.ServiceType, client.LocalIP)
	s.upnpClient = client
	return client, nil
}

func (s *Server) clearUPnP(client *upnpigd.Client) {
	s.upnpMu.Lock()
	defer s.upnpMu.Unlock()
	if s.upnpClient == client {
		s.upnpClient = nil
	}
}

func (s *Server) listenPassive() (int, net.Listener, error) {
	s.portMu.Lock()
	defer s.portMu.Unlock()
	if len(s.ports) == 0 {
		ln, err := net.Listen("tcp", ":0") // #nosec G102 -- passive FTP data sockets must be reachable on the server listen interface.
		if err != nil {
			return 0, nil, err
		}
		return ln.Addr().(*net.TCPAddr).Port, ln, nil
	}
	for i := 0; i < len(s.ports); i++ {
		idx := (s.nextPort + i) % len(s.ports)
		port := s.ports[idx]
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port)) // #nosec G102 -- configured passive FTP ports must accept external data connections.
		if err == nil {
			s.nextPort = (idx + 1) % len(s.ports)
			return port, ln, nil
		}
	}
	return 0, nil, errors.New("no free passive ports")
}

func (s *session) enterActive(arg string) {
	if !s.server.cfg.AllowActive {
		s.reply(502, "Active mode disabled")
		return
	}
	parts := strings.Split(arg, ",")
	if len(parts) != 6 {
		s.reply(501, "Bad PORT")
		return
	}
	nums := make([]int, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			s.reply(501, "Bad PORT")
			return
		}
		nums[i] = n
	}
	host := fmt.Sprintf("%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3])
	port := nums[4]*256 + nums[5]
	if !s.server.cfg.AllowFXP && !sameHost(s.conn.RemoteAddr(), host) {
		s.reply(501, "FXP active target denied")
		return
	}
	s.closePassive()
	s.activeAddr = net.JoinHostPort(host, strconv.Itoa(port))
	s.reply(200, "PORT command successful")
}

func (s *session) enterExtendedActive(arg string) {
	if !s.server.cfg.AllowActive {
		s.reply(502, "Active mode disabled")
		return
	}
	if len(arg) < 5 {
		s.reply(501, "Bad EPRT")
		return
	}
	delim := arg[0]
	parts := strings.Split(arg[1:], string(delim))
	if len(parts) < 4 {
		s.reply(501, "Bad EPRT")
		return
	}
	host, port := parts[1], parts[2]
	if !s.server.cfg.AllowFXP && !sameHost(s.conn.RemoteAddr(), host) {
		s.reply(501, "FXP active target denied")
		return
	}
	s.closePassive()
	s.activeAddr = net.JoinHostPort(host, port)
	s.reply(200, "EPRT command successful")
}

func (s *session) openData() (net.Conn, error) {
	if s.passive != nil {
		ln := s.passive
		port := s.passivePort
		s.passive = nil
		s.passivePort = 0
		defer ln.Close()
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			if port > 0 {
				s.releasePassivePort(port)
			}
			return nil, err
		}
		if port > 0 {
			return &passiveDataConn{Conn: conn, release: func() { s.releasePassivePort(port) }}, nil
		}
		return conn, nil
	}
	if s.activeAddr != "" {
		addr := s.activeAddr
		s.activeAddr = ""
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.New("no data connection")
}

func (s *session) beginDataTransfer() (net.Conn, bool) {
	conn, err := s.openData()
	if err != nil {
		s.reply(425, "Cannot open data connection")
		return nil, false
	}
	s.setDataDeadline(conn)
	s.reply(150, "Opening data connection")
	conn, err = s.protectDataConn(conn)
	if err != nil {
		_ = conn.Close()
		s.reply(425, "Cannot secure data connection")
		return nil, false
	}
	s.setDataDeadline(conn)
	return conn, true
}

func (s *session) protectDataConn(conn net.Conn) (net.Conn, error) {
	if !s.protPrivate || s.server.tlsConfig == nil {
		return conn, nil
	}
	tlsConn := tls.Server(conn, s.server.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (s *session) releasePassivePort(port int) {
	if err := s.server.unmapPassivePort(port); err != nil {
		log.Printf("natpmp: passive unmap tcp %d failed: %v", port, err)
	}
}

type passiveDataConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *passiveDataConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (s *session) setDataDeadline(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(s.server.cfg.IdleTimeout.Std(10 * time.Minute)))
}

func (s *session) requireAuth() bool {
	if !s.authenticated {
		s.reply(530, "Please login")
		return false
	}
	return true
}

func (s *session) requireAuthPerm(ok bool, name string) bool {
	if !s.requireAuth() {
		return false
	}
	if !ok {
		s.reply(550, "Permission denied: "+name)
		return false
	}
	return true
}

func (s *session) loginLimitKey() string {
	host, _, err := net.SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		host = s.conn.RemoteAddr().String()
	}
	return host + "|" + strings.ToLower(strings.TrimSpace(s.username))
}

func (s *session) logActivity(action, outcome, pathValue, destPath string, bytes int64, detail string) {
	actor := s.username
	if s.user.Username != "" {
		actor = s.user.Username
	}
	if actor == "" {
		actor = "anonymous"
	}
	s.server.activity.Add(activity.Event{
		Type:     "ftp_" + action,
		Protocol: "ftp",
		Actor:    actor,
		Remote:   s.conn.RemoteAddr().String(),
		Action:   action,
		Outcome:  outcome,
		Path:     pathValue,
		DestPath: destPath,
		Bytes:    bytes,
		Detail:   detail,
	})
}

func (s *session) updateStatus(mutate func(*status.Session)) {
	if s.server.tracker == nil || s.statusID == 0 {
		return
	}
	s.server.tracker.Update(s.statusID, mutate)
}

func (s *session) reply(code int, msg string) {
	fmt.Fprintf(s.writer, "%d %s\r\n", code, msg)
	_ = s.writer.Flush()
}

func (s *session) multiline(code int, lines []string, end string) {
	fmt.Fprintf(s.writer, "%d-%s\r\n", code, end)
	for _, line := range lines {
		fmt.Fprintf(s.writer, " %s\r\n", line)
	}
	fmt.Fprintf(s.writer, "%d %s\r\n", code, end)
	_ = s.writer.Flush()
}

func (s *session) close() {
	s.closePassive()
	if s.server.tracker != nil && s.statusID != 0 {
		s.server.tracker.Remove(s.statusID)
	}
	_ = s.conn.Close()
}

func (s *session) closePassive() {
	if s.passive != nil {
		_ = s.passive.Close()
		s.passive = nil
	}
	if s.passivePort > 0 {
		port := s.passivePort
		s.passivePort = 0
		s.releasePassivePort(port)
	}
}

func (s *session) closeDataSetup() {
	s.closePassive()
	s.activeAddr = ""
}

func splitCommand(line string) (string, string) {
	before, after, ok := strings.Cut(line, " ")
	if !ok {
		return line, ""
	}
	return before, strings.TrimSpace(after)
}

func scrubListArg(arg string) string {
	fields := strings.Fields(arg)
	for _, field := range fields {
		if !strings.HasPrefix(field, "-") {
			return field
		}
	}
	return ""
}

func formatList(name, mode string, size int64, mod time.Time) string {
	prefix := "-"
	if strings.HasPrefix(mode, "d") {
		prefix = "d"
	}
	return fmt.Sprintf("%srw-r--r-- 1 owner group %12d %s %s", prefix, size, mod.Format("Jan _2 15:04"), name)
}

func mlsxFacts(entry storage.Entry) string {
	typ := "file"
	perm := "r"
	if entry.IsDir {
		typ = "dir"
		perm = "el"
	}
	return fmt.Sprintf("type=%s;size=%d;modify=%s;perm=%s;", typ, entry.Size, entry.ModTime.UTC().Format("20060102150405"), perm)
}

func parsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			a, b, _ := strings.Cut(part, "-")
			start, err := strconv.Atoi(strings.TrimSpace(a))
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(strings.TrimSpace(b))
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("bad passive port range %q", part)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func sameHost(remote net.Addr, host string) bool {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}
	return tcp.IP.Equal(ip)
}
