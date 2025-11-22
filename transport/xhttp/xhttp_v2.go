package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/net/http2"
)

const (
	// 默认配置值（参考 Xray-core）
	defaultMaxUploadSize      = 1000000 // 1MB
	defaultMinPostInterval    = 30      // 30ms
	defaultMaxBufferedPosts   = 30
	defaultPaddingFrom        = 100
	defaultPaddingTo          = 1000
	defaultUploadBufferSize   = 65536 // 64KB
	defaultDownloadBufferSize = 65536 // 64KB
)

// xhttpConnV2 实现完整的 xhttp 连接
type xhttpConnV2 struct {
	ctx    context.Context
	cancel context.CancelFunc

	config *XhttpConfig

	// 底层连接
	underlay net.Conn
	tlsConn  net.Conn

	// HTTP/2 客户端
	h2Transport *http2.Transport
	h2Client    *http.Client

	// 数据管道
	uploadPipeReader   *io.PipeReader
	uploadPipeWriter   *io.PipeWriter
	downloadPipeReader *io.PipeReader
	downloadPipeWriter *io.PipeWriter

	// 状态管理
	readMux          sync.Mutex
	writeMux         sync.Mutex
	closed           atomic.Bool
	closeOnce        sync.Once
	downloadReady    chan struct{} // 信号：下载流已就绪
	downloadReadySet atomic.Bool   // 标记：下载流是否已就绪

	// 会话信息
	sessionID  string
	remoteAddr net.Addr
	localAddr  net.Addr

	// 统计信息
	uploadSeq     atomic.Int64
	uploadBytes   atomic.Int64
	downloadBytes atomic.Int64
}

// StreamXhttpConnV2 创建新的 xhttp 连接（完整版本）
func StreamXhttpConnV2(ctx context.Context, conn net.Conn, config *XhttpConfig) (net.Conn, error) {
	log.Infoln("[Xhttp] Initializing HTTP/2 connection (v2)")

	// 设置默认值
	if config.MaxUploadSize == 0 {
		config.MaxUploadSize = defaultMaxUploadSize
	}
	if config.MinPostInterval == 0 {
		config.MinPostInterval = defaultMinPostInterval
	}
	if config.MaxBufferedPosts == 0 {
		config.MaxBufferedPosts = defaultMaxBufferedPosts
	}
	if config.PaddingLengthMin == 0 {
		config.PaddingLengthMin = defaultPaddingFrom
	}
	if config.PaddingLengthMax == 0 {
		config.PaddingLengthMax = defaultPaddingTo
	}
	if config.Mode == "" {
		config.Mode = "packet-up" // 默认模式
	}

	xctx, cancel := context.WithCancel(ctx)

	xc := &xhttpConnV2{
		ctx:           xctx,
		cancel:        cancel,
		config:        config,
		underlay:      conn,
		sessionID:     generateUUID(),
		downloadReady: make(chan struct{}),
	}

	// 建立 TLS 连接
	if err := xc.setupTLSV2(); err != nil {
		cancel()
		return nil, fmt.Errorf("setup TLS failed: %w", err)
	}

	// 建立 HTTP/2 连接
	if err := xc.setupHTTP2V2(); err != nil {
		cancel()
		xc.tlsConn.Close()
		return nil, fmt.Errorf("setup HTTP/2 failed: %w", err)
	}

	// 创建数据管道
	xc.uploadPipeReader, xc.uploadPipeWriter = io.Pipe()
	xc.downloadPipeReader, xc.downloadPipeWriter = io.Pipe()

	// 根据模式启动相应的协程
	switch config.Mode {
	case "packet-up":
		// packet-up + stream-down（默认模式）
		go xc.packetUploadLoop()
		go xc.streamDownloadLoop()
	case "stream-up":
		// stream-up + stream-down
		go xc.streamUploadLoop()
		go xc.streamDownloadLoop()
	case "stream-one":
		// 单向流（上传和下载在同一个流中）
		go xc.streamOneLoop()
	default:
		cancel()
		return nil, fmt.Errorf("unsupported mode: %s", config.Mode)
	}

	log.Infoln("[Xhttp] HTTP/2 connection established (v2), session: %s, mode: %s", xc.sessionID, config.Mode)

	return xc, nil
}

// setupTLSV2 建立 TLS 连接
func (xc *xhttpConnV2) setupTLSV2() error {
	tlsConfig := xc.config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true,
		}
	} else {
		// 确保 ALPN 包含 h2
		if len(tlsConfig.NextProtos) == 0 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}
	}

	// 建立 TLS 连接
	tlsConn := tls.Client(xc.underlay, tlsConfig)
	if err := tlsConn.HandshakeContext(xc.ctx); err != nil {
		return fmt.Errorf("tls handshake failed: %w", err)
	}
	xc.tlsConn = tlsConn

	// 验证 ALPN
	if tlsConn, ok := xc.tlsConn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol != "h2" {
			log.Warnln("[Xhttp] ALPN negotiated protocol is not h2: %s", state.NegotiatedProtocol)
		} else {
			log.Debugln("[Xhttp] TLS handshake completed, protocol: %s", state.NegotiatedProtocol)
		}
	}

	return nil
}

// setupHTTP2V2 建立 HTTP/2 连接
func (xc *xhttpConnV2) setupHTTP2V2() error {
	// 创建 HTTP/2 Transport
	xc.h2Transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			// 返回已经建立的 TLS 连接
			return xc.tlsConn, nil
		},
		AllowHTTP: false,
	}

	// 创建 HTTP 客户端
	xc.h2Client = &http.Client{
		Transport: xc.h2Transport,
		Timeout:   0, // 不设置超时，由上层控制
	}

	return nil
}

// packetUploadLoop packet-up 模式的上传循环
func (xc *xhttpConnV2) packetUploadLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[Xhttp] Packet upload loop panic: %v", r)
		}
		xc.uploadPipeWriter.Close()
	}()

	// 等待下载流就绪（最多等待 5 秒）
	select {
	case <-xc.downloadReady:
		log.Debugln("[Xhttp] Upload loop: download stream is ready")
	case <-time.After(5 * time.Second):
		log.Warnln("[Xhttp] Upload loop: timeout waiting for download stream")
	case <-xc.ctx.Done():
		log.Debugln("[Xhttp] Upload loop: context cancelled before download ready")
		return
	}

	basePath, query := xc.getNormalizedPathAndQuery()
	buffer := make([]byte, xc.config.MaxUploadSize)
	var lastWrite time.Time

	for {
		// 读取数据
		n, err := xc.uploadPipeReader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Debugln("[Xhttp] Upload read error: %v", err)
			}
			break
		}

		if n == 0 {
			continue
		}

		seq := xc.uploadSeq.Add(1) - 1

		// 等待最小间隔
		if xc.config.MinPostInterval > 0 && seq > 0 {
			elapsed := time.Since(lastWrite)
			minInterval := time.Duration(xc.config.MinPostInterval) * time.Millisecond
			if elapsed < minInterval {
				time.Sleep(minInterval - elapsed)
			}
		}

		// 构建 URL: /path/sessionID/seq
		uploadURL := fmt.Sprintf("https://%s%s%s/%d",
			net.JoinHostPort(xc.config.Host, xc.config.Port),
			basePath,
			xc.sessionID,
			seq)

		if query != "" {
			uploadURL += "?" + query
		}

		// 创建请求
		req, err := http.NewRequestWithContext(xc.ctx, http.MethodPost, uploadURL, bytes.NewReader(buffer[:n]))
		if err != nil {
			log.Errorln("[Xhttp] Failed to create upload request: %v", err)
			break
		}

		// 设置 headers
		xc.setRequestHeaders(req, uploadURL)
		req.ContentLength = int64(n)

		if seq == 0 {
			log.Infoln("[Xhttp] Starting packet-up mode to %s", uploadURL)
		}

		lastWrite = time.Now()

		// 发送请求
		resp, err := xc.h2Client.Do(req)
		if err != nil {
			log.Errorln("[Xhttp] Upload request failed: %v", err)
			break
		}

		// 检查响应
		if resp.StatusCode != http.StatusOK {
			log.Errorln("[Xhttp] Upload response status: %s for seq %d", resp.Status, seq)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			break
		}

		// 丢弃响应体
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		xc.uploadBytes.Add(int64(n))
	}

	seq := xc.uploadSeq.Load()
	log.Debugln("[Xhttp] Packet upload loop closed after %d packets, %d bytes", seq, xc.uploadBytes.Load())
}

// streamUploadLoop stream-up 模式的上传循环
func (xc *xhttpConnV2) streamUploadLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[Xhttp] Stream upload loop panic: %v", r)
		}
	}()

	// 等待下载流就绪（最多等待 5 秒）
	select {
	case <-xc.downloadReady:
		log.Debugln("[Xhttp] Stream upload: download stream is ready")
	case <-time.After(5 * time.Second):
		log.Warnln("[Xhttp] Stream upload: timeout waiting for download stream")
	case <-xc.ctx.Done():
		log.Debugln("[Xhttp] Stream upload: context cancelled before download ready")
		return
	}

	basePath, query := xc.getNormalizedPathAndQuery()
	uploadURL := fmt.Sprintf("https://%s%s%s",
		net.JoinHostPort(xc.config.Host, xc.config.Port),
		basePath,
		xc.sessionID)

	if query != "" {
		uploadURL += "?" + query
	}

	req, err := http.NewRequestWithContext(xc.ctx, http.MethodPost, uploadURL, xc.uploadPipeReader)
	if err != nil {
		log.Errorln("[Xhttp] Failed to create stream upload request: %v", err)
		return
	}

	xc.setRequestHeaders(req, uploadURL)
	if !xc.config.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	log.Infoln("[Xhttp] Starting stream-up mode to %s", uploadURL)

	resp, err := xc.h2Client.Do(req)
	if err != nil {
		log.Errorln("[Xhttp] Stream upload request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorln("[Xhttp] Stream upload response status: %s", resp.Status)
		return
	}

	io.Copy(io.Discard, resp.Body)
	log.Debugln("[Xhttp] Stream upload closed")
}

// streamDownloadLoop stream-down 模式的下载循环
func (xc *xhttpConnV2) streamDownloadLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[Xhttp] Stream download loop panic: %v", r)
		}
		xc.downloadPipeWriter.Close()
	}()

	// 等待一小段时间，确保上传流已经建立
	time.Sleep(100 * time.Millisecond)

	basePath, query := xc.getNormalizedPathAndQuery()
	downloadURL := fmt.Sprintf("https://%s%s%s",
		net.JoinHostPort(xc.config.Host, xc.config.Port),
		basePath,
		xc.sessionID)

	if query != "" {
		downloadURL += "?" + query
	}

	req, err := http.NewRequestWithContext(xc.ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		log.Errorln("[Xhttp] Failed to create download request: %v", err)
		return
	}

	xc.setRequestHeaders(req, downloadURL)

	log.Infoln("[Xhttp] Starting stream-down mode from %s", downloadURL)

	resp, err := xc.h2Client.Do(req)
	if err != nil {
		log.Errorln("[Xhttp] Download request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorln("[Xhttp] Download response status: %s", resp.Status)
		return
	}

	log.Debugln("[Xhttp] Download stream established")

	// 通知上传循环：下载流已就绪
	if !xc.downloadReadySet.Swap(true) {
		close(xc.downloadReady)
		log.Debugln("[Xhttp] Signaled upload loop: download stream ready")
	}

	// 将响应体复制到 downloadPipeWriter
	n, err := io.Copy(xc.downloadPipeWriter, resp.Body)
	if err != nil && err != io.EOF {
		log.Debugln("[Xhttp] Download stream error: %v", err)
	}

	xc.downloadBytes.Store(n)
	log.Debugln("[Xhttp] Download stream closed, %d bytes received", n)
}

// streamOneLoop stream-one 模式（单向流）
func (xc *xhttpConnV2) streamOneLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("[Xhttp] Stream-one loop panic: %v", r)
		}
		xc.downloadPipeWriter.Close()
	}()

	basePath, query := xc.getNormalizedPathAndQuery()
	// stream-one 模式不使用 sessionID，且保留末尾斜杠（与 Xray 保持一致）
	streamOneURL := fmt.Sprintf("https://%s%s",
		net.JoinHostPort(xc.config.Host, xc.config.Port),
		basePath)

	if query != "" {
		streamOneURL += "?" + query
	}

	req, err := http.NewRequestWithContext(xc.ctx, http.MethodPost, streamOneURL, xc.uploadPipeReader)
	if err != nil {
		log.Errorln("[Xhttp] Failed to create stream-one request: %v", err)
		return
	}

	xc.setRequestHeaders(req, streamOneURL)
	if !xc.config.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}

	log.Infoln("[Xhttp] Starting stream-one mode to %s", streamOneURL)

	resp, err := xc.h2Client.Do(req)
	if err != nil {
		log.Errorln("[Xhttp] Stream-one request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorln("[Xhttp] Stream-one response status: %s", resp.Status)
		return
	}

	log.Debugln("[Xhttp] Stream-one established")

	// 将响应体复制到 downloadPipeWriter
	_, err = io.Copy(xc.downloadPipeWriter, resp.Body)
	if err != nil && err != io.EOF {
		log.Debugln("[Xhttp] Stream-one error: %v", err)
	}

	log.Debugln("[Xhttp] Stream-one closed")
}

// setRequestHeaders 设置请求头（包括 x_padding）
func (xc *xhttpConnV2) setRequestHeaders(req *http.Request, rawURL string) {
	// 生成随机 padding 长度
	paddingLen := xc.config.PaddingLengthMin +
		int32(mathrand.Int31n(xc.config.PaddingLengthMax-xc.config.PaddingLengthMin+1))

	// 设置 Referer header 包含 x_padding
	refererURL := fmt.Sprintf("%s?x_padding=%s", rawURL, strings.Repeat("X", int(paddingLen)))
	req.Header.Set("Referer", refererURL)

	// 添加用户自定义 headers
	for key, values := range xc.config.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 如果配置了 Host header，强制设置 req.Host
	// 这对于某些严格检查 Host 的服务器/CDN 是必须的
	if host := xc.config.Headers.Get("Host"); host != "" {
		req.Host = host
	}
}

// getNormalizedPathAndQuery 规范化路径并分离查询参数
func (xc *xhttpConnV2) getNormalizedPathAndQuery() (string, string) {
	path := xc.config.Path
	query := ""

	if strings.Contains(path, "?") {
		parts := strings.SplitN(path, "?", 2)
		path = parts[0]
		query = parts[1]
	}

	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	if path[len(path)-1] != '/' {
		path = path + "/"
	}
	return path, query
}

// Read 实现 net.Conn 接口
func (xc *xhttpConnV2) Read(b []byte) (n int, err error) {
	if xc.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return xc.downloadPipeReader.Read(b)
}

// Write 实现 net.Conn 接口
func (xc *xhttpConnV2) Write(b []byte) (n int, err error) {
	if xc.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return xc.uploadPipeWriter.Write(b)
}

// Close 实现 net.Conn 接口
func (xc *xhttpConnV2) Close() error {
	var err error
	xc.closeOnce.Do(func() {
		xc.closed.Store(true)
		xc.cancel()

		// 关闭管道
		if xc.uploadPipeWriter != nil {
			xc.uploadPipeWriter.Close()
		}
		if xc.downloadPipeWriter != nil {
			xc.downloadPipeWriter.Close()
		}

		// 关闭 HTTP/2 transport
		if xc.h2Transport != nil {
			xc.h2Transport.CloseIdleConnections()
		}

		// 关闭底层连接
		if xc.tlsConn != nil {
			err = xc.tlsConn.Close()
		}
		if xc.underlay != nil {
			xc.underlay.Close()
		}

		log.Debugln("[Xhttp] Connection closed")
	})
	return err
}

// LocalAddr 实现 net.Conn 接口
func (xc *xhttpConnV2) LocalAddr() net.Addr {
	if xc.localAddr != nil {
		return xc.localAddr
	}
	if xc.underlay != nil {
		return xc.underlay.LocalAddr()
	}
	return nil
}

// RemoteAddr 实现 net.Conn 接口
func (xc *xhttpConnV2) RemoteAddr() net.Addr {
	if xc.remoteAddr != nil {
		return xc.remoteAddr
	}
	if xc.underlay != nil {
		return xc.underlay.RemoteAddr()
	}
	return nil
}

// SetDeadline 实现 net.Conn 接口
func (xc *xhttpConnV2) SetDeadline(t time.Time) error {
	// HTTP/2 不支持 deadline
	return nil
}

// SetReadDeadline 实现 net.Conn 接口
func (xc *xhttpConnV2) SetReadDeadline(t time.Time) error {
	// HTTP/2 不支持 deadline
	return nil
}

// SetWriteDeadline 实现 net.Conn 接口
func (xc *xhttpConnV2) SetWriteDeadline(t time.Time) error {
	// HTTP/2 不支持 deadline
	return nil
}

// generateUUID 生成 UUID v4
func generateUUID() string {
	b := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		// 如果随机数生成失败，使用时间戳作为后备
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	// 设置 UUID 版本 (4) 和变体
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
