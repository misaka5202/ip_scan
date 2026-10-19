// Package main 实现代理扫描与弱口令爆破工具。
//
// 支持 SOCKS5 / HTTP / HTTPS 代理，通过 iplocate.io 获取出口与入口 IP 的地理信息，
// 并可加载密码本对需要认证的代理进行弱口令检测。扫描结果可导出为 CSV。
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// ipLocateBaseURL 是 iplocate.io 的查询接口。
	//   - 查询代理出口自身：https://www.iplocate.io/api/lookup
	//   - 查询指定 IP：    https://www.iplocate.io/api/lookup/{ip}
	ipLocateBaseURL = "https://www.iplocate.io/api/lookup/"
)

var (
	file       = flag.String("f", "", "待爆破的代理列表文件 (必需), 格式: IP:端口 或 IP 端口")
	passFile   = flag.String("p", "", "密码本文件, 格式: 用户名:密码 (可选)")
	outFile    = flag.String("o", "", "输出CSV文件名 (可选)")
	maxThreads = flag.Int("m", 50, "最大并发任务数（每个任务为一个代理/一组凭据）")
	timeoutSec = flag.Int("s", 3, "超时时间（秒），超过该时间丢弃")
	debug      = flag.Bool("debug", false, "开启调试日志")
	proxyType  = flag.String("t", "", "代理协议类型: socks5, http 或 https (必需)")
	skipVerify = flag.Bool("skip-verify", true, "跳过HTTPS代理的证书验证 (默认 true)")
)

// ErrProxyAuthRequired 表示代理要求认证（HTTP 407）。
var ErrProxyAuthRequired = errors.New("proxy requires authentication")

// ErrInvalidAuth 表示代理认证失败（HTTP 401/403 等）。
var ErrInvalidAuth = errors.New("invalid username/password")

// IPInfo 保存 iplocate.io /api/lookup 返回的字段。
// 兼容原有字段（IP、Country、City、ISP、Hosting、Tag），并补充 ASN / company / privacy 等明细。
type IPInfo struct {
	IP          string
	Country     string
	CountryCode string
	City        string
	Continent   string
	Subdivision string
	Timezone    string
	PostalCode  string
	Latitude    float64
	Longitude   float64

	// ISP 主要用于输出展示（优先取 ASN 名称，回退 company.name）
	ISP string

	// ASN 明细（对应 iplocate 响应的 asn.* 字段）
	ASN       string
	ASNName   string
	ASNRoute  string
	ASNDomain string
	ASNType   string
	RIR       string

	// company 明细
	CompanyName    string
	CompanyType    string
	CompanyNetwork string

	// privacy 明细
	Hosting      bool // 与 worker 一致：取自 privacy.is_hosting
	IsDatacenter bool
	IsBogon      bool
	IsProxy      bool
	IsVPN        bool
	IsTor        bool
	IsAbuser     bool
	IsCrawler    bool
	IsSatellite  bool

	Tag string
}

// ProxyResult 保存单个代理的最终扫描结果。
type ProxyResult struct {
	IP           string // 代理入口 IP
	Port         int    // 代理端口
	Username     string // 成功认证的用户名（空认证时为空）
	Password     string // 成功认证的密码（空认证时为空）
	Success      bool
	OutboundIP   string // 出口 IP
	OutInfo      string // 出口展示信息，格式：地区_城市[ISP]
	OutTag       string // CSV 类型标记：家宽 / 商宽
	InInfo       string // 入口展示信息
	ErrorMsg     string
	ResponseTime int64  // 出口/入口信息采集耗时（毫秒）
	Protocol     string // socks5 / http / https
}

// Credential 表示一组用户名/密码凭据。
type Credential struct {
	Username string
	Password string
}

// ProgressTracker 负责并发安全地统计扫描进度并渲染进度条。
type ProgressTracker struct {
	total     int64
	completed int64
	success   int64
	mu        sync.Mutex
	startTime time.Time
}

// NewProgressTracker 创建进度跟踪器。
func NewProgressTracker(total int64) *ProgressTracker {
	return &ProgressTracker{
		total:     total,
		completed: 0,
		success:   0,
		startTime: time.Now(),
	}
}

// Add 累加完成数与成功数，并刷新进度条。
func (p *ProgressTracker) Add(completedDelta, successDelta int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.completed += completedDelta
	p.success += successDelta
	p.render()
}

// render 渲染单行进度条（需在锁内调用）。
func (p *ProgressTracker) render() {
	percent := float64(p.completed) / float64(p.total) * 100
	elapsed := time.Since(p.startTime).Seconds()
	rate := float64(p.completed) / elapsed
	barWidth := 40
	filled := int(percent / 100 * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\rProxy Scan | [%s] %5.1f%% | %d/%d, Alive=%d, %.0f/s",
		bar, percent, p.completed, p.total, p.success, rate)
}

// Finish 输出最终进度并换行。
func (p *ProgressTracker) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.render()
	fmt.Println()
}

// debugPrintf 仅在 -debug 开启时输出调试日志。
func debugPrintf(format string, v ...interface{}) {
	if *debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// getIPTypeTags 根据 hosting 标记返回 CSV 标签和控制台标签。
func getIPTypeTags(hosting bool) (csvTag string, screenTag string) {
	if hosting {
		return "商宽", "🟥商宽"
	}
	return "家宽", "✅家宽"
}

// doFetchViaProxy 通过代理请求 iplocate.io/api/lookup 获取 IP 信息。
// queryIP 为空时，查询代理出口自身的 IP 信息（对应 /api/lookup）；
// queryIP 不为空时，查询指定 IP 的信息（对应 /api/lookup/{ip}），常用于查询入口（代理本身）IP 的信息。
//
// 字段映射：
//   - Hosting <- privacy.is_hosting
//   - ISP     <- asn.name（回退 company.name）
//   - is_bogon / is_proxy / is_vpn / is_tor / is_abuser <- privacy.*
func doFetchViaProxy(client *http.Client, queryIP string) (*IPInfo, error) {
	urlStr := ipLocateBaseURL
	if queryIP != "" {
		urlStr += queryIP
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		// 确保连接可复用，同时释放响应体。
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// 根据 HTTP 状态码区分认证相关错误，便于爆破阶段快速判断。
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, ErrProxyAuthRequired
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrInvalidAuth
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}

	// 使用匿名结构体承接 iplocate.io 响应，仅提取需要的字段。
	var data struct {
		IP          string  `json:"ip"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		City        string  `json:"city"`
		Continent   string  `json:"continent"`
		Subdivision string  `json:"subdivision"`
		Timezone    string  `json:"time_zone"`
		PostalCode  string  `json:"postal_code"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		ASN         struct {
			ASN    string `json:"asn"`
			Name   string `json:"name"`
			Route  string `json:"route"`
			Domain string `json:"domain"`
			Type   string `json:"type"`
			RIR    string `json:"rir"`
		} `json:"asn"`
		Company struct {
			Name        string `json:"name"`
			Domain      string `json:"domain"`
			Type        string `json:"type"`
			Network     string `json:"network"`
			AbuserScore string `json:"abuser_score"`
		} `json:"company"`
		Privacy struct {
			IsAbuser     bool `json:"is_abuser"`
			IsBogon      bool `json:"is_bogon"`
			IsCrawler    bool `json:"is_crawler"`
			IsDatacenter bool `json:"is_datacenter"`
			IsHosting    bool `json:"is_hosting"`
			IsICANN      bool `json:"is_icann"`
			IsProxy      bool `json:"is_proxy"`
			IsSatellite  bool `json:"is_satellite"`
			IsTor        bool `json:"is_tor"`
			IsVPN        bool `json:"is_vpn"`
		} `json:"privacy"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	if data.Error != "" {
		return nil, fmt.Errorf("iplocate错误: %s", data.Error)
	}
	if data.Message != "" && data.IP == "" {
		return nil, fmt.Errorf("iplocate错误: %s", data.Message)
	}
	if data.IP == "" {
		return nil, fmt.Errorf("iplocate返回无效数据")
	}

	// ISP：优先 ASN 名称，其次 company 名称。
	isp := strings.TrimSpace(data.ASN.Name)
	if isp == "" {
		isp = strings.TrimSpace(data.Company.Name)
	}
	if isp == "" {
		isp = "未知ISP"
	}

	// Hosting 判定使用 privacy.is_hosting。
	hosting := data.Privacy.IsHosting

	info := &IPInfo{
		IP:             data.IP,
		Country:        data.Country,
		CountryCode:    data.CountryCode,
		City:           data.City,
		Continent:      data.Continent,
		Subdivision:    data.Subdivision,
		Timezone:       data.Timezone,
		PostalCode:     data.PostalCode,
		Latitude:       data.Latitude,
		Longitude:      data.Longitude,
		ISP:            isp,
		ASN:            data.ASN.ASN,
		ASNName:        data.ASN.Name,
		ASNRoute:       data.ASN.Route,
		ASNDomain:      data.ASN.Domain,
		ASNType:        data.ASN.Type,
		RIR:            data.ASN.RIR,
		CompanyName:    data.Company.Name,
		CompanyType:    data.Company.Type,
		CompanyNetwork: data.Company.Network,
		Hosting:        hosting,
		IsDatacenter:   data.Privacy.IsDatacenter || data.Privacy.IsHosting,
		IsBogon:        data.Privacy.IsBogon,
		IsProxy:        data.Privacy.IsProxy,
		IsVPN:          data.Privacy.IsVPN,
		IsTor:          data.Privacy.IsTor,
		IsAbuser:       data.Privacy.IsAbuser,
		IsCrawler:      data.Privacy.IsCrawler,
		IsSatellite:    data.Privacy.IsSatellite,
	}
	_, info.Tag = getIPTypeTags(info.Hosting)
	return info, nil
}

// createProxyClient 根据协议类型创建带认证信息的 HTTP 客户端。
func createProxyClient(proxyAddr, username, password, proxyType string, timeout time.Duration, skipVerify bool) (*http.Client, error) {
	switch proxyType {
	case "socks5":
		auth := proxy.Auth{User: username, Password: password}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, &auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("创建SOCKS5 dialer失败: %v", err)
		}
		transport := &http.Transport{Dial: dialer.Dial}
		return &http.Client{Transport: transport, Timeout: timeout}, nil
	case "http":
		var proxyURL *url.URL
		if username != "" || password != "" {
			proxyURL = &url.URL{
				Scheme: "http",
				Host:   proxyAddr,
				User:   url.UserPassword(username, password),
			}
		} else {
			proxyURL = &url.URL{Scheme: "http", Host: proxyAddr}
		}
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		return &http.Client{Transport: transport, Timeout: timeout}, nil
	case "https":
		var proxyURL *url.URL
		if username != "" || password != "" {
			proxyURL = &url.URL{
				Scheme: "https",
				Host:   proxyAddr,
				User:   url.UserPassword(username, password),
			}
		} else {
			proxyURL = &url.URL{Scheme: "https", Host: proxyAddr}
		}
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		}
		return &http.Client{Transport: transport, Timeout: timeout}, nil
	default:
		return nil, fmt.Errorf("不支持的代理类型: %s", proxyType)
	}
}

// fetchProxyInfo 通过代理获取出口信息和入口信息。
// 返回的 elapsed 为整个信息采集过程的耗时；入口查询失败时不会返回错误，而是使用“未知”占位。
func fetchProxyInfo(client *http.Client, entryIP string) (exitInfo *IPInfo, entryInfo *IPInfo, elapsed time.Duration, err error) {
	start := time.Now()
	defer func() {
		elapsed = time.Since(start)
	}()

	exitInfo, err = doFetchViaProxy(client, "")
	if err != nil {
		return nil, nil, 0, err
	}
	debugPrintf("出口信息获取成功 IP=%s, 类型=%s", exitInfo.IP, exitInfo.Tag)

	if entryIP != "" {
		entryInfo, err = doFetchViaProxy(client, entryIP)
		if err != nil {
			debugPrintf("获取入口信息失败: %v", err)
			entryInfo = &IPInfo{Country: "未知", City: "", ISP: ""}
		} else {
			debugPrintf("入口信息获取成功 IP=%s", entryInfo.IP)
		}
	} else {
		entryInfo = &IPInfo{Country: "未知", City: "", ISP: ""}
	}

	return exitInfo, entryInfo, elapsed, nil
}

// readProxyList 从文件读取代理列表，支持 `IP:端口` 和 `IP 端口` 两种格式。
func readProxyList(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var ip, portStr string
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			ip, portStr = parts[0], parts[1]
		} else {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			ip, portStr = fields[0], fields[1]
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		proxies = append(proxies, fmt.Sprintf("%s:%d", ip, port))
	}
	return proxies, scanner.Err()
}

// readPasswords 从密码本读取凭据。
// 若未提供密码本，则返回一个空凭据（用于空认证测试）。
func readPasswords(filePath string) ([]Credential, error) {
	if filePath == "" {
		debugPrintf("未提供密码本，将仅使用无认证（空用户名密码）")
		return []Credential{{"", ""}}, nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开密码本文件失败: %v", err)
	}
	defer f.Close()
	var creds []Credential
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		creds = append(creds, Credential{Username: parts[0], Password: parts[1]})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取密码本文件出错: %v", err)
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("密码本文件中没有找到任何有效的 \"用户名:密码\" 格式行")
	}
	// 去重，避免重复尝试相同凭据。
	unique := make(map[string]bool)
	var result []Credential
	for _, cred := range creds {
		key := cred.Username + ":" + cred.Password
		if !unique[key] {
			unique[key] = true
			result = append(result, cred)
		}
	}
	debugPrintf("从密码本加载了 %d 组凭据", len(result))
	return result, nil
}

// formatOutInfo 格式化出口展示信息，格式：地区_城市[ISP]。
func formatOutInfo(info *IPInfo) string {
	var parts []string
	if info.Country != "" {
		parts = append(parts, info.Country)
	}
	if info.City != "" && info.City != info.Country {
		parts = append(parts, info.City)
	}
	isp := info.ISP
	if isp == "" || isp == "Unknown ISP" {
		isp = "未知ISP"
	}
	if len(parts) == 1 {
		return parts[0] + "[" + isp + "]"
	} else if len(parts) >= 2 {
		return parts[0] + "_" + parts[1] + "[" + isp + "]"
	}
	return "未知地区[" + isp + "]"
}

// formatInInfo 格式化入口展示信息，格式：地区_城市[ISP] 或 地区_城市。
func formatInInfo(info *IPInfo) string {
	var parts []string
	if info.Country != "" {
		parts = append(parts, info.Country)
	}
	if info.City != "" && info.City != info.Country {
		parts = append(parts, info.City)
	}
	if len(parts) == 1 {
		if info.ISP != "" && info.ISP != "Unknown ISP" {
			return parts[0] + "[" + info.ISP + "]"
		}
		return parts[0]
	} else if len(parts) >= 2 {
		if info.ISP != "" && info.ISP != "Unknown ISP" {
			return parts[0] + "_" + parts[1] + "[" + info.ISP + "]"
		}
		return parts[0] + "_" + parts[1]
	}
	return "未知地区"
}

// parseLocationCityASN 解析 formatOutInfo / formatInInfo 生成的字符串。
// 返回 region、city、asn 三部分；若字段缺失则返回空字符串。
func parseLocationCityASN(info string) (region, city, asn string) {
	lastBracket := strings.LastIndex(info, "[")
	if lastBracket != -1 && strings.HasSuffix(info, "]") {
		asn = info[lastBracket+1 : len(info)-1]
		info = info[:lastBracket]
	} else {
		asn = ""
	}
	if strings.Contains(info, "_") {
		parts := strings.SplitN(info, "_", 2)
		region = parts[0]
		if len(parts) > 1 {
			city = parts[1]
		} else {
			city = ""
		}
	} else {
		region = info
		city = ""
	}
	return region, city, asn
}

// increaseMaxOpenFiles 尝试在 Linux 下提升文件描述符上限。
//
// 注意：该命令通过 `bash -c` 在子 shell 中执行，ulimit 的修改不会影响当前进程。
// 若需真正提升并发能力，建议在启动程序前于 shell 中执行：
//
//	ulimit -n 10000
func increaseMaxOpenFiles() {
	if runtime.GOOS == "linux" {
		fmt.Println("正在尝试提升文件描述符的上限...")
		cmd := exec.Command("bash", "-c", "ulimit -n 10000")
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
		} else {
			fmt.Printf("文件描述符上限已提升!\n")
		}
	}
}

// quoteCSV 对 CSV 字段进行引号包裹和转义。
func quoteCSV(s string) string {
	if !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// writeResultsToCSV 将成功结果写入 CSV 文件（带 UTF-8 BOM，便于 Excel 打开）。
func writeResultsToCSV(results []ProxyResult, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("\xEF\xBB\xBF")

	headers := []string{
		"协议", "节点", "类型", "出口IP", "出口地区", "出口城市", "出口ASN",
		"入口地区", "入口城市", "入口ASN", "出入口是否一致", "响应时间(ms)",
	}
	headerLine := strings.Join(headers, ",")
	if _, err := f.WriteString(headerLine + "\n"); err != nil {
		return err
	}

	for _, r := range results {
		if !r.Success {
			continue
		}
		outRegion, outCity, outASN := parseLocationCityASN(r.OutInfo)

		// 构造节点字符串：协议://[用户名:密码@]IP:端口#地区_城市[ASN]
		var node string
		protocolPrefix := r.Protocol + "://"
		var addrPart string
		if r.Username != "" || r.Password != "" {
			addrPart = fmt.Sprintf("%s:%s@%s:%d", r.Username, r.Password, r.IP, r.Port)
		} else {
			addrPart = fmt.Sprintf("%s:%d", r.IP, r.Port)
		}
		if outCity != "" && outASN != "" {
			node = fmt.Sprintf("%s%s#%s_%s[%s]", protocolPrefix, addrPart, outRegion, outCity, outASN)
		} else if outCity != "" && outASN == "" {
			node = fmt.Sprintf("%s%s#%s_%s", protocolPrefix, addrPart, outRegion, outCity)
		} else if outCity == "" && outASN != "" {
			node = fmt.Sprintf("%s%s#%s[%s]", protocolPrefix, addrPart, outRegion, outASN)
		} else {
			node = fmt.Sprintf("%s%s#%s", protocolPrefix, addrPart, outRegion)
		}

		nodeType := r.OutTag
		exitIP := r.OutboundIP
		outRegionVal := outRegion
		outCityVal := outCity
		outASNVal := outASN

		inRegion, inCity, inASN := parseLocationCityASN(r.InInfo)

		sameIP := "FALSE"
		if r.IP == r.OutboundIP {
			sameIP = "TRUE"
		}

		respTimeMs := r.ResponseTime

		row := strings.Join([]string{
			quoteCSV(r.Protocol),
			quoteCSV(node),
			nodeType,
			exitIP,
			quoteCSV(outRegionVal),
			quoteCSV(outCityVal),
			quoteCSV(outASNVal),
			quoteCSV(inRegion),
			quoteCSV(inCity),
			quoteCSV(inASN),
			sameIP,
			strconv.FormatInt(respTimeMs, 10),
		}, ",")
		if _, err := f.WriteString(row + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// isAuthError 判断错误是否与代理认证相关。
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrProxyAuthRequired) || errors.Is(err, ErrInvalidAuth) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "invalid username/password") ||
		strings.Contains(errStr, "authentication failed") ||
		strings.Contains(errStr, "Authentication failed") ||
		strings.Contains(errStr, "User authentication failed") ||
		strings.Contains(errStr, "407") ||
		strings.Contains(errStr, "Proxy Authentication Required")
}

// main 解析参数、加载代理与密码本、并发扫描并输出结果。
func main() {
	flag.Parse()
	if *file == "" {
		fmt.Println("错误: 必须指定 -f 和 -t 参数")
		flag.Usage()
		os.Exit(1)
	}
	if *proxyType != "socks5" && *proxyType != "http" && *proxyType != "https" {
		fmt.Println("错误: -t 参数必须是 socks5, http 或 https")
		flag.Usage()
		os.Exit(1)
	}
	globalTimeout := time.Duration(*timeoutSec) * time.Second

	increaseMaxOpenFiles()

	proxies, err := readProxyList(*file)
	if err != nil {
		fmt.Printf("读取代理列表失败: %v\n", err)
		os.Exit(1)
	}
	if len(proxies) == 0 {
		fmt.Println("没有找到有效的代理地址")
		os.Exit(1)
	}
	debugPrintf("读取到 %d 个代理地址", len(proxies))

	credentials, err := readPasswords(*passFile)
	if err != nil {
		fmt.Printf("读取密码本失败: %v\n", err)
		os.Exit(1)
	}
	// 判断是否提供了有效密码本（非仅空认证占位）。
	hasValidPasswordBook := len(credentials) > 0 && !(len(credentials) == 1 && credentials[0].Username == "" && credentials[0].Password == "")

	fmt.Printf("开始扫描代理 (共 %d 个，类型: %s)，密码本数量: %d，跳过证书验证: %v\n",
		len(proxies), *proxyType, len(credentials), *skipVerify)
	progress := NewProgressTracker(int64(len(proxies)))

	var mu sync.Mutex
	var allResults []ProxyResult

	type task struct {
		proxyAddr string
	}
	taskChan := make(chan task, len(proxies))
	for _, p := range proxies {
		taskChan <- task{proxyAddr: p}
	}
	close(taskChan)

	workerCount := *maxThreads
	if workerCount > len(proxies) {
		workerCount = len(proxies)
	}
	debugPrintf("使用 %d 个并发 worker", workerCount)

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for t := range taskChan {
				proxyAddr := t.proxyAddr
				debugPrintf("[Worker %d] 开始处理代理 %s (%s)", workerID, proxyAddr, *proxyType)

				ipPort := strings.SplitN(proxyAddr, ":", 2)
				entryIP := ipPort[0]
				port, _ := strconv.Atoi(ipPort[1])

				// 第一步：尝试无认证连接。
				client, err := createProxyClient(proxyAddr, "", "", *proxyType, globalTimeout, *skipVerify)
				if err == nil {
					exitInfo, entryInfo, elapsed, err := fetchProxyInfo(client, entryIP)
					client.CloseIdleConnections()
					if err == nil {
						debugPrintf("[Worker %d] 代理 %s 空认证成功", workerID, proxyAddr)
						csvTag, screenTag := getIPTypeTags(exitInfo.Hosting)
						outInfo := formatOutInfo(exitInfo)
						inInfo := formatInInfo(entryInfo)

						fmt.Printf("\r\033[K%s %-22s %-4s %-24s %s\n",
							screenTag,
							fmt.Sprintf("%s:%d", entryIP, port),
							strings.ToUpper(*proxyType),
							"NO_AUTH",
							outInfo)
						res := ProxyResult{
							IP:           entryIP,
							Port:         port,
							Username:     "",
							Password:     "",
							Success:      true,
							OutboundIP:   exitInfo.IP,
							OutInfo:      outInfo,
							OutTag:       csvTag,
							InInfo:       inInfo,
							ResponseTime: elapsed.Milliseconds(),
							Protocol:     *proxyType,
						}
						mu.Lock()
						allResults = append(allResults, res)
						mu.Unlock()
						progress.Add(1, 1)
						continue
					}
					debugPrintf("[Worker %d] 代理 %s 无认证失败: %v", workerID, proxyAddr, err)
				} else {
					debugPrintf("[Worker %d] 创建无认证客户端失败: %v", workerID, err)
				}

				// 需要认证但没有有效密码本则跳过。
				if !hasValidPasswordBook {
					debugPrintf("[Worker %d] 代理 %s 需要认证但无有效密码本，跳过", workerID, proxyAddr)
					progress.Add(1, 0)
					continue
				}

				// 第二步：爆破凭据。每个凭据仅请求出口接口进行轻量验证。
				var successCred *Credential
				for idx, cred := range credentials {
					debugPrintf("[Worker %d] 代理 %s 测试第 %d 个凭据: %s:%s", workerID, proxyAddr, idx+1, cred.Username, cred.Password)
					testClient, err := createProxyClient(proxyAddr, cred.Username, cred.Password, *proxyType, globalTimeout, *skipVerify)
					if err != nil {
						debugPrintf("[Worker %d] 创建客户端失败: %v", workerID, err)
						continue
					}
					_, err = doFetchViaProxy(testClient, "")
					testClient.CloseIdleConnections()
					if err == nil {
						successCred = &cred
						debugPrintf("[Worker %d] 代理 %s 爆破成功！凭据: %s:%s", workerID, proxyAddr, cred.Username, cred.Password)
						break
					} else {
						debugPrintf("[Worker %d] 凭据 %s:%s 失败: %v", workerID, cred.Username, cred.Password, err)
					}
				}

				if successCred == nil {
					debugPrintf("[Worker %d] 代理 %s 所有凭据尝试失败", workerID, proxyAddr)
					progress.Add(1, 0)
					continue
				}

				// 第三步：使用成功凭据重新创建客户端，完整采集出口和入口信息。
				finalClient, err := createProxyClient(proxyAddr, successCred.Username, successCred.Password, *proxyType, globalTimeout, *skipVerify)
				if err != nil {
					debugPrintf("[Worker %d] 创建最终客户端失败: %v", workerID, err)
					progress.Add(1, 0)
					continue
				}
				exitInfo, entryInfo, elapsed, err := fetchProxyInfo(finalClient, entryIP)
				finalClient.CloseIdleConnections()
				if err != nil {
					debugPrintf("[Worker %d] 获取完整代理信息失败: %v", workerID, err)
					progress.Add(1, 0)
					continue
				}

				csvTag, screenTag := getIPTypeTags(exitInfo.Hosting)
				outInfo := formatOutInfo(exitInfo)
				inInfo := formatInInfo(entryInfo)

				fmt.Printf("\r\033[K%s %-22s %-4s %-24s %s\n",
					screenTag,
					fmt.Sprintf("%s:%d", entryIP, port),
					strings.ToUpper(*proxyType),
					fmt.Sprintf("WEAK(%s:%s)", successCred.Username, successCred.Password),
					outInfo)
				res := ProxyResult{
					IP:           entryIP,
					Port:         port,
					Username:     successCred.Username,
					Password:     successCred.Password,
					Success:      true,
					OutboundIP:   exitInfo.IP,
					OutInfo:      outInfo,
					OutTag:       csvTag,
					InInfo:       inInfo,
					ResponseTime: elapsed.Milliseconds(),
					Protocol:     *proxyType,
				}
				mu.Lock()
				allResults = append(allResults, res)
				mu.Unlock()
				progress.Add(1, 1)
			}
			debugPrintf("[Worker %d] worker 结束", workerID)
		}(i)
	}

	wg.Wait()
	progress.Finish()

	if len(allResults) > 0 {
		outputPath := *outFile
		if outputPath == "" {
			outputPath = fmt.Sprintf("%s_scan_%s.csv", *proxyType, time.Now().Format("20060102_150405"))
		}
		if err := writeResultsToCSV(allResults, outputPath); err != nil {
			fmt.Printf("写入CSV文件失败: %v\n", err)
			os.Exit(1)
		}
		successCount := len(allResults)
		fmt.Printf("探测完成！成功: %d/%d, 结果已保存到: %s\n", successCount, len(proxies), outputPath)
	} else {
		fmt.Printf("探测完成！成功: 0/%d, 没有找到有效代理，不生成CSV文件。\n", len(proxies))
	}
}