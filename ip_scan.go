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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	ipCheckURL    = "https://api.ipapi.is/"
	cnGeoJSONPURL = "https://ipv4.ping0.cc/geo/jsonp/callback"
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
	cnMode     = flag.Bool("cn", false, "使用中文地理信息 (ping0.cc)，出口显示中文，入口保持英文")
)

var ErrProxyAuthRequired = errors.New("proxy requires authentication")
var ErrInvalidAuth = errors.New("invalid username/password")

type IPInfo struct {
	IP          string
	Country     string
	City        string
	ISP         string
	ASNType     string
	CompanyType string
	Tag         string
}

type ProxyResult struct {
	IP           string
	Port         int
	Username     string
	Password     string
	Success      bool
	OutboundIP   string
	OutInfo      string
	OutTag       string
	InInfo       string
	ErrorMsg     string
	ResponseTime int64
	Protocol     string
}

type Credential struct {
	Username string
	Password string
}

type ProgressTracker struct {
	total     int64
	completed int64
	success   int64
	mu        sync.Mutex
	startTime time.Time
}

func NewProgressTracker(total int64) *ProgressTracker {
	return &ProgressTracker{
		total:     total,
		completed: 0,
		success:   0,
		startTime: time.Now(),
	}
}

func (p *ProgressTracker) Add(completedDelta, successDelta int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.completed += completedDelta
	p.success += successDelta
	p.render()
}

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

func (p *ProgressTracker) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.render()
	fmt.Println()
}

func debugPrintf(format string, v ...interface{}) {
	if *debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func getIPTypeTags(companyType, asnType string) (csvTag string, screenTag string) {
	if companyType == "isp" && asnType == "isp" {
		return "家宽", "✅家宽"
	}
	switch companyType {
	case "education":
		return "教育", "🎓教育"
	case "government":
		return "政府", "🏛政府"
	case "banking":
		return "金融", "💰金融"
	case "business":
		return "企业", "🏢企业"
	case "hosting":
		return "机房", "🟥机房"
	}
	switch asnType {
	case "education":
		return "教育", "🎓教育"
	case "government":
		return "政府", "🏛政府"
	case "banking":
		return "金融", "💰金融"
	case "business":
		return "企业", "🏢企业"
	case "hosting":
		return "机房", "🟥机房"
	}
	return "机房", "🟥机房"
}

func doFetchViaProxy(client *http.Client, queryIP string) (*IPInfo, error) {
	urlStr := ipCheckURL
	if queryIP != "" {
		urlStr = fmt.Sprintf("%s?q=%s", ipCheckURL, queryIP)
	}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxy-scanner/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, ErrProxyAuthRequired
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrInvalidAuth
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	info := &IPInfo{}
	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if loc, ok := data["location"].(map[string]interface{}); ok {
		if c, ok := loc["country"].(string); ok {
			info.Country = c
		}
		if ci, ok := loc["city"].(string); ok {
			info.City = ci
		}
		if info.City == "" {
			if state, ok := loc["state"].(string); ok {
				info.City = state
			}
		}
	}
	var asnOrg string
	if asn, ok := data["asn"].(map[string]interface{}); ok {
		if org, ok := asn["asn_org"].(string); ok {
			asnOrg = org
		}
		if tp, ok := asn["type"].(string); ok {
			info.ASNType = tp
		}
	}
	if company, ok := data["company"].(map[string]interface{}); ok {
		if name, ok := company["name"].(string); ok {
			info.ISP = name
		}
		if tp, ok := company["type"].(string); ok && tp != "" {
			info.CompanyType = tp
		}
	}
	if info.ISP == "" && asnOrg != "" {
		info.ISP = asnOrg
	} else if info.ISP == "" {
		info.ISP = "Unknown ISP"
	}
	_, info.Tag = getIPTypeTags(info.CompanyType, info.ASNType)
	return info, nil
}

func fetchCNGeo(client *http.Client, queryIP string) (country, city, isp, asn string, err error) {
	urlStr := cnGeoJSONPURL
	if queryIP != "" {
		urlStr = fmt.Sprintf("%s?ip=%s", cnGeoJSONPURL, queryIP)
	}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", "", "", "", err
	}
	req.Header.Set("User-Agent", "proxy-scanner/1.0")
	req.Header.Set("Accept", "text/javascript, application/javascript")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", fmt.Errorf("ping0.cc JSONP HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", "", "", "", err
	}

	bodyStr := string(body)
	re := regexp.MustCompile(`callback\(([^)]+)\)`)
	matches := re.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return "", "", "", "", fmt.Errorf("无法解析 JSONP 响应")
	}
	argsStr := matches[1]
	jsonArray := "[" + argsStr + "]"
	var args []string
	if err := json.Unmarshal([]byte(jsonArray), &args); err != nil {
		parts := strings.Split(argsStr, ",")
		for i, p := range parts {
			parts[i] = strings.Trim(p, `" `)
		}
		args = parts
	}
	if len(args) < 4 {
		return "", "", "", "", fmt.Errorf("JSONP 参数不足，得到 %d 个", len(args))
	}
	location := strings.Trim(args[1], `"`)
	asnStr := strings.Trim(args[2], `"`)
	orgStr := strings.Trim(args[3], `"`)

	cleanLoc := regexp.MustCompile(`[^\p{Han}a-zA-Z0-9\s_]`).ReplaceAllString(location, "")
	space := regexp.MustCompile(`\s+`)
	cleanLoc = space.ReplaceAllString(cleanLoc, " ")
	parts := strings.Fields(cleanLoc)
	if len(parts) == 0 {
		country = ""
		city = ""
	} else if len(parts) == 1 {
		country = parts[0]
		city = ""
	} else {
		country = parts[0]
		city = strings.Join(parts[1:], "_")
	}
	isp = orgStr
	asn = asnStr
	return country, city, isp, asn, nil
}

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

func fetchProxyInfoWithCN(client *http.Client, entryIP string) (exitInfo *IPInfo, entryInfo *IPInfo, elapsed time.Duration, err error) {
	start := time.Now()
	defer func() {
		elapsed = time.Since(start)
	}()

	exitInfo, err = doFetchViaProxy(client, "")
	if err != nil {
		return nil, nil, 0, err
	}
	debugPrintf("出口信息获取成功 IP=%s, 类型=%s", exitInfo.IP, exitInfo.Tag)

	if *cnMode {
		if cnCountry, cnCity, cnISP, _, err2 := fetchCNGeo(client, ""); err2 == nil {
			debugPrintf("出口中文信息获取成功: 国家=%s, 城市=%s, ISP=%s", cnCountry, cnCity, cnISP)
			exitInfo.Country = cnCountry
			exitInfo.City = cnCity
			exitInfo.ISP = cnISP
		} else {
			debugPrintf("获取出口中文信息失败: %v", err2)
		}
	}

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

func quoteCSV(s string) string {
	if !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

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
		var node string
		protocolPrefix := r.Protocol + "://"
		if outCity != "" && outASN != "" {
			node = fmt.Sprintf("%s%s:%d#%s_%s[%s]", protocolPrefix, r.IP, r.Port, outRegion, outCity, outASN)
		} else if outCity != "" && outASN == "" {
			node = fmt.Sprintf("%s%s:%d#%s_%s", protocolPrefix, r.IP, r.Port, outRegion, outCity)
		} else if outCity == "" && outASN != "" {
			node = fmt.Sprintf("%s%s:%d#%s[%s]", protocolPrefix, r.IP, r.Port, outRegion, outASN)
		} else {
			node = fmt.Sprintf("%s%s:%d#%s", protocolPrefix, r.IP, r.Port, outRegion)
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
	hasValidPasswordBook := len(credentials) > 0 && !(len(credentials) == 1 && credentials[0].Username == "" && credentials[0].Password == "")

	fmt.Printf("开始扫描代理 (共 %d 个，类型: %s)，密码本数量: %d，跳过证书验证: %v，中文模式: %v\n",
		len(proxies), *proxyType, len(credentials), *skipVerify, *cnMode)
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

				// 尝试无认证
				client, err := createProxyClient(proxyAddr, "", "", *proxyType, globalTimeout, *skipVerify)
				if err == nil {
					exitInfo, entryInfo, elapsed, err := fetchProxyInfoWithCN(client, entryIP)
					client.CloseIdleConnections()
					if err == nil {
						debugPrintf("[Worker %d] 代理 %s 空认证成功", workerID, proxyAddr)
						csvTag, screenTag := getIPTypeTags(exitInfo.CompanyType, exitInfo.ASNType)
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

				// 需要认证但没有密码本则跳过
				if !hasValidPasswordBook {
					debugPrintf("[Worker %d] 代理 %s 需要认证但无有效密码本，跳过", workerID, proxyAddr)
					progress.Add(1, 0)
					continue
				}

				// 爆破凭据（轻量验证，只请求出口一次，忽略返回的详细信息）
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

				// 使用成功凭据创建最终客户端，完成完整的三次请求（复用连接）
				finalClient, err := createProxyClient(proxyAddr, successCred.Username, successCred.Password, *proxyType, globalTimeout, *skipVerify)
				if err != nil {
					debugPrintf("[Worker %d] 创建最终客户端失败: %v", workerID, err)
					progress.Add(1, 0)
					continue
				}
				exitInfo, entryInfo, elapsed, err := fetchProxyInfoWithCN(finalClient, entryIP)
				finalClient.CloseIdleConnections()
				if err != nil {
					debugPrintf("[Worker %d] 获取完整代理信息失败: %v", workerID, err)
					progress.Add(1, 0)
					continue
				}

				csvTag, screenTag := getIPTypeTags(exitInfo.CompanyType, exitInfo.ASNType)
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