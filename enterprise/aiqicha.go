// Package enterprise 提供企业工商数据 Provider 的实现。
// 调用方提供 HTTP 客户端和凭据读取接口，并负责 Provider 的创建与生命周期。
package enterprise

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/emhha/netloom/httpclient"
)

const defaultAiqichaBase = "https://aiqicha.baidu.com"

// 哨兵错误：由 checkResponseError / cookie 返回，供上层判断降级策略。
var (
	// ErrNotConfigured 表示未配置 aiqicha_cookie，Provider 无法发起认证请求。
	ErrNotConfigured = errors.New("enterprise.aiqicha: cookie 未配置，请通过凭据读取接口提供 aiqicha_cookie")
	// ErrSecurityVerify 表示触发百度安全验证，需人工在浏览器完成验证。
	ErrSecurityVerify = errors.New("enterprise.aiqicha: 触发百度安全验证，请在浏览器访问 https://aiqicha.baidu.com/ 完成验证")
	// ErrIPBanned 表示当前出口 IP 被封禁（HTTP 403）。
	ErrIPBanned = errors.New("enterprise.aiqicha: IP 被禁止访问，请更换 IP 或代理")
	// ErrCookieExpired 表示 Cookie 失效或过期（HTTP 401/302）。
	ErrCookieExpired = errors.New("enterprise.aiqicha: Cookie 已过期或无效，请重新获取")
)

// cookieReader 由调用方提供，按键返回明文 Cookie；存储与解密不属于本包。
type cookieReader interface {
	Get(ctx context.Context, key string) ([]byte, error)
}

// AiqichaProvider 通过爱企查 API 获取企业工商数据，实现 Provider。
// 并发安全：无可变状态，所有字段在构造后只读。
type AiqichaProvider struct {
	session enterpriseHTTPClient
	secrets cookieReader
	baseURL string // 默认 defaultAiqichaBase；测试时覆盖为 httptest.Server.URL
	source  string // httpclient 限速桶名称，默认 "aiqicha"；测试时覆盖以跳过内置限速
}

// NewAiqichaProvider 构造 AiqichaProvider。
// secrets 在查询时返回 "aiqicha_cookie" 的明文；凭据保护与轮换由调用方负责。
// secrets 为 nil 时所有方法返回 ErrNotConfigured。
type enterpriseHTTPClient interface {
	Get(context.Context, string, string, map[string]string) (*http.Response, error)
}

func NewAiqichaProvider(session enterpriseHTTPClient, secrets cookieReader) *AiqichaProvider {
	return &AiqichaProvider{
		session: session,
		secrets: secrets,
		baseURL: defaultAiqichaBase,
		source:  "aiqicha",
	}
}

func (p *AiqichaProvider) Name() string { return "aiqicha" }

// cookie 从调用方的凭据读取接口取得 aiqicha_cookie 明文，查询时重新读取以支持轮换。
// 未配置（secrets 为 nil、读取失败或值为空）时返回 ErrNotConfigured。
func (p *AiqichaProvider) cookie(ctx context.Context) (string, error) {
	if p.secrets == nil {
		return "", ErrNotConfigured
	}
	raw, err := p.secrets.Get(ctx, "aiqicha_cookie")
	if err != nil || len(raw) == 0 {
		return "", ErrNotConfigured
	}
	return strings.TrimSpace(string(raw)), nil
}

// headers 构造携带认证 Cookie 与 Referer 的请求头。
func (p *AiqichaProvider) headers(cookie string) map[string]string {
	return map[string]string{
		"Accept":  "text/html,application/json,application/xhtml+xml, image/jxr, */*",
		"Cookie":  cookie,
		"Referer": p.baseURL + "/",
	}
}

// doGet 发送一次 GET，读取响应体并做统一的错误检测（安全验证、封禁、API status）。
func (p *AiqichaProvider) doGet(ctx context.Context, rawURL, cookie string) ([]byte, error) {
	resp, err := p.session.Get(ctx, rawURL, p.source, p.headers(cookie))
	if err != nil {
		return nil, err
	}
	body, err := httpclient.ReadBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if err := checkResponseError(body, resp.StatusCode); err != nil {
		return nil, err
	}
	return body, nil
}

// checkResponseError 依据响应体与状态码识别反爬/认证失败与业务级错误。
func checkResponseError(body []byte, statusCode int) error {
	if bytes.Contains(body, []byte("百度安全验证")) {
		return ErrSecurityVerify
	}
	switch {
	case statusCode == 403:
		return ErrIPBanned
	case statusCode == 401, statusCode == 302:
		return ErrCookieExpired
	case statusCode == 404:
		return fmt.Errorf("enterprise.aiqicha: 资源不存在 (404)")
	case statusCode >= 400:
		return fmt.Errorf("enterprise.aiqicha: HTTP 错误 %d", statusCode)
	}
	// 业务级错误：顶层 status 非 0。
	var probe struct {
		Status int    `json:"status"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && probe.Status != 0 {
		return fmt.Errorf("enterprise.aiqicha: API 错误 status=%d msg=%s", probe.Status, probe.Msg)
	}
	return nil
}

// ---- pid 反混淆 ---------------------------------------------------------
//
// 搜索结果中的 pid 经过按位数字替换混淆，混淆表由响应中的 ddw 字段选择。
// aiqichaTransform 为只读查表，构造后不再修改。

var aiqichaTransform = [3]map[rune]rune{
	0: nil,
	1: {'0': '0', '1': '1', '2': '2', '3': '3', '4': '5', '5': '4', '6': '7', '7': '6', '8': '9', '9': '8'},
	2: {'0': '0', '1': '1', '2': '2', '3': '3', '4': '6', '5': '8', '6': '9', '7': '4', '8': '5', '9': '7'},
}

// transformAiqichaPid 按 ddw 选定的替换表还原真实 pid；ddw 越界时原样返回。
func transformAiqichaPid(input string, ddw int64) string {
	if ddw < 1 || ddw > 2 {
		return input
	}
	table := aiqichaTransform[ddw]
	out := make([]rune, 0, len(input))
	for _, c := range input {
		if mapped, ok := table[c]; ok {
			out = append(out, mapped)
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}

// stripHTML 移除搜索结果高亮标签（<em>...</em>）。
func stripHTML(s string) string {
	s = strings.ReplaceAll(s, "<em>", "")
	s = strings.ReplaceAll(s, "</em>", "")
	s = strings.ReplaceAll(s, `<\/em>`, "")
	return s
}

// ---- SearchByName -------------------------------------------------------

type aiqichaSearchResp struct {
	Status int   `json:"status"`
	DDW    int64 `json:"ddw"`
	Data   struct {
		ResultList []struct {
			PID         string `json:"pid"`
			EntName     string `json:"entName"`
			LegalPerson string `json:"legalPerson"`
			OpenStatus  string `json:"openStatus"`
			Domicile    string `json:"domicile"`
			RegCap      string `json:"regCap"`
			Website     string `json:"website"`
			Describe    string `json:"describe"`
			NewLabels   []struct {
				Key   string `json:"key"`
				Value struct {
					Text string `json:"text"`
				} `json:"value"`
			} `json:"newLabels"`
			EmailInfo []struct {
				Email string `json:"email"`
			} `json:"emailinfo"`
		} `json:"resultList"`
	} `json:"data"`
}

// SearchByName 按企业名称搜索，调用 /s/advanceFilterAjax。
func (p *AiqichaProvider) SearchByName(ctx context.Context, query string) ([]CompanyBasic, error) {
	cookie, err := p.cookie(ctx)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.SearchByName: %w", err)
	}
	apiURL := fmt.Sprintf("%s/s/advanceFilterAjax?q=%s&p=1&s=10&f=%s", p.baseURL, url.QueryEscape(query), url.QueryEscape("{}"))

	body, err := p.doGet(ctx, apiURL, cookie)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.SearchByName: %w", err)
	}

	var sr aiqichaSearchResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.SearchByName: decode: %w", err)
	}

	results := make([]CompanyBasic, 0, len(sr.Data.ResultList))
	for _, item := range sr.Data.ResultList {
		name := stripHTML(item.EntName)
		if name == "" {
			continue
		}

		groupName := ""
		for _, label := range item.NewLabels {
			if label.Key == "groupdata" {
				groupName = label.Value.Text
				break
			}
		}

		email := ""
		if len(item.EmailInfo) > 0 {
			email = item.EmailInfo[0].Email
		}

		results = append(results, CompanyBasic{
			Name:              name,
			PID:               transformAiqichaPid(item.PID, sr.DDW),
			LegalPerson:       item.LegalPerson,
			OpenStatus:        stripHTML(item.OpenStatus),
			Domicile:          item.Domicile,
			RegisteredCapital: item.RegCap,
			GroupName:         groupName,
			Website:           item.Website,
			Description:       stripHTML(item.Describe),
			Email:             email,
			Source:            p.Name(),
		})
	}
	return results, nil
}

// ---- GetCompanyDetail ---------------------------------------------------

type aiqichaDetailResp struct {
	Data struct {
		BasicData struct {
			EntName     string `json:"entName"`
			LegalPerson string `json:"legalPerson"`
			OpenStatus  string `json:"openStatus"`
			Email       string `json:"email"`
			RegCapital  string `json:"regCapital"`
			RegAddr     string `json:"regAddr"`
		} `json:"basicData"`
	} `json:"data"`
}

// GetCompanyDetail 获取企业详情，调用 /detail/basicAllDataAjax?pid={pid}。
func (p *AiqichaProvider) GetCompanyDetail(ctx context.Context, pid string) (*Company, error) {
	cookie, err := p.cookie(ctx)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.GetCompanyDetail: %w", err)
	}
	apiURL := fmt.Sprintf("%s/detail/basicAllDataAjax?pid=%s", p.baseURL, url.QueryEscape(pid))

	body, err := p.doGet(ctx, apiURL, cookie)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.GetCompanyDetail: %w", err)
	}

	var dr aiqichaDetailResp
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.GetCompanyDetail: decode: %w", err)
	}
	bd := dr.Data.BasicData
	if bd.EntName == "" {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.GetCompanyDetail: company not found: %s", pid)
	}

	return &Company{
		Name:              bd.EntName,
		EID:               pid,
		RegStatus:         bd.OpenStatus,
		LegalPerson:       bd.LegalPerson,
		Domicile:          bd.RegAddr,
		RegisteredCapital: bd.RegCapital,
		Email:             bd.Email,
		Source:            p.Name(),
	}, nil
}

// ---- GetSubsidiaries ----------------------------------------------------

type aiqichaInvestResp struct {
	Data struct {
		Total int `json:"total"`
		List  []struct {
			EntName    string `json:"entName"`
			PID        string `json:"pid"`
			RegRate    string `json:"regRate"`
			OpenStatus string `json:"openStatus"`
		} `json:"list"`
	} `json:"data"`
}

// GetSubsidiaries 获取对外投资（子公司）列表，分页调用 /detail/investajax。
// 首页失败返回错误；后续分页失败返回已抓取的部分结果，供上层继续构建树。
func (p *AiqichaProvider) GetSubsidiaries(ctx context.Context, pid string) ([]Company, error) {
	cookie, err := p.cookie(ctx)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.GetSubsidiaries: %w", err)
	}

	var companies []Company
	page := 1
	for {
		apiURL := fmt.Sprintf("%s/detail/investajax?size=100&pid=%s&p=%d", p.baseURL, url.QueryEscape(pid), page)
		body, err := p.doGet(ctx, apiURL, cookie)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.GetSubsidiaries: %w", err)
			}
			break
		}

		var ir aiqichaInvestResp
		if err := json.Unmarshal(body, &ir); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.GetSubsidiaries: decode: %w", err)
			}
			break
		}

		for _, item := range ir.Data.List {
			name := stripHTML(item.EntName)
			if name == "" || name == "-" {
				continue
			}
			var ratio float64
			fmt.Sscanf(strings.TrimSuffix(item.RegRate, "%"), "%f", &ratio)
			companies = append(companies, Company{
				Name:        name,
				EID:         item.PID,
				RegStatus:   stripHTML(item.OpenStatus),
				InvestRatio: ratio,
				Source:      p.Name(),
			})
		}

		if len(ir.Data.List) == 0 || len(companies) >= ir.Data.Total {
			break
		}
		page++
	}
	return companies, nil
}

// ---- GetBranches --------------------------------------------------------

type aiqichaBranchResp struct {
	Data struct {
		Total int `json:"total"`
		List  []struct {
			EntName string `json:"entName"`
			PID     string `json:"pid"`
		} `json:"list"`
	} `json:"data"`
}

// GetBranches 获取分支机构列表，分页调用 /detail/branchajax。
func (p *AiqichaProvider) GetBranches(ctx context.Context, pid string) ([]Company, error) {
	cookie, err := p.cookie(ctx)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.GetBranches: %w", err)
	}

	var companies []Company
	page := 1
	for {
		apiURL := fmt.Sprintf("%s/detail/branchajax?size=100&pid=%s&p=%d", p.baseURL, url.QueryEscape(pid), page)
		body, err := p.doGet(ctx, apiURL, cookie)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.GetBranches: %w", err)
			}
			break
		}

		var br aiqichaBranchResp
		if err := json.Unmarshal(body, &br); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.GetBranches: decode: %w", err)
			}
			break
		}

		for _, item := range br.Data.List {
			name := stripHTML(item.EntName)
			if name == "" {
				continue
			}
			companies = append(companies, Company{
				Name:   name,
				EID:    item.PID,
				Source: p.Name(),
			})
		}

		if len(br.Data.List) == 0 || len(companies) >= br.Data.Total {
			break
		}
		page++
	}
	return companies, nil
}

// ---- FetchTable ---------------------------------------------------------

// FetchTable 获取指定 field 的关联数据表。Table.Name 取 field 值（如 "icp"），
// 以便 repository.ExtractICPDomains 按名匹配。不支持的 field 返回 (nil, nil)。
func (p *AiqichaProvider) FetchTable(ctx context.Context, pid string, field string) (*Table, error) {
	cookie, err := p.cookie(ctx)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.FetchTable: %w", err)
	}

	switch field {
	case "icp":
		return p.fetchICP(ctx, pid, cookie)
	case "wechat":
		return p.fetchWechat(ctx, pid, cookie)
	case "app":
		return p.fetchApp(ctx, pid, cookie)
	case "copyright":
		return p.fetchCopyright(ctx, pid, cookie)
	default:
		return nil, nil
	}
}

// fieldColumns 返回各 field 表的固定列定义，保证下游（导入、展示）能按列名取值。
func fieldColumns(field string) []string {
	switch field {
	case "icp":
		return []string{"website_name", "website", "domain", "icp", "company_name", "source"}
	case "wechat":
		return []string{"name", "wechat_id", "description", "qrcode", "avatar", "source"}
	case "app":
		return []string{"name", "category", "logo", "source"}
	case "copyright":
		return []string{"software_name", "short_name", "batch_num", "software_type", "type_code", "reg_date", "source"}
	default:
		return nil
	}
}

func (p *AiqichaProvider) fetchICP(ctx context.Context, pid, cookie string) (*Table, error) {
	table := &Table{Name: "icp", Columns: fieldColumns("icp"), Rows: []map[string]interface{}{}}
	page := 1
	for {
		apiURL := fmt.Sprintf("%s/detail/icpinfoAjax?size=100&pid=%s&p=%d", p.baseURL, url.QueryEscape(pid), page)
		body, err := p.doGet(ctx, apiURL, cookie)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchICP: %w", err)
			}
			break
		}

		var resp struct {
			Data struct {
				Total int `json:"total"`
				List  []struct {
					SiteName string   `json:"siteName"`
					HomeURL  string   `json:"homeUrl"`
					Domain   []string `json:"domain"`
					IcpNo    string   `json:"icpNo"`
				} `json:"list"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchICP: decode: %w", err)
			}
			break
		}

		count := 0
		for _, item := range resp.Data.List {
			count++
			for _, domain := range item.Domain {
				if domain == "" {
					continue
				}
				table.Rows = append(table.Rows, map[string]interface{}{
					"website_name": item.SiteName,
					"website":      item.HomeURL,
					"domain":       domain,
					"icp":          item.IcpNo,
					"company_name": "",
					"source":       p.Name(),
				})
			}
		}

		if count == 0 || count >= resp.Data.Total {
			break
		}
		page++
	}
	return table, nil
}

func (p *AiqichaProvider) fetchWechat(ctx context.Context, pid, cookie string) (*Table, error) {
	table := &Table{Name: "wechat", Columns: fieldColumns("wechat"), Rows: []map[string]interface{}{}}
	apiURL := fmt.Sprintf("%s/c/wechatoaAjax?size=100&pid=%s&p=1", p.baseURL, url.QueryEscape(pid))
	body, err := p.doGet(ctx, apiURL, cookie)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchWechat: %w", err)
	}

	var resp struct {
		Data struct {
			List []struct {
				WechatName         string `json:"wechatName"`
				WechatID           string `json:"wechatId"`
				WechatIntruduction string `json:"wechatIntruduction"`
				Qrcode             string `json:"qrcode"`
				WechatLogo         string `json:"wechatLogo"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchWechat: decode: %w", err)
	}
	for _, item := range resp.Data.List {
		table.Rows = append(table.Rows, map[string]interface{}{
			"name":        item.WechatName,
			"wechat_id":   item.WechatID,
			"description": item.WechatIntruduction,
			"qrcode":      item.Qrcode,
			"avatar":      item.WechatLogo,
			"source":      p.Name(),
		})
	}
	return table, nil
}

func (p *AiqichaProvider) fetchApp(ctx context.Context, pid, cookie string) (*Table, error) {
	table := &Table{Name: "app", Columns: fieldColumns("app"), Rows: []map[string]interface{}{}}
	apiURL := fmt.Sprintf("%s/c/appinfoAjax?size=100&pid=%s&p=1", p.baseURL, url.QueryEscape(pid))
	body, err := p.doGet(ctx, apiURL, cookie)
	if err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchApp: %w", err)
	}

	var resp struct {
		Data struct {
			List []struct {
				Name     string `json:"name"`
				Classify string `json:"classify"`
				Logo     string `json:"logo"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchApp: decode: %w", err)
	}
	for _, item := range resp.Data.List {
		table.Rows = append(table.Rows, map[string]interface{}{
			"name":     item.Name,
			"category": item.Classify,
			"logo":     item.Logo,
			"source":   p.Name(),
		})
	}
	return table, nil
}

func (p *AiqichaProvider) fetchCopyright(ctx context.Context, pid, cookie string) (*Table, error) {
	table := &Table{Name: "copyright", Columns: fieldColumns("copyright"), Rows: []map[string]interface{}{}}
	page := 1
	for {
		apiURL := fmt.Sprintf("%s/detail/copyrightAjax?size=100&pid=%s&p=%d", p.baseURL, url.QueryEscape(pid), page)
		body, err := p.doGet(ctx, apiURL, cookie)
		if err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchCopyright: %w", err)
			}
			break
		}

		var resp struct {
			Data struct {
				Total int `json:"total"`
				List  []struct {
					SoftwareName string `json:"softwareName"`
					ShortName    string `json:"shortName"`
					BatchNum     string `json:"batchNum"`
					SoftwareType string `json:"softwareType"`
					TypeCode     string `json:"typeCode"`
					RegDate      string `json:"regDate"`
				} `json:"list"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			if page == 1 {
				return nil, fmt.Errorf("enterprise.AiqichaProvider.fetchCopyright: decode: %w", err)
			}
			break
		}

		for _, item := range resp.Data.List {
			table.Rows = append(table.Rows, map[string]interface{}{
				"software_name": item.SoftwareName,
				"short_name":    item.ShortName,
				"batch_num":     item.BatchNum,
				"software_type": item.SoftwareType,
				"type_code":     item.TypeCode,
				"reg_date":      item.RegDate,
				"source":        p.Name(),
			})
		}

		if len(resp.Data.List) == 0 || len(table.Rows) >= resp.Data.Total {
			break
		}
		page++
	}
	return table, nil
}

func NewAiqichaProviderAt(session enterpriseHTTPClient, secrets cookieReader, endpoint string) *AiqichaProvider {
	p := NewAiqichaProvider(session, secrets)
	if endpoint != "" {
		p.baseURL = strings.TrimRight(endpoint, "/")
	}
	return p
}
