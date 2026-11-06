package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emhha/netloom/httpclient"
)

// mockSecrets 实现 cookieReader，返回固定 Cookie 值。err 非 nil 时模拟读取失败。
type mockSecrets struct {
	cookie string
	err    error
}

func (m *mockSecrets) Get(_ context.Context, _ string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte(m.cookie), nil
}

// newTestProvider 构造一个指向 ts.URL 的 AiqichaProvider，方便各测试复用。
// source 设为 "aiqicha-test" 以跳过内置的 1 req/3s 限速桶，使测试快速完成。
func newTestProvider(ts *httptest.Server) *AiqichaProvider {
	session := httpclient.NewSession(httpclient.Options{RetryMax: -1})
	p := NewAiqichaProvider(session, &mockSecrets{cookie: "test-cookie"})
	p.baseURL = ts.URL
	p.source = "aiqicha-test"
	return p
}

// writeJSON 序列化 v 并写入响应。
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestAiqichaProvider_Name(t *testing.T) {
	p := &AiqichaProvider{}
	if p.Name() != "aiqicha" {
		t.Errorf("expected aiqicha, got %s", p.Name())
	}
}

func TestAiqichaProvider_NotConfigured(t *testing.T) {
	session := httpclient.NewSession(httpclient.Options{RetryMax: -1})
	// secrets 为 nil：应立即返回 ErrNotConfigured，不发起网络请求。
	p := NewAiqichaProvider(session, nil)
	if _, err := p.SearchByName(context.Background(), "test"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}

	// secrets 存在但返回空 Cookie：同样视为未配置。
	p2 := NewAiqichaProvider(session, &mockSecrets{cookie: ""})
	if _, err := p2.SearchByName(context.Background(), "test"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured for empty cookie, got %v", err)
	}
}

func TestAiqichaProvider_SearchByName(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/s/advanceFilterAjax" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]interface{}{
			"status": 0,
			"ddw":    1, // 混淆表 1：4<->5,6<->7,8<->9
			"data": map[string]interface{}{
				"resultList": []map[string]interface{}{
					{
						"pid":         "1489", // ddw=1 还原为 "1598"
						"entName":     "<em>腾讯</em>科技（深圳）有限公司",
						"legalPerson": "马化腾",
						"openStatus":  "在营",
						"domicile":    "深圳市南山区",
						"regCap":      "10000万元",
						"website":     "www.tencent.com",
						"describe":    "互联网技术公司",
						"newLabels": []map[string]interface{}{
							{"key": "groupdata", "value": map[string]interface{}{"text": "腾讯集团"}},
						},
						"emailinfo": []map[string]interface{}{
							{"email": "service@tencent.com"},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	results, err := p.SearchByName(context.Background(), "腾讯")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	c := results[0]
	if c.Name != "腾讯科技（深圳）有限公司" {
		t.Errorf("expected stripped name, got %q", c.Name)
	}
	if c.PID != "1598" {
		t.Errorf("expected de-obfuscated pid 1598, got %s", c.PID)
	}
	if c.GroupName != "腾讯集团" {
		t.Errorf("unexpected group_name: %s", c.GroupName)
	}
	if c.Email != "service@tencent.com" {
		t.Errorf("unexpected email: %s", c.Email)
	}
	if c.Source != "aiqicha" {
		t.Errorf("expected source aiqicha, got %s", c.Source)
	}
}

func TestAiqichaProvider_SearchByName_SecurityVerify(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>百度安全验证</html>"))
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	_, err := p.SearchByName(context.Background(), "test")
	if !errors.Is(err, ErrSecurityVerify) {
		t.Fatalf("expected ErrSecurityVerify, got %v", err)
	}
}

func TestAiqichaProvider_SearchByName_APIStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]interface{}{"status": 10001, "msg": "bad request"})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	if _, err := p.SearchByName(context.Background(), "test"); err == nil {
		t.Fatal("expected error for non-zero api status")
	}
}

func TestAiqichaProvider_SearchByName_IPBanned(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	if _, err := p.SearchByName(context.Background(), "test"); !errors.Is(err, ErrIPBanned) {
		t.Fatalf("expected ErrIPBanned, got %v", err)
	}
}

func TestAiqichaProvider_GetCompanyDetail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/detail/basicAllDataAjax" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]interface{}{
			"data": map[string]interface{}{
				"basicData": map[string]interface{}{
					"entName":     "腾讯控股有限公司",
					"legalPerson": "马化腾",
					"openStatus":  "在营",
					"email":       "ir@tencent.com",
					"regCapital":  "10000万美元",
					"regAddr":     "深圳市南山区",
				},
			},
		})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	company, err := p.GetCompanyDetail(context.Background(), "pid001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if company.EID != "pid001" {
		t.Errorf("expected eid pid001, got %s", company.EID)
	}
	if company.Name != "腾讯控股有限公司" {
		t.Errorf("unexpected name: %s", company.Name)
	}
	if company.Domicile != "深圳市南山区" {
		t.Errorf("unexpected domicile: %s", company.Domicile)
	}
	if company.Source != "aiqicha" {
		t.Errorf("expected source aiqicha, got %s", company.Source)
	}
}

func TestAiqichaProvider_GetCompanyDetail_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]interface{}{"data": map[string]interface{}{"basicData": map[string]interface{}{}}})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	if _, err := p.GetCompanyDetail(context.Background(), "unknown"); err == nil {
		t.Fatal("expected error for empty entName")
	}
}

func TestAiqichaProvider_GetSubsidiaries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/detail/investajax" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]interface{}{
			"data": map[string]interface{}{
				"total": 2,
				"list": []map[string]interface{}{
					{"entName": "子公司 A", "pid": "sub-a", "regRate": "51%", "openStatus": "在营"},
					{"entName": "子公司 B", "pid": "sub-b", "regRate": "100", "openStatus": "在营"},
				},
			},
		})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	subs, err := p.GetSubsidiaries(context.Background(), "root")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subsidiaries, got %d", len(subs))
	}
	if subs[0].EID != "sub-a" {
		t.Errorf("unexpected eid: %s", subs[0].EID)
	}
	if subs[0].InvestRatio != 51.0 {
		t.Errorf("expected invest_ratio 51 (percent suffix stripped), got %f", subs[0].InvestRatio)
	}
	if subs[1].InvestRatio != 100.0 {
		t.Errorf("unexpected invest_ratio: %f", subs[1].InvestRatio)
	}
}

func TestAiqichaProvider_GetSubsidiaries_ErrorFirstPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	if _, err := p.GetSubsidiaries(context.Background(), "pid"); err == nil {
		t.Fatal("expected error when first page fails")
	}
}

func TestAiqichaProvider_GetBranches(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/detail/branchajax" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]interface{}{
			"data": map[string]interface{}{
				"total": 2,
				"list": []map[string]interface{}{
					{"entName": "北京分公司", "pid": "branch-bj"},
					{"entName": "上海分公司", "pid": "branch-sh"},
				},
			},
		})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	branches, err := p.GetBranches(context.Background(), "root")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(branches) != 2 {
		t.Fatalf("expected 2 branches, got %d", len(branches))
	}
	if branches[0].Name != "北京分公司" {
		t.Errorf("unexpected name: %s", branches[0].Name)
	}
	if branches[0].EID != "branch-bj" {
		t.Errorf("unexpected eid: %s", branches[0].EID)
	}
	if branches[0].Source != "aiqicha" {
		t.Errorf("expected source aiqicha, got %s", branches[0].Source)
	}
}

func TestAiqichaProvider_FetchTable_ICP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/detail/icpinfoAjax" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]interface{}{
			"data": map[string]interface{}{
				"total": 1,
				"list": []map[string]interface{}{
					{
						"siteName": "腾讯网",
						"homeUrl":  "https://www.tencent.com",
						"domain":   []string{"tencent.com", "qq.com"},
						"icpNo":    "粤B2-20090059",
					},
				},
			},
		})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	table, err := p.FetchTable(context.Background(), "root", "icp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Name 必须为 "icp"，供 repository.ExtractICPDomains 按名匹配。
	if table.Name != "icp" {
		t.Errorf("expected table name icp, got %s", table.Name)
	}
	if len(table.Rows) != 2 {
		t.Fatalf("expected 2 rows (one per domain), got %d", len(table.Rows))
	}
	if table.Rows[0]["domain"] != "tencent.com" {
		t.Errorf("unexpected domain: %v", table.Rows[0]["domain"])
	}
	if table.Rows[1]["domain"] != "qq.com" {
		t.Errorf("unexpected domain: %v", table.Rows[1]["domain"])
	}
}

func TestAiqichaProvider_FetchTable_Unsupported(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]interface{}{"data": map[string]interface{}{}})
	}))
	defer ts.Close()

	p := newTestProvider(ts)
	table, err := p.FetchTable(context.Background(), "root", "nonexistent")
	if err != nil {
		t.Fatalf("expected nil error for unsupported field, got %v", err)
	}
	if table != nil {
		t.Fatalf("expected nil table for unsupported field, got %+v", table)
	}
}
