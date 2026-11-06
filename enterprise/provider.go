package enterprise

import "context"

// CompanyBasic 是名称搜索返回的公司摘要。
type CompanyBasic struct {
	Name              string `json:"name"`
	PID               string `json:"pid"`
	LegalPerson       string `json:"legal_person"`
	OpenStatus        string `json:"open_status"`
	Domicile          string `json:"domicile"`
	RegisteredCapital string `json:"registered_capital"`
	GroupName         string `json:"group_name"`
	Website           string `json:"website"`
	Description       string `json:"description"`
	Email             string `json:"email"`
	Source            string `json:"source"`
}

// Company 是投资关系树节点，包含子公司列表。
type Company struct {
	Name              string    `json:"name"`
	EID               string    `json:"eid"`
	RegStatus         string    `json:"reg_status"`
	InvestRatio       float64   `json:"invest_ratio"`
	LegalPerson       string    `json:"legal_person"`
	Domicile          string    `json:"domicile"`
	RegisteredCapital string    `json:"registered_capital"`
	Email             string    `json:"email"`
	Source            string    `json:"source"`
	Children          []Company `json:"children"`
}

// Table 是 FetchTable 返回的通用表格（icp/wechat/app 等）。
type Table struct {
	Name    string                   `json:"name"`
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
}

// EnterpriseTree 是单个 PID 的投资树与关联资产表的聚合结果。
type EnterpriseTree struct {
	RootPID  string   `json:"root_pid"`
	RootName string   `json:"root_name"`
	Source   string   `json:"source"`
	Root     *Company `json:"root"`
	Tables   []Table  `json:"tables"`
}

// Provider 是单个企业数据源的统一接口。
type Provider interface {
	Name() string
	SearchByName(ctx context.Context, query string) ([]CompanyBasic, error)
	GetCompanyDetail(ctx context.Context, pid string) (*Company, error)
	GetSubsidiaries(ctx context.Context, pid string) ([]Company, error)
	GetBranches(ctx context.Context, pid string) ([]Company, error)
	FetchTable(ctx context.Context, pid string, field string) (*Table, error)
}
