package enterprise

import (
	"encoding/json"
	"testing"
)

func TestEnterpriseResponsesUseFrontendFieldNames(t *testing.T) {
	tree := EnterpriseTree{
		RootPID: "company-1", RootName: "Example", Source: "aiqicha",
		Root:   &Company{Name: "Example", EID: "company-1", Children: []Company{{Name: "Branch", EID: "company-2"}}},
		Tables: []Table{{Name: "icp", Columns: []string{"domain"}, Rows: []map[string]interface{}{{"domain": "example.com"}}}},
	}
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		RootPID string `json:"root_pid"`
		Root    struct {
			Name     string `json:"name"`
			EID      string `json:"eid"`
			Children []struct {
				EID string `json:"eid"`
			} `json:"children"`
		} `json:"root"`
		Tables []struct {
			Name string              `json:"name"`
			Rows []map[string]string `json:"rows"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.RootPID != "company-1" || response.Root.EID != "company-1" || len(response.Root.Children) != 1 || response.Root.Children[0].EID != "company-2" || len(response.Tables) != 1 || response.Tables[0].Rows[0]["domain"] != "example.com" {
		t.Fatalf("frontend cannot consume enterprise response: %s", data)
	}
	data, err = json.Marshal(CompanyBasic{PID: "company-1", LegalPerson: "Example Person"})
	if err != nil {
		t.Fatal(err)
	}
	var company map[string]string
	if err := json.Unmarshal(data, &company); err != nil {
		t.Fatal(err)
	}
	if company["pid"] != "company-1" || company["legal_person"] != "Example Person" {
		t.Fatalf("frontend cannot select company: %s", data)
	}
}
