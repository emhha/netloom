package plugins

import (
	"context"

	"github.com/emhha/netloom/fingerprint"
	"github.com/emhha/netloom/passive"
)

type Fingerprint struct{ Engine *fingerprint.Engine }

func (p Fingerprint) Metadata() passive.Metadata {
	return passive.Metadata{ID: "fingerprint", Version: "3", Description: "基于已取得请求与响应的技术指纹分析"}
}
func (p Fingerprint) CacheKey(in passive.Input) string { return passive.ResponseKey(in) }
func (p Fingerprint) Analyze(ctx context.Context, in passive.Input) (passive.Result, error) {
	if err := ctx.Err(); err != nil {
		return passive.Result{}, err
	}
	result := passive.Result{}
	for _, technology := range p.Engine.MatchExchange(ctx, in.Request, in.Response) {
		result.Artifacts = append(result.Artifacts, passive.Artifact{Type: "technology", Value: technology.Name, Rule: technology.Source})
	}
	return result, ctx.Err()
}
