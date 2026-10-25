## 指纹数据处理核心流程

```mermaid
flowchart TD
    subgraph "高级清理管道"
        A[parseJSONLToStructuredRules<br/>逐行解析JSONL文件<br/>提取CMS名称和规则数组<br/>构建RuleSet结构] --> B[mergeSimilarCMS<br/>标准化CMS名称<br/>生成领导者映射<br/>apache-solr→solr]
        B --> C[applyAdvancedCleaning<br/>应用三阶段清理管道]
        C --> D[removeExactDuplicateRuleSets<br/>基于JSON序列化去重<br/>优先保留混合大小写规则]
        D --> E[removeSupersetRules<br/>检查规则包含关系<br/>移除被完全包含的规则]
        E --> F[mergeSimilarSingleRules<br/>使用Levenshtein算法<br/>合并相似度>90%的规则]
    end
    
    subgraph "相似度处理"
        G[levenshtein距离计算<br/>动态规划算法<br/>计算字符串编辑距离] --> H[相似度阈值判断<br/>相似度=1-距离/最大长度<br/>90%阈值过滤]
        H --> I[保留更短的规则<br/>优先选择长度较短的<br/>减少误报]
    end
    
    subgraph "CMS名称标准化"
        J[normalizeCMSName<br/>转小写+移除特殊字符<br/>统一命名格式] --> K[generateLeaderMapping<br/>按长度排序CMS名称<br/>短名称作为领导者]
        K --> L[合并相似CMS名称<br/>检查包含关系<br/>apache-solr→solr]
    end
    
    subgraph "规则解析"
        M[parseRuleString<br/>解析复杂规则字符串<br/>支持AND/OR/括号] --> N[解析AND/OR逻辑<br/>按括号层级分割<br/>构建逻辑树]
        N --> O[过滤无效字段<br/>移除path/banner/protocol<br/>保留body/header/title/icon_hash]
        O --> P[构建RuleSet<br/>生成Rule结构数组<br/>Location+Keyword映射]
    end
    
    F --> G
    L --> B
    P --> A
```

## 指纹处理示例流程
```mermaid
flowchart TD
    subgraph "输入示例"
        A1["body='seeyon' && header='Server: nginx'<br/>title='致远OA' || icon_hash='12345678'"]
        A2["apache-solr<br/>solr<br/>Apache Solr"]
    end
    
    subgraph "规则解析过程"
        B1["按括号分割:<br/>body='seeyon' && header='Server: nginx'<br/>title='致远OA'<br/>icon_hash='12345678'"]
        B2["过滤字段:<br/>保留: body, header, title, icon_hash<br/>移除: path, banner, protocol"]
    end
    
    subgraph "CMS标准化过程"
        C1["apache-solr → apachesolr<br/>solr → solr<br/>Apache Solr → apachesolr"]
        C2["按长度排序:<br/>solr(4) < apachesolr(11)<br/>solr成为领导者"]
    end
    
    subgraph "相似度合并过程"
        D1["规则1: body='seeyon'<br/>规则2: body='seeyon-oa'<br/>距离=3, 相似度=0.75"]
        D2["相似度<90%<br/>不合并，保留两个规则"]
    end
    
    subgraph "输出结果"
        E1["solr:<br/>- body='seeyon' && header='Server: nginx'<br/>- title='致远OA'<br/>- icon_hash='12345678'"]
    end
    
    A1 --> B1
    A2 --> C1
    B1 --> B2
    C1 --> C2
    B2 --> D1
    D1 --> D2
    C2 --> E1
    D2 --> E1
```

## 指纹内容部分示例

```yaml
1拍物联网云服务平台:
    - header="1拍物联网云服务平台"
    - title="1拍物联网云服务平台"
2zproject:
    - body="generator\" content=\"2z project"
3com-3cdsg8:
    - (title="3Com Corporation Web Interface" && body="content=\" 3CDSG8\"")
    - body="content=\" 3cdsg8\""
3com-nj2000:
    - (title="3Com Corporation Web Interface" && body="content=\"3Com IntelliJack NJ2000\"")
    - body="content=\"3com intellijack nj2000\""
```

也只是尽量处理了，并非一个完美的指纹库。
cms的总数是: count=10520，指纹库总行数 3.8w，也就是有2.8万条规则。如果只是单纯的合并指纹库，数量更多。

