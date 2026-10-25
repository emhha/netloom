# dirsearch 字典

`dirsearch/db/` 是从 https://github.com/maurosoria/dirsearch.git 的 Git 对象导出的原样快照，只引入 `db` 子目录。`dirsearch/upstream.json` 固定完整提交号、db Git tree 和每个文件的 SHA-256；不随扫描自动更新。

首次固定版本：`06c1be640c4479600064b22131a67f5f21fe2bca`。当前环境不能直接访问 GitHub，因此初次导入使用本机已有、origin 指向上游的干净 Git 检出，从提交对象读取，不复制工作区内容。该版本不是对最新 master 的承诺。

## 使用

从 netrt 仓库根目录运行时可显式配置：

```go
cfg := &dirscan.Config{
    BaseURL: "https://example.com",
    Preset: dirscan.PresetQuick,
    WordlistDir: "dirscan/wordlists/dirsearch/db",
}
```

其他应用应把目录复制到自己部署的资源位置，再传入实际路径。SDK 不按源码位置寻找字典、不读取用户目录、不将这些数据 embed 到二进制。自己的字典放在快照外，通过 Config.Wordlist 或单独的 WordlistDir 使用，以免更新冲突。

上游目录直接满足 common/conf/db/backups/keys/logs/vcs 预设及框架字典映射；未额外生成或添加 `leak.txt`。db 中原有 Python 字典生成器仅作为上游文件保留，扫描和更新脚本都不会执行它们。

## 检查和更新

需要 Python 3 和 Git；在 netrt 仓库根目录执行：

```sh
# 离线检查当前快照的完整性
python3 scripts/update-dirsearch-wordlists.py --check

# 重新导入锁定版本，默认不会跟随 master
python3 scripts/update-dirsearch-wordlists.py

# 推荐：更新到经过选定的完整提交 SHA
python3 scripts/update-dirsearch-wordlists.py --ref <完整提交SHA>

# 或明确取更新时的 master；脚本会解析并记录完整 SHA
python3 scripts/update-dirsearch-wordlists.py --ref master

# 使用本地 Git 对象离线导入；不会改动来源仓库
python3 scripts/update-dirsearch-wordlists.py --source /path/to/dirsearch --ref <完整提交SHA>

go test ./dirscan
```

更新会先在临时目录导出并校验，再替换快照；上游删除的文件也会同步删除。现有快照与锁文件不一致时拒绝覆盖，失败的下载不会改变当前快照。确认 Git diff 中的字典、许可和 upstream.json 变化后，将它们与 netrt 一起提交，便可用 Git 回退到任何已收录版本。

这里使用随主仓库提交的 Git 来源快照，因此不需要 submodule 初始化，也不需要写父仓库 `.git`。只收录上游子目录，不引入整个 dirsearch 应用。

## 出处与许可

Copyright (C) Mauro Soria；上游 README 声明 GNU GPL version 2，打包元数据标记 GPL-2.0-only。原始声明分别保留于 `dirsearch/README.upstream.md` 和 `dirsearch/PACKAGING.upstream.txt`，GPL v2 全文保留于 `LICENSE-GPL-2.0.txt`（来自系统提供的标准许可文本）。字典与生成器内已有的来源、作者和许可说明均原样保留，不改为本项目许可。
