# Git 常用命令速查

## 日常更新代码（最常用）

```bash
# 1. 查看当前修改状态
git status

# 2. 添加所有修改到暂存区
git add .

# 3. 提交更改
git commit -m "更新说明"

# 4. 推送到 GitHub
git push

# 一条龙命令（合并上面4步）
git add . && git commit -m "更新说明" && git push
```

## 首次克隆项目（给别人用）

```bash
git clone https://github.com/Vlunter/Myscanner.git
cd Myscanner
```

## 其他常用操作

```bash
# 查看提交历史
git log --oneline -10

# 查看远程仓库地址
git remote -v

# 拉取最新代码（多人协作时）
git pull

# 只添加指定文件
git add main.py
git add README.md

# 撤销未提交的修改（慎用）
git checkout -- <文件名>

# 创建新分支
git checkout -b feature-xxx

# 切换分支
git checkout main
```

## 注意事项

- 推送前确保已设置代理（国内网络）：
  ```powershell
  $env:HTTPS_PROXY="http://127.0.0.1:7890"
  $env:HTTP_PROXY="http://127.0.0.1:7890"
  ```
- Token 有效期到期后需要重新生成：https://github.com/settings/tokens
