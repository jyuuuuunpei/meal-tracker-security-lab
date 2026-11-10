# meal-tracker-security-lab

食事日、食事区分、料理名、メモを食事ノートに記録し、日付や料理名で振り返るローカルWebアプリです。所有者は、指定した相手に食事ノートの閲覧と検索を許可できます。

## 状態

Sprint 1を実装済みです。機能、権限、4回のSprintの完了条件は [REQUIREMENTS.md](REQUIREMENTS.md) を参照してください。Codexの作業ルールは [AGENTS.md](AGENTS.md) にあります。

## ローカル起動

Python 3.10以降を用意し、PowerShellでプロジェクトフォルダーに移動して次を実行します。

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app seed-demo
python -m flask --app app run
```

`seed-demo` は架空アカウント `a`・`b`・`c` のパスワードを対話入力し、ハッシュ化して保存します。起動後、ブラウザーで `http://127.0.0.1:5000` を開いてください。ローカル利用専用です。

## テスト

```powershell
python -m unittest discover -s tests -v
```

テストでは、架空アカウントでのログイン・ログアウト、ノート作成・一覧・詳細、他利用者による同じURLへの直接アクセス拒否、CSRF拒否、HTMLエスケープ、デモアカウントのパスワードハッシュ保存を確認します。

## 卒業研究での利用

各Sprint末の同じ実験用保存版に対し、静的解析のみの場合と生成AIレビューを加えた場合を比較します。対象は料理名検索のSQLインジェクション、メモ表示のXSS、食事ノートや記録への認可漏れです。実験用の保存版は、架空データを使い、隔離したローカル環境で扱います。
