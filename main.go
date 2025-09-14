package main

import (
  "database/sql"
  "encoding/json"
  "log"
  "net/http"
  "strconv"
  "time"

  "github.com/gorilla/mux"
  "github.com/rs/cors"
  _ "github.com/mattn/go-sqlite3"
  "golang.org/x/crypto/bcrypt"
)

// 用戶結構
type User struct {
  ID       int     `json:"id"`
  Username string  `json:"username"`
  Email    string  `json:"email"`
  Password string  `json:"password,omitempty"`
  Balance  float64 `json:"balance"`
  Created  string  `json:"created"`
}

// 交易結構
type Transaction struct {
  ID      int     `json:"id"`
  UserID  int     `json:"user_id"`
  Type    string  `json:"type"`
  Amount  float64 `json:"amount"`
  Balance float64 `json:"balance"`
  Date    string  `json:"date"`
}

// 登入請求結構
type LoginRequest struct {
  Email    string `json:"email"`
  Password string `json:"password"`
}

// 註冊請求結構
type RegisterRequest struct {
  Username string `json:"username"`
  Email    string `json:"email"`
  Password string `json:"password"`
}

// 交易請求結構
type TransactionRequest struct {
  UserID int     `json:"user_id"`
  Amount float64 `json:"amount"`
}

// 全局資料庫連接
var db *sql.DB

// 初始化資料庫
func initDB() {
  var err error
  db, err = sql.Open("sqlite3", "./banking_system.db")
  if err != nil {
    log.Fatal("無法打開資料庫:", err)
  }

  // 創建用戶表
  createUsersTable := `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0,
    created DATETIME DEFAULT CURRENT_TIMESTAMP
  );`

  _, err = db.Exec(createUsersTable)
  if err != nil {
    log.Fatal("創建用戶表失敗:", err)
  }

  // 創建交易表
  createTransactionsTable := `
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    balance REAL NOT NULL,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  );`

  _, err = db.Exec(createTransactionsTable)
  if err != nil {
    log.Fatal("創建交易表失敗:", err)
  }

  log.Println("資料庫初始化成功")
}

// 密碼哈希
func hashPassword(password string) (string, error) {
  bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
  return string(bytes), err
}

// 驗證密碼
func checkPasswordHash(password, hash string) bool {
  err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
  return err == nil
}

// 註冊用戶
func registerHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  var req RegisterRequest
  if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, `{"error":"無效的請求格式"}`, http.StatusBadRequest)
    return
  }

  // 驗證輸入
  if req.Username == "" || req.Email == "" || req.Password == "" {
    http.Error(w, `{"error":"所有欄位都是必填的"}`, http.StatusBadRequest)
    return
  }

  // 檢查郵箱是否已存在
  var exists bool
  err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", req.Email).Scan(&exists)
  if err != nil {
    http.Error(w, `{"error":"資料庫查詢錯誤"}`, http.StatusInternalServerError)
    return
  }
  if exists {
    http.Error(w, `{"error":"此電子郵件已被註冊"}`, http.StatusConflict)
    return
  }

  // 哈希密碼
  hashedPassword, err := hashPassword(req.Password)
  if err != nil {
    http.Error(w, `{"error":"密碼處理失敗"}`, http.StatusInternalServerError)
    return
  }

  // 創建用戶
  _, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    req.Username, req.Email, hashedPassword)
  if err != nil {
    http.Error(w, `{"error":"用戶創建失敗"}`, http.StatusInternalServerError)
    return
  }

  w.WriteHeader(http.StatusCreated)
  json.NewEncoder(w).Encode(map[string]string{"message": "註冊成功"})
}

// 用戶登入
func loginHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  var req LoginRequest
  if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, `{"error":"無效的請求格式"}`, http.StatusBadRequest)
    return
  }

  var user User
  var storedPassword string
  err := db.QueryRow("SELECT id, username, email, password, balance, created FROM users WHERE email = ?",
    req.Email).Scan(&user.ID, &user.Username, &user.Email, &storedPassword, &user.Balance, &user.Created)

  if err != nil {
    if err == sql.ErrNoRows {
      http.Error(w, `{"error":"電子郵件或密碼錯誤"}`, http.StatusUnauthorized)
      return
    }
    http.Error(w, `{"error":"資料庫查詢錯誤"}`, http.StatusInternalServerError)
    return
  }

  // 驗證密碼
  if !checkPasswordHash(req.Password, storedPassword) {
    http.Error(w, `{"error":"電子郵件或密碼錯誤"}`, http.StatusUnauthorized)
    return
  }

  // 不返回密碼
  user.Password = ""
  json.NewEncoder(w).Encode(map[string]interface{}{
    "message": "登入成功",
    "user":    user,
  })
}

// 獲取用戶餘額
func getBalanceHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  userID := r.URL.Query().Get("user_id")
  if userID == "" {
    http.Error(w, `{"error":"用戶ID是必需的"}`, http.StatusBadRequest)
    return
  }

  var balance float64
  err := db.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&balance)
  if err != nil {
    if err == sql.ErrNoRows {
      http.Error(w, `{"error":"用戶不存在"}`, http.StatusNotFound)
      return
    }
    http.Error(w, `{"error":"資料庫查詢錯誤"}`, http.StatusInternalServerError)
    return
  }

  json.NewEncoder(w).Encode(map[string]float64{"balance": balance})
}

// 儲值
func depositHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  var req TransactionRequest
  if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, `{"error":"無效的請求格式"}`, http.StatusBadRequest)
    return
  }

  if req.Amount <= 0 {
    http.Error(w, `{"error":"金額必須大於0"}`, http.StatusBadRequest)
    return
  }

  // 開始事務
  tx, err := db.Begin()
  if err != nil {
    http.Error(w, `{"error":"資料庫事務開始失敗"}`, http.StatusInternalServerError)
    return
  }
  defer tx.Rollback()

  // 檢查餘額是否足夠
  var currentBalance float64
  err = tx.QueryRow("SELECT balance FROM users WHERE id = ?", req.UserID).Scan(&currentBalance)
  if err != nil {
    if err == sql.ErrNoRows {
      http.Error(w, `{"error":"用戶不存在"}`, http.StatusNotFound)
      return
    }
    http.Error(w, `{"error":"獲取餘額失敗"}`, http.StatusInternalServerError)
    return
  }

  if currentBalance < req.Amount {
    http.Error(w, `{"error":"餘額不足"}`, http.StatusBadRequest)
    return
  }

  // 更新用戶餘額
  _, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", req.Amount, req.UserID)
  if err != nil {
    http.Error(w, `{"error":"餘額更新失敗"}`, http.StatusInternalServerError)
    return
  }

  // 獲取新餘額
  var newBalance float64
  err = tx.QueryRow("SELECT balance FROM users WHERE id = ?", req.UserID).Scan(&newBalance)
  if err != nil {
    http.Error(w, `{"error":"獲取餘額失敗"}`, http.StatusInternalServerError)
    return
  }

  // 記錄交易
  _, err = tx.Exec("INSERT INTO transactions (user_id, type, amount, balance) VALUES (?, ?, ?, ?)",
    req.UserID, "withdraw", req.Amount, newBalance)
  if err != nil {
    http.Error(w, `{"error":"交易記錄失敗"}`, http.StatusInternalServerError)
    return
  }

  // 提交事務
  if err = tx.Commit(); err != nil {
    http.Error(w, `{"error":"事務提交失敗"}`, http.StatusInternalServerError)
    return
  }

  json.NewEncoder(w).Encode(map[string]interface{}{
    "message":    "提款成功",
    "amount":     req.Amount,
    "newBalance": newBalance,
  })
}

// 獲取交易記錄
func getTransactionsHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  userID := r.URL.Query().Get("user_id")
  if userID == "" {
    http.Error(w, `{"error":"用戶ID是必需的"}`, http.StatusBadRequest)
    return
  }

  // 獲取分頁參數
  limitStr := r.URL.Query().Get("limit")
  offsetStr := r.URL.Query().Get("offset")

  limit := 50 // 默認限制
  offset := 0 // 默認偏移

  if limitStr != "" {
    if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
      limit = l
    }
  }

  if offsetStr != "" {
    if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
      offset = o
    }
  }

  rows, err := db.Query(
    "SELECT id, user_id, type, amount, balance, date FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT ? OFFSET ?",
    userID, limit, offset)
  if err != nil {
    http.Error(w, `{"error":"資料庫查詢錯誤"}`, http.StatusInternalServerError)
    return
  }
  defer rows.Close()

  var transactions []Transaction
  for rows.Next() {
    var t Transaction
    var dateStr string
    err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Amount, &t.Balance, &dateStr)
    if err != nil {
      http.Error(w, `{"error":"資料掃描錯誤"}`, http.StatusInternalServerError)
      return
    }

    // 解析時間並格式化
    if parsedTime, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
      t.Date = parsedTime.Format("2006-01-02 15:04:05")
    } else {
      t.Date = dateStr
    }

    transactions = append(transactions, t)
  }

  if transactions == nil {
    transactions = []Transaction{}
  }

  json.NewEncoder(w).Encode(transactions)
}

// 健康檢查
func healthHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(map[string]string{
    "status": "healthy",
    "time":   time.Now().Format("2006-01-02 15:04:05"),
  })
}

// 設置路由
func setupRoutes() *mux.Router {
  router := mux.NewRouter()

  // API 路由
  api := router.PathPrefix("/api").Subrouter()

  // 用戶相關
  api.HandleFunc("/register", registerHandler).Methods("POST")
  api.HandleFunc("/login", loginHandler).Methods("POST")
  api.HandleFunc("/balance", getBalanceHandler).Methods("GET")

  // 交易相關
  api.HandleFunc("/deposit", depositHandler).Methods("POST")
  api.HandleFunc("/withdraw", withdrawHandler).Methods("POST")
  api.HandleFunc("/transactions", getTransactionsHandler).Methods("GET")

  // 健康檢查
  api.HandleFunc("/health", healthHandler).Methods("GET")

  // 靜態檔案服務（可選）
  router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

  return router
}

// 中間件：記錄請求
func loggingMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    next.ServeHTTP(w, r)
    log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
  })
}

func main() {
  // 初始化資料庫
  initDB()
  defer db.Close()

  // 設置路由
  router := setupRoutes()

  // 添加中間件
  router.Use(loggingMiddleware)

  // 配置 CORS
  c := cors.New(cors.Options{
    AllowedOrigins: []string{"*"}, // 在生產環境中應該設置具體的域名
    AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowedHeaders: []string{"*"},
  })

  handler := c.Handler(router)

  // 啟動服務器
  port := "0.0.0.0:5000"
  log.Printf("服務器啟動在端口 %s", port)
  log.Printf("健康檢查: http://localhost:5000/api/health")

  if err := http.ListenAndServe(port, handler); err != nil {
    log.Fatal("服務器啟動失敗:", err)
  }
}

// 提款
func withdrawHandler(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "application/json")

  var req TransactionRequest
  if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    http.Error(w, `{"error":"無效的請求格式"}`, http.StatusBadRequest)
    return
  }

  if req.Amount <= 0 {
    http.Error(w, `{"error":"金額必須大於0"}`, http.StatusBadRequest)
    return
  }

  // 開始事務
  tx, err := db.Begin()
  if err != nil {
    http.Error(w, `{"error":"資料庫事務開始失敗"}`, http.StatusInternalServerError)
    return
  }
  defer tx.Rollback()

  // 檢查餘額是否足夠
  var currentBalance float64
  err = tx.QueryRow("SELECT balance FROM users WHERE id = ?", req.UserID).Scan(&currentBalance)
  if err != nil {
    if err == sql.ErrNoRows {
      http.Error(w, `{"error":"用戶不存在"}`, http.StatusNotFound)
      return
    }
    http.Error(w, `{"error":"獲取餘額失敗"}`, http.StatusInternalServerError)
    return
  }

  if currentBalance < req.Amount {
    http.Error(w, `{"error":"餘額不足"}`, http.StatusBadRequest)
    return
  }

  // 更新用戶餘額
  _, err = tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", req.Amount, req.UserID)
  if err != nil {
    http.Error(w, `{"error":"餘額更新失敗"}`, http.StatusInternalServerError)
    return
  }

  // 獲取新餘額
  var newBalance float64
  err = tx.QueryRow("SELECT balance FROM users WHERE id = ?", req.UserID).Scan(&newBalance)
  if err != nil {
    http.Error(w, `{"error":"獲取餘額失敗"}`, http.StatusInternalServerError)
    return
  }

  // 記錄交易
  _, err = tx.Exec("INSERT INTO transactions (user_id, type, amount, balance) VALUES (?, ?, ?, ?)",
    req.UserID, "withdraw", req.Amount, newBalance)
  if err != nil {
    http.Error(w, `{"error":"交易記錄失敗"}`, http.StatusInternalServerError)
    return
  }

  // 提交事務
  if err = tx.Commit(); err != nil {
    http.Error(w, `{"error":"事務提交失敗"}`, http.StatusInternalServerError)
    return
  }

  json.NewEncoder(w).Encode(map[string]interface{}{
    "message":    "提款成功",
    "amount":     req.Amount,
    "newBalance": newBalance,
  })
}