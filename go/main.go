package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/motoki317/sc"
	"github.com/oklog/ulid/v2"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

var (
	memberCountCache int64
	membersCache     *sc.Cache[string, *Member]
	bookInfoCache    *sc.Cache[string, *Book]
	booksCache       *sc.Cache[string, *Book]
)

func main() {
	host := getEnvOrDefault("DB_HOST", "localhost")
	port := getEnvOrDefault("DB_PORT", "3306")
	user := getEnvOrDefault("DB_USER", "isucon")
	pass := getEnvOrDefault("DB_PASS", "isucon")
	name := getEnvOrDefault("DB_NAME", "isulibrary")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Asia%%2FTokyo&interpolateParams=true", user, pass, host, port, name)

	var err error
	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	var key string
	err = db.Get(&key, "SELECT `key` FROM `key` WHERE `id` = (SELECT MAX(`id`) FROM `key`)")
	if err != nil {
		log.Panic(err)
	}

	membersCache = sc.NewMust(func(ctx context.Context, id string) (*Member, error) {
		var member Member
		err := db.GetContext(ctx, &member, "SELECT * FROM `member` WHERE `id` = ?", id)
		return &member, err
	}, 24*time.Hour, 24*time.Hour)
	bookInfoCache = sc.NewMust(func(ctx context.Context, id string) (*Book, error) {
		var book Book
		err := db.GetContext(ctx, &book, "SELECT * FROM `book` WHERE `id` = ?", id)
		return &book, err
	}, 24*time.Hour, 24*time.Hour)
	booksCache = sc.NewMust(func(ctx context.Context, id string) (*Book, error) {
		var book Book
		err := db.GetContext(ctx, &book, "SELECT * FROM `book` WHERE `id` = ?", id)
		return &book, err
	}, 24*time.Hour, 24*time.Hour)

	block, err = aes.NewCipher([]byte(key))
	if err != nil {
		log.Panic(err)
	}

	e := echo.New()
	e.Debug = true
	e.Use(middleware.Logger())

	api := e.Group("/api")
	{
		api.POST("/initialize", initializeHandler)

		membersAPI := api.Group("/members")
		{
			membersAPI.POST("", postMemberHandler)
			membersAPI.GET("", getMembersHandler)
			membersAPI.GET("/:id", getMemberHandler)
			membersAPI.PATCH("/:id", patchMemberHandler)
			membersAPI.DELETE("/:id", banMemberHandler)
			membersAPI.GET("/:id/qrcode", getMemberQRCodeHandler)
		}

		booksAPI := api.Group("/books")
		{
			booksAPI.POST("", postBooksHandler)
			booksAPI.GET("", getBooksHandler)
			booksAPI.GET("/:id", getBookHandler)
			booksAPI.GET("/:id/qrcode", getBookQRCodeHandler)
		}

		lendingsAPI := api.Group("/lendings")
		{
			lendingsAPI.POST("", postLendingsHandler)
			lendingsAPI.GET("", getLendingsHandler)
			lendingsAPI.POST("/return", returnLendingsHandler)
		}
	}

	e.Logger.Fatal(e.Start(":8080"))
}

/*
---------------------------------------------------------------
Domain Models
---------------------------------------------------------------
*/

// 会員
type Member struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Address     string    `json:"address" db:"address"`
	PhoneNumber string    `json:"phone_number" db:"phone_number"`
	Banned      bool      `json:"banned" db:"banned"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// 図書分類
type Genre int

// 国際十進分類法に従った図書分類
const (
	General         Genre = iota // 総記
	Philosophy                   // 哲学・心理学
	Religion                     // 宗教・神学
	SocialScience                // 社会科学
	Vacant                       // 未定義
	Mathematics                  // 数学・自然科学
	AppliedSciences              // 応用科学・医学・工学
	Arts                         // 芸術
	Literature                   // 言語・文学
	Geography                    // 地理・歴史
)

// 蔵書
type Book struct {
	ID        string    `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Author    string    `json:"author" db:"author"`
	Genre     Genre     `json:"genre" db:"genre"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	LendingID sql.NullString `json:"-" db:"lending_id"`
	MemberID  sql.NullString `json:"-" db:"member_id"`
	Due       sql.NullTime   `json:"-" db:"due"`
	LentAt    sql.NullTime   `json:"-" db:"lent_at"`
}

// 貸出記録
type Lending struct {
	ID        string    `json:"id"`
	MemberID  string    `json:"member_id"`
	BookID    string    `json:"book_id"`
	Due       time.Time `json:"due"`
	CreatedAt time.Time `json:"created_at"`
}

/*
---------------------------------------------------------------
Utilities
---------------------------------------------------------------
*/

// ULIDを生成
func generateID() string {
	return ulid.Make().String()
}

var db *sqlx.DB

func getEnvOrDefault(key string, defaultValue string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}

	return defaultValue
}

var (
	block      cipher.Block
	qrFileLock sync.Mutex
)

// AES + CTRモード + base64エンコードでテキストを暗号化
func encrypt(plainText string) (string, error) {
	cipherText := make([]byte, aes.BlockSize+len([]byte(plainText)))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], []byte(plainText))
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

// AES + CTRモード + base64エンコードで暗号化されたテキストを複合
func decrypt(cipherText string) (string, error) {
	cipherByte, err := base64.URLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	decryptedText := make([]byte, len([]byte(cipherByte[aes.BlockSize:])))
	decryptStream := cipher.NewCTR(block, []byte(cipherByte[:aes.BlockSize]))
	decryptStream.XORKeyStream(decryptedText, []byte(cipherByte[aes.BlockSize:]))
	return string(decryptedText), nil
}

const qrCodeFileName = "../images/qr.png"

// QRコードを生成
func generateQRCode(id string) ([]byte, error) {
	encryptedID, err := encrypt(id)
	if err != nil {
		return nil, err
	}

	/*
		生成するQRコードの仕様
		 - PNGフォーマット
		 - QRコードの1モジュールは1ピクセルで表現
		 - バージョン6 (41x41ピクセル、マージン含め49x49ピクセル)
		 - エラー訂正レベルM (15%)
	*/
	err = exec.
		Command("sh", "-c", fmt.Sprintf("echo \"%s\" | qrencode -o %s -t PNG -s 1 -v 6 --strict-version -l M", encryptedID, qrCodeFileName)).
		Run()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(qrCodeFileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

/*
---------------------------------------------------------------
Initialization API
---------------------------------------------------------------
*/

type InitializeHandlerRequest struct {
	Key string `json:"key"`
}

type InitializeHandlerResponse struct {
	Language string `json:"language"`
}

// 初期化用ハンドラ
func initializeHandler(c echo.Context) error {
	var req InitializeHandlerRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if len(req.Key) != 16 {
		return echo.NewHTTPError(http.StatusBadRequest, "key must be 16 characters")
	}

	cmd := exec.Command("sh", "../sql/init_db.sh")
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_, err = db.ExecContext(c.Request().Context(), "INSERT INTO `key` (`key`) VALUES (?)", req.Key)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	block, err = aes.NewCipher([]byte(req.Key))
	if err != nil {
		log.Panic(err.Error())
	}

	atomic.StoreInt64(&memberCountCache, 0)
	membersCache.Purge()
	booksCache.Purge()
	bookInfoCache.Purge()

	// warm cache
	err = db.GetContext(c.Request().Context(), &memberCountCache, "SELECT COUNT(*) FROM `member`")
	if err != nil {
		log.Panic(err.Error())
	}

	var ids []string
	err = db.SelectContext(c.Request().Context(), &ids, "SELECT id FROM book")
	if err != nil {
		log.Panic(err.Error())
	}
	for _, id := range ids {
		_, err = booksCache.Get(c.Request().Context(), id)
		if err != nil {
			log.Panic(err.Error())
		}
		_, err = bookInfoCache.Get(c.Request().Context(), id)
		if err != nil {
			log.Panic(err.Error())
		}
	}

	return c.JSON(http.StatusOK, InitializeHandlerResponse{
		Language: "Go",
	})
}

/*
---------------------------------------------------------------
Members API
---------------------------------------------------------------
*/

type PostMemberRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
}

// 会員登録
func postMemberHandler(c echo.Context) error {
	var req PostMemberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" || req.Address == "" || req.PhoneNumber == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, address, phoneNumber are required")
	}

	id := generateID()

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = tx.ExecContext(c.Request().Context(),
		"INSERT INTO `member` (`id`, `name`, `address`, `phone_number`, `banned`, `created_at`) VALUES (?, ?, ?, ?, FALSE, ?)",
		id, req.Name, req.Address, req.PhoneNumber, time.Now())
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	var res Member
	err = tx.GetContext(c.Request().Context(), &res, "SELECT * FROM `member` WHERE `id` = ?", id)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_ = tx.Commit()
	atomic.AddInt64(&memberCountCache, 1)

	return c.JSON(http.StatusCreated, res)
}

const memberPageLimit = 100

type GetMembersResponse struct {
	Members []Member `json:"members"`
	Total   int      `json:"total"`
}

// 会員一覧を取得 (ページネーションあり)
func getMembersHandler(c echo.Context) error {
	pageStr := c.QueryParam("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// 前ページの最後の会員ID
	// シーク法をフロントエンドでは実装したが、バックエンドは力尽きた
	_ = c.QueryParam("last_member_id")

	order := c.QueryParam("order")
	if order != "" && order != "name_asc" && order != "name_desc" {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid order")
	}

	tx, err := db.BeginTxx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := "SELECT * FROM `member` WHERE `banned` = FALSE "
	switch order {
	case "name_asc":
		query += "ORDER BY `name` ASC "
	case "name_desc":
		query += " ORDER BY `name` DESC "
	}
	query += "LIMIT ? OFFSET ?"

	members := []Member{}
	err = tx.SelectContext(c.Request().Context(), &members, query, memberPageLimit, (page-1)*memberPageLimit)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if len(members) == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "no members to show in this page")
	}

	total := int(atomic.LoadInt64(&memberCountCache))
	// err = tx.GetContext(c.Request().Context(), &total, "SELECT COUNT(*) FROM `member`")
	// if err != nil {
	// 	c.Logger().Error(err)
	// 	return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	// }

	_ = tx.Commit()

	return c.JSON(http.StatusOK, GetMembersResponse{
		Members: members,
		Total:   total,
	})
}

// 会員を取得
func getMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	encrypted := c.QueryParam("encrypted")
	if encrypted == "true" {
		var err error
		id, err = decrypt(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else if encrypted != "" && encrypted != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "encrypted must be boolean value")
	}

	member, err := membersCache.Get(c.Request().Context(), id)
	// member := Member{}
	// err := db.GetContext(c.Request().Context(), &member, "SELECT * FROM `member` WHERE `id` = ? AND `banned` = FALSE", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if member.Banned {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}

	return c.JSON(http.StatusOK, member)
}

type PatchMemberRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number"`
}

// 会員情報編集
func patchMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	var req PatchMemberRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.Name == "" && req.Address == "" && req.PhoneNumber == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name, address or phoneNumber is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在を確認
	member, err := membersCache.Get(c.Request().Context(), id)
	// err = tx.GetContext(c.Request().Context(), &Member{}, "SELECT * FROM `member` WHERE `id` = ? AND `banned` = FALSE", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if member.Banned {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}

	query := "UPDATE `member` SET "
	params := []any{}
	if req.Name != "" {
		query += "`name` = ?, "
		params = append(params, req.Name)
	}
	if req.Address != "" {
		query += "`address` = ?, "
		params = append(params, req.Address)
	}
	if req.PhoneNumber != "" {
		query += "`phone_number` = ?, "
		params = append(params, req.PhoneNumber)
	}
	query = strings.TrimSuffix(query, ", ")
	query += " WHERE `id` = ?"
	params = append(params, id)

	_, err = tx.ExecContext(c.Request().Context(), query, params...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_ = tx.Commit()
	membersCache.Forget(id)

	return c.NoContent(http.StatusNoContent)
}

// 会員をBAN
func banMemberHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在を確認
	_, err = membersCache.Get(c.Request().Context(), id)
	// err = tx.GetContext(c.Request().Context(), &Member{}, "SELECT * FROM `member` WHERE `id` = ? AND `banned` = FALSE", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_, err = tx.ExecContext(c.Request().Context(), "UPDATE `member` SET `banned` = TRUE WHERE `id` = ?", id)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_ = tx.Commit()
	membersCache.Forget(id)

	return c.NoContent(http.StatusNoContent)
}

// 会員証用のQRコードを取得
func getMemberQRCodeHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	// 会員の存在確認
	member, err := membersCache.Get(c.Request().Context(), id)
	// err := db.GetContext(c.Request().Context(), &Member{}, "SELECT * FROM `member` WHERE `id` = ? AND `banned` = FALSE", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if member.Banned {
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	}

	qrFileLock.Lock()
	defer qrFileLock.Unlock()

	qrCode, err := generateQRCode(id)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.Blob(http.StatusOK, "image/png", qrCode)
}

/*
---------------------------------------------------------------
Books API
---------------------------------------------------------------
*/

type PostBooksRequest struct {
	Title  string `json:"title"`
	Author string `json:"author"`
	Genre  Genre  `json:"genre"`
}

// 蔵書を登録 (複数札を一気に登録)
func postBooksHandler(c echo.Context) error {
	var reqSlice []PostBooksRequest
	if err := c.Bind(&reqSlice); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	res := []Book{}
	createdAt := time.Now()

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, req := range reqSlice {
		if req.Title == "" || req.Author == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "title, author is required")
		}
		if req.Genre < 0 || req.Genre > 9 {
			return echo.NewHTTPError(http.StatusBadRequest, "genre is invalid")
		}

		id := generateID()

		_, err := tx.ExecContext(c.Request().Context(),
			"INSERT INTO `book` (`id`, `title`, `author`, `genre`, `created_at`) VALUES (?, ?, ?, ?, ?)",
			id, req.Title, req.Author, req.Genre, createdAt)
		if err != nil {
			c.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		var record Book
		err = tx.GetContext(c.Request().Context(), &record, "SELECT * FROM `book` WHERE `id` = ?", id)
		if err != nil {
			c.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		res = append(res, record)
	}

	_ = tx.Commit()

	return c.JSON(http.StatusCreated, res)
}

const bookPageLimit = 50

type GetBooksResponse struct {
	Books []GetBookResponse `json:"books"`
	Total int               `json:"total"`
}

// 蔵書を検索
func getBooksHandler(c echo.Context) error {
	title := c.QueryParam("title")
	author := c.QueryParam("author")
	genre := c.QueryParam("genre")
	if genre != "" {
		genreInt, err := strconv.Atoi(genre)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if genreInt < 0 || genreInt > 9 {
			return echo.NewHTTPError(http.StatusBadRequest, "genre is invalid")
		}
	}
	if genre == "" && title == "" && author == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "title, author or genre is required")
	}

	pageStr := c.QueryParam("page")
	if pageStr == "" {
		pageStr = "1"
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// 前ページの最後の蔵書ID
	// シーク法をフロントエンドでは実装したが、バックエンドは力尽きた
	_ = c.QueryParam("last_book_id")

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := "SELECT COUNT(*) FROM `book` WHERE "
	var args []any
	if genre != "" {
		query += "genre = ? AND "
		args = append(args, genre)
	}
	if title != "" {
		query += "title LIKE ? AND "
		args = append(args, "%"+title+"%")
	}
	if author != "" {
		query += "author LIKE ? AND "
		args = append(args, "%"+author+"%")
	}
	query = strings.TrimSuffix(query, "AND ")

	var total int
	err = tx.GetContext(c.Request().Context(), &total, query, args...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if total == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "no books found")
	}

	query = strings.ReplaceAll(query, "COUNT(*)", "*")
	query += "LIMIT ? OFFSET ?"
	args = append(args, bookPageLimit, (page-1)*bookPageLimit)

	var books []Book
	err = tx.SelectContext(c.Request().Context(), &books, query, args...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if len(books) == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "no books to show in this page")
	}

	res := GetBooksResponse{
		Books: make([]GetBookResponse, len(books)),
		Total: total,
	}

	for i, book := range books {
		res.Books[i].Book = book
		res.Books[i].Lending = book.LendingID.Valid
	}

	_ = tx.Commit()

	return c.JSON(http.StatusOK, res)
}

type GetBookResponse struct {
	Book
	Lending bool `json:"lending"`
}

// 蔵書を取得
func getBookHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	encrypted := c.QueryParam("encrypted")
	if encrypted == "true" {
		var err error
		id, err = decrypt(id)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	} else if encrypted != "" && encrypted != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "encrypted must be boolean value")
	}

	tx, err := db.BeginTxx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	book, err := booksCache.Get(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	res := GetBookResponse{
		Book:    *book,
		Lending: book.LendingID.Valid,
	}

	_ = tx.Commit()

	return c.JSON(http.StatusOK, res)
}

// 蔵書のQRコードを取得
func getBookQRCodeHandler(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "id is required")
	}

	// 蔵書の存在確認
	_, err := booksCache.Get(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	qrFileLock.Lock()
	defer qrFileLock.Unlock()

	qrCode, err := generateQRCode(id)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.Blob(http.StatusOK, "image/png", qrCode)
}

/*
---------------------------------------------------------------
Lending API
---------------------------------------------------------------
*/

// 貸出期間(ミリ秒)
const LendingPeriod = 3000

type PostLendingsRequest struct {
	BookIDs  []string `json:"book_ids"`
	MemberID string   `json:"member_id"`
}

type PostLendingsResponse struct {
	Lending
	MemberName string `json:"member_name"`
	BookTitle  string `json:"book_title"`
}

// 本を貸し出し
func postLendingsHandler(c echo.Context) error {
	var req PostLendingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.MemberID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "member_id is required")
	}
	if len(req.BookIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "at least one book_ids is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在確認
	member, err := membersCache.Get(c.Request().Context(), req.MemberID)
	// var member Member
	// err = tx.GetContext(c.Request().Context(), &member, "SELECT * FROM `member` WHERE `id` = ?", req.MemberID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	lendingTime := time.Now().Truncate(time.Microsecond).In(time.UTC)
	due := lendingTime.Add(LendingPeriod * time.Millisecond)

	query, args, err := sqlx.In("SELECT COUNT(*) FROM `book` WHERE `id` IN (?) AND `lending_id` IS NULL FOR UPDATE", req.BookIDs)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	var count int
	err = tx.GetContext(c.Request().Context(), &count, query, args...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if count != len(req.BookIDs) {
		c.Logger().Errorf("count: %v, len(req.BookIDs): %v", count, len(req.BookIDs))
		return echo.NewHTTPError(http.StatusConflict, "this book is already lent")
	}

	books := make([]*Book, len(req.BookIDs))
	for i := range books {
		books[i], err = bookInfoCache.Get(c.Request().Context(), req.BookIDs[i])
		if err != nil {
			c.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		books[i].LendingID = sql.NullString{String: generateID(), Valid: true}
		books[i].MemberID = sql.NullString{String: req.MemberID, Valid: true}
		books[i].Due = sql.NullTime{Time: due, Valid: true}
		books[i].LentAt = sql.NullTime{Time: lendingTime, Valid: true}
	}
	_, err = tx.NamedExecContext(
		c.Request().Context(),
		"INSERT INTO book (id, title, author, genre, created_at, lending_id, member_id, due, lent_at) VALUES (:id, :title, :author, :genre, :created_at, :lending_id, :member_id, :due, :lent_at) ON DUPLICATE KEY UPDATE lending_id = VALUES(lending_id), member_id = VALUES(member_id), due = VALUES(due), lent_at = VALUES(lent_at)",
		books,
	)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	res := lo.Map(req.BookIDs, func(id string, i int) PostLendingsResponse {
		return PostLendingsResponse{
			Lending: Lending{
				ID:        books[i].LendingID.String,
				MemberID:  books[i].MemberID.String,
				BookID:    id,
				Due:       books[i].Due.Time,
				CreatedAt: books[i].LentAt.Time,
			},
			MemberName: member.Name,
			BookTitle:  books[i].Title,
		}
	})

	_ = tx.Commit()
	for _, r := range res {
		booksCache.Forget(r.BookID)
	}

	return c.JSON(http.StatusCreated, res)
}

type GetLendingsResponse struct {
	Lending
	MemberName string `json:"member_name"`
	BookTitle  string `json:"book_title"`
}

func getLendingsHandler(c echo.Context) error {
	overDue := c.QueryParam("over_due")
	if overDue != "" && overDue != "true" && overDue != "false" {
		return echo.NewHTTPError(http.StatusBadRequest, "over_due must be boolean value")
	}

	tx, err := db.BeginTxx(c.Request().Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := "SELECT * FROM `book`"
	args := []any{}
	if overDue == "true" {
		query += " WHERE `due` > ? AND `due` IS NOT NULL"
		args = append(args, time.Now())
	} else {
		query += " WHERE `due` IS NOT NULL"
	}

	var books []Book
	err = tx.SelectContext(c.Request().Context(), &books, query, args...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	res := make([]*GetLendingsResponse, len(books))
	for i, book := range books {
		res[i] = &GetLendingsResponse{}
		res[i].Lending = Lending{
			ID:        book.LendingID.String,
			MemberID:  book.MemberID.String,
			BookID:    book.ID,
			Due:       book.Due.Time.In(time.UTC),
			CreatedAt: book.LentAt.Time.In(time.UTC),
		}
		res[i].BookTitle = book.Title

		member, err := membersCache.Get(c.Request().Context(), book.MemberID.String)
		// var member Member
		// err = tx.GetContext(c.Request().Context(), &member, "SELECT * FROM `member` WHERE `id` = ?", book.MemberID)
		if err != nil {
			c.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		res[i].MemberName = member.Name
	}

	_ = tx.Commit()

	slices.SortFunc(res, func(a, b *GetLendingsResponse) bool {
		return a.ID < b.ID
	})

	return c.JSON(http.StatusOK, res)
}

type ReturnLendingsRequest struct {
	BookIDs  []string `json:"book_ids"`
	MemberID string   `json:"member_id"`
}

// 蔵書を返却
func returnLendingsHandler(c echo.Context) error {
	var req ReturnLendingsRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.MemberID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "member_id is required")
	}
	if len(req.BookIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "at least one book_ids is required")
	}

	tx, err := db.BeginTxx(c.Request().Context(), nil)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 会員の存在確認
	_, err = membersCache.Get(c.Request().Context(), req.MemberID)
	// err = tx.GetContext(c.Request().Context(), &Member{}, "SELECT * FROM `member` WHERE `id` = ?", req.MemberID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	// 貸し出しの存在確認
	query, args, err := sqlx.In("SELECT COUNT(*) FROM book WHERE id IN (?) AND member_id = ?", req.BookIDs, req.MemberID)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	var count int
	err = tx.GetContext(c.Request().Context(), &count, query, args...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if count != len(req.BookIDs) {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	}

	query, args, err = sqlx.In("UPDATE `book` SET `lending_id` = NULL, `member_id` = NULL, `due` = NULL, `lent_at` = NULL WHERE `id` IN (?)", req.BookIDs)
	_, err = tx.ExecContext(c.Request().Context(), query, args...)
	if err != nil {
		c.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	_ = tx.Commit()
	for _, bookID := range req.BookIDs {
		booksCache.Forget(bookID)
	}

	return c.NoContent(http.StatusNoContent)
}
