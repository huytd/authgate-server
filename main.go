package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	DB  *sql.DB
	RDB *redis.Client
}

type User struct {
	UserID   string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func initDB(db *sql.DB) {
	// Create users table
	_, err := db.Exec(`
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	CREATE TABLE IF NOT EXISTS users (
		user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), 
		name VARCHAR,
		email VARCHAR,
		password VARCHAR 
	);
	`)
	if err != nil {
		panic(err)
	}
}

func InvalidRequestError(c echo.Context) error {
	return c.JSON(400, echo.Map{"error": "Invalid request"})
}

func UnauthorizedError(c echo.Context) error {
	return c.JSON(401, echo.Map{"error": "Unauthorized"})
}

func SetCookie(c echo.Context, key, value string, expiration time.Time) {
	cookie := &http.Cookie{
		Name:     key,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiration,
	}
	c.SetCookie(cookie)
}

func (s *Server) SessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID, err := c.Cookie("userid")
		if err != nil {
			fmt.Printf("User cookie not found: %s\n", err)
			return UnauthorizedError(c)
		}

		sessionID, err := c.Cookie("session")
		if err != nil {
			fmt.Printf("Session cookie not found: %s\n", err)
			return UnauthorizedError(c)
		}

		storedUserID, err := s.RDB.Get(c.Request().Context(), sessionID.Value).Result()
		if err != nil {
			fmt.Printf("Session not found or expired: %s\n", err)
			return UnauthorizedError(c)
		}

		if storedUserID != userID.Value {
			fmt.Printf("Invalid session: %s\n", err)
			return UnauthorizedError(c)
		}

		c.Set("userID", userID.Value)
		c.Set("sessionID", sessionID.Value)
		return next(c)
	}
}

func (s *Server) UserSignUpHandler(c echo.Context) error {
	var user User

	err := c.Bind(&user)
	if err != nil || len(user.Email) == 0 || len(user.Password) == 0 {
		return InvalidRequestError(c)
	}

	var exists bool
	err = s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", user.Email).Scan(&exists)
	if err != nil || exists {
		fmt.Printf("User exists: %s\n", err)
		return InvalidRequestError(c)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		fmt.Printf("Could not hash password: %s\n", err)
		return InvalidRequestError(c)
	}

	_, err = s.DB.Exec("INSERT INTO users (name, email, password) VALUES($1, $2, $3)",
		user.Name, user.Email, string(hashedPassword))
	if err != nil {
		fmt.Printf("Could not create user: %s\n", err)
		return InvalidRequestError(c)
	}

	return c.JSON(200, echo.Map{"status": "User created"})
}

func (s *Server) UserSignInHandler(c echo.Context) error {
	var user User

	// Read JSON body
	err := c.Bind(&user)
	if err != nil || len(user.Email) == 0 || len(user.Password) == 0 {
		return InvalidRequestError(c)
	}

	var userID string
	var hashedPassword string
	// Check if user exists
	err = s.DB.QueryRow("SELECT user_id, password FROM users WHERE email=$1", user.Email).Scan(&userID, &hashedPassword)
	if err != nil {
		fmt.Printf("Could find user information: %s\n", err)
		return UnauthorizedError(c)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		fmt.Printf("Failed to compare password hashes: %s\n", err)
		return UnauthorizedError(c)
	}

	sessionID := uuid.New().String()
	err = s.RDB.Set(c.Request().Context(), sessionID, userID, time.Hour*24).Err()
	if err != nil {
		fmt.Printf("Failed to create user session: %s\n", err)
		return UnauthorizedError(c)
	}

	SetCookie(c, "userid", userID, time.Now().Add(time.Hour*24))
	SetCookie(c, "session", sessionID, time.Now().Add(time.Hour*24))

	return c.JSON(200, echo.Map{
		"status": "success",
	})
}

func (s *Server) UserInfoHandler(c echo.Context) error {
	userID := c.Get("userID").(string)
	var userEmail string
	var userName string
	err := s.DB.QueryRow("SELECT email, name FROM users WHERE user_id=$1", userID).Scan(&userEmail, &userName)
	if err != nil {
		fmt.Printf("Could find user information: %s\n", err)
		return UnauthorizedError(c)
	}
	return c.JSON(200, echo.Map{
		"user_id": userID,
		"email":   userEmail,
		"name":    userName,
	})
}

func (s *Server) UserSignOutHandler(c echo.Context) error {
	sessionID := c.Get("sessionID").(string)
	s.RDB.Del(c.Request().Context(), sessionID)

	SetCookie(c, "userid", "", time.Unix(0, 0))
	SetCookie(c, "session", "", time.Unix(0, 0))

	return c.JSON(201, echo.Map{"status": "success"})
}

func (s *Server) UserSessionVerify(c echo.Context) error {
	userID := c.Get("userID").(string)

	return c.JSON(200, echo.Map{
		"user_id": userID,
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	initDB(db)

	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	defer rdb.Close()

	e := echo.New()
	s := Server{
		DB:  db,
		RDB: rdb,
	}

	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_rfc3339} :: method=${method}, uri=${uri}, status=${status}, referrer=${referrer}\n",
	}))

	e.POST("/register", s.UserSignUpHandler)
	e.POST("/login", s.UserSignInHandler)
	e.POST("/logout", s.UserSignOutHandler, s.SessionMiddleware)
	e.GET("/profile", s.UserInfoHandler, s.SessionMiddleware)
	e.GET("/verify-session", s.UserSessionVerify, s.SessionMiddleware)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3030"
	}
	e.Start(":" + port)
}
