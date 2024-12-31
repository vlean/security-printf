package p

import (
	"fmt"
	"log"
)

type User struct {
	Name     string
	Age      int
	Password string
	Token    string
}

type Config struct {
	Version string
	Secret  string
}

func _() {
	// 测试敏感字段
	user := User{
		Name:     "John",
		Age:      30,
		Password: "secret123",
		Token:    "abc123",
	}

	config := &Config{
		Version: "1.0",
		Secret:  "xyz789",
	}
	// 测试复合类型
	users := []User{{Name: "John", Password: "123"}}
	log.Printf("users: %v", users) // want "direct struct type printing is not allowed, please specify fields explicitly"

	// 这些应该报错
	log.Printf("user data: %v", user)          // want "direct struct type printing is not allowed, please specify fields explicitly"
	fmt.Printf("password: %s", user.Password)  // want "potentially sensitive field 'Password' should not be logged"
	fmt.Printf("user token is %s", user.Token) // want "potentially sensitive field 'Token' should not be logged"
	fmt.Printf("config: %+v", config)          // want "direct struct type printing is not allowed, please specify fields explicitly"

	// 测试 map
	sensitiveMap := map[string]string{
		"username": "john",
		"password": "secret",
	}
	log.Printf("map data: %v", sensitiveMap)           // want "direct map type printing is not allowed, please specify fields explicitly"
	log.Printf("secret: %s", sensitiveMap["password"]) // want "potentially sensitive field 'password' should not be logged"

	// 测试变量名
	userPassword := "secret123"
	authToken := "xyz789"
	log.Printf("auth: %s", userPassword) // want "potentially sensitive field 'userPassword' should not be logged"
	fmt.Printf("token: %s", authToken)   // want "potentially sensitive field 'authToken' should not be logged"

	// 这些应该是安全的
	log.Printf("user name: %s, age: %d", user.Name, user.Age)
	fmt.Printf("config version: %s", config.Version)
	log.Printf("map size: %d", len(sensitiveMap))
	fmt.Printf("Hello, %s!", user.Name)

}
