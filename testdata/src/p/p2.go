package p

import (
	"fmt"
	"log"
)

type Credentials struct {
	Username string
	ApiKey   string
	Secret   string
}

type Database struct {
	Name     string
	Password string
	Host     string
	Port     int
}

type NestedConfig struct {
	DB       Database
	Auth     Credentials
	Settings map[string]string
}

func testNestedStructs() {
	// 测试嵌套结构体
	creds := Credentials{
		Username: "admin",
		ApiKey:   "key123",
		Secret:   "secret456",
	}

	db := Database{
		Name:     "mydb",
		Password: "dbpass",
		Host:     "localhost",
		Port:     5432,
	}

	config := NestedConfig{
		DB:   db,
		Auth: creds,
		Settings: map[string]string{
			"password": "123",
			"token":    "abc",
		},
	}

	// 这些应该报错
	log.Printf("creds: %v", creds)                // want "direct struct type printing is not allowed, please specify fields explicitly"
	log.Printf("database: %+v", db)               // want "direct struct type printing is not allowed, please specify fields explicitly"
	log.Printf("full config: %#v", config)        // want "direct struct type printing is not allowed, please specify fields explicitly"
	log.Printf("auth config: %#v", config.DB)     // want "direct struct type printing is not allowed, please specify fields explicitly"
	fmt.Printf("db pass: %s", config.DB.Password) // want "potentially sensitive field 'Password' should not be logged"
	fmt.Printf("api key: %s", config.Auth.ApiKey) // want "potentially sensitive field 'ApiKey' should not be logged"
	log.Printf("settings: %v", config.Settings)   // want "direct map type printing is not allowed, please specify fields explicitly"

	// 测试指针和接口
	var iface interface{} = &creds
	log.Printf("interface: %v", iface) // want "direct struct type printing is not allowed, please specify fields explicitly"

	// 测试数组和切片
	dbs := []Database{{Name: "db1", Password: "pass1"}, {Name: "db2", Password: "pass2"}}
	log.Printf("databases: %v", dbs) // want "direct struct type printing is not allowed, please specify fields explicitly"

	// 测试map嵌套
	nestedMap := map[string]map[string]string{
		"auth": {
			"password": "pass",
			"key":      "secret",
		},
	}
	log.Printf("nested map: %v", nestedMap) // want "direct map type printing is not allowed, please specify fields explicitly"

	// 测试函数返回值
	getPassword := func() string { return "secret" }
	log.Printf("password: %s", getPassword())

	// 这些应该是安全的
	fmt.Printf("database name: %s, host: %s, port: %d", db.Name, db.Host, db.Port)
	log.Printf("number of settings: %d", len(config.Settings))
	fmt.Printf("username: %s", creds.Username)
}

type Service interface {
	GetConfig() *Config
	GetCredentials() *Credentials
}

type serviceImpl struct {
	config *Config
	creds  *Credentials
}

func (s *serviceImpl) GetConfig() *Config {
	return s.config
}

func (s *serviceImpl) GetCredentials() *Credentials {
	return s.creds
}

func testInterfaces() {
	svc := &serviceImpl{
		config: &Config{Version: "2.0", Secret: "xyz"},
		creds:  &Credentials{Username: "admin", ApiKey: "key", Secret: "secret"},
	}

	// 这些应该报错
	log.Printf("service config: %v", svc.GetConfig())      // want "direct struct type printing is not allowed, please specify fields explicitly"
	fmt.Printf("service creds: %+v", svc.GetCredentials()) // want "direct struct type printing is not allowed, please specify fields explicitly"

	var svcInterface Service = svc
	log.Printf("interface config: %v", svcInterface.GetConfig()) // want "direct struct type printing is not allowed, please specify fields explicitly"
}
