# 自动化测试文档

## 概述

本目录包含了针对 `pkg/controller/routes.go` 中所有 Handler 的自动化测试。测试使用真实的数据库连接，确保测试的准确性和可靠性。

## 测试结构

```
tests/
├── setup_test.go           # 测试套件基础设置
├── helpers_test.go         # 测试辅助函数
├── signup_test.go          # 用户注册测试
├── mock_providers.go       # Mock提供者实现
└── README.md              # 本文档
```

## 任务要求
- 做完一个，才能做下一个，不要追求快速推进

## 测试原则

- 每个测试，都要测试完整真实数据链路
- 测试用例需要标注对应的前端API文件地址
- 错误信息要参考前端API和 `pkg/consts/errors.go`
- 行为逻辑需要参考 `pkg/config/` 配置

## 测试工具说明

### 1. MatchObject 函数
用于验证API响应是否包含期望的字段和值。支持部分匹配，只检查指定字段：

```go
suite.helper.MatchObject(suite.T(), response, S{
    "user": S{
        "email": email,
        "id":    "1",
    },
    "session": nil,
})
```

### 2. HasError 函数
用于验证API返回错误响应，检查错误类型是否符合预期：

```go
suite.helper.HasError(suite.T(), response, "user_already_exists")
```

### 3. Mock提供者
- **MockEmailProvider**: 模拟邮件发送，记录发送的邮件内容
- **MockSMSProvider**: 模拟短信发送，记录发送的短信内容

这些Mock提供者在测试setup阶段自动配置，避免实际发送邮件/短信。

## 配置参考

### 服务配置 (pkg/config/service.go)
- `AllowNewUsers`: 控制是否允许新用户注册
- `ConfirmEmail`: 控制是否需要邮箱确认
- `MaxTimeAllowedForAuthRequest`: 认证请求超时时间

### 会话配置 (pkg/config/session.go)
- `AccessTokenTTL`: 访问令牌有效期
- `RefreshTokenTTL`: 刷新令牌有效期

### 速率限制 (pkg/config/ratelimit.go)
- `SignUpSignInRateLimit`: 注册登录速率限制
- `EmailRateLimit`: 邮件发送速率限制

## 数据库验证

所有测试都使用真实的数据库查询进行验证：

```go

var countAfter int64
err = suite.DB.Raw("SELECT COUNT(*) FROM users WHERE email = ? AND instance_id = ?", 
    email, suite.TestInstance).Scan(&countAfter).Error
suite.Require().NoError(err)
suite.Equal(int64(1), countAfter, "User should exist after signup")
```

## Mock提供者使用

测试环境自动配置Mock提供者，可以验证邮件/短信发送：

```go

lastEmail := suite.EmailProvider.GetLastEmail()
suite.NotNil(lastEmail)
suite.Equal("test@example.com", lastEmail.To)
suite.Contains(lastEmail.Subject, "Confirm your signup")
```