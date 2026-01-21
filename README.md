# 账号密码系统

一个完整的用户账号管理系统，支持用户注册、登录、个人信息管理、密码修改等功能。

## 功能特性

- ✅ 用户注册（邮箱和用户名验证）
- ✅ 用户登录（JWT 认证）
- ✅ 个人信息管理（查看和编辑）
- ✅ 密码修改（含原密码验证）
- ✅ 密码历史记录
- ✅ 账号登出
- ✅ 安全的密码加密（bcrypt）
- ✅ 响应式界面设计

## 技术栈

### 后端
- **Node.js** - JavaScript 运行时
- **Express.js** - Web 框架
- **SQLite** - 数据库
- **bcryptjs** - 密码加密
- **jsonwebtoken** - JWT 认证
- **CORS** - 跨域请求处理

### 前端
- **HTML5** - 标记
- **CSS3** - 样式
- **原生 JavaScript** - 交互逻辑

## 安装和运行

### 1. 安装依赖

```bash
npm install
```

### 2. 启动服务器

```bash
npm start
```

服务器将在 `http://localhost:3000` 启动

### 3. 访问应用

打开浏览器访问：
- **账号系统主页**: http://localhost:3000/auth.html
- **个人主页**: http://localhost:3000/index.html

## API 文档

### 注册
**POST** `/api/auth/register`

请求体：
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "password123",
  "confirmPassword": "password123"
}
```

响应：
```json
{
  "message": "注册成功",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

### 登录
**POST** `/api/auth/login`

请求体：
```json
{
  "username": "john_doe",
  "password": "password123"
}
```

响应：
```json
{
  "message": "登录成功",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

### 获取用户资料
**GET** `/api/auth/profile`

请求头：
```
Authorization: Bearer <token>
```

响应：
```json
{
  "id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "created_at": "2026-01-21T10:00:00.000Z"
}
```

### 修改密码
**POST** `/api/auth/change-password`

请求头：
```
Authorization: Bearer <token>
```

请求体：
```json
{
  "oldPassword": "password123",
  "newPassword": "newpassword456",
  "confirmPassword": "newpassword456"
}
```

### 获取密码历史
**GET** `/api/auth/password-history`

请求头：
```
Authorization: Bearer <token>
```

### 编辑个人信息
**PUT** `/api/auth/profile`

请求头：
```
Authorization: Bearer <token>
```

请求体：
```json
{
  "email": "newemail@example.com"
}
```

### 登出
**POST** `/api/auth/logout`

请求头：
```
Authorization: Bearer <token>
```

## 数据库结构

### users 表
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 主键，自增 |
| username | TEXT | 用户名，唯一 |
| email | TEXT | 邮箱，唯一 |
| password | TEXT | 加密后的密码 |
| created_at | DATETIME | 创建时间 |
| updated_at | DATETIME | 更新时间 |

### password_history 表
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 主键，自增 |
| user_id | INTEGER | 用户ID（外键） |
| old_password | TEXT | 修改前的密码（加密） |
| changed_at | DATETIME | 修改时间 |

## 文件结构

```
.
├── server.js              # 后端服务器
├── auth.html              # 账号系统前端
├── index.html             # 个人主页
├── package.json           # NPM 配置
├── .env                   # 环境变量
├── .gitignore             # Git 忽略文件
├── database.db            # SQLite 数据库（自动生成）
└── README.md              # 本文件
```

## 开发建议

- 修改 `.env` 文件中的 `JWT_SECRET` 为更强的密钥（生产环境）
- 添加数据验证和错误处理的详细日志
- 考虑实现邮箱验证功能
- 添加找回密码功能
- 实现账号锁定（多次登录失败）
- 使用 HTTPS（生产环境）

## 安全性注意

1. **密码加密**：使用 bcryptjs 对密码进行加密存储
2. **JWT 认证**：使用 JWT 实现无状态认证
3. **CORS**：正确配置 CORS 以防止跨域攻击
4. **验证**：在后端对所有输入进行验证
5. **HTTPS**：生产环境必须使用 HTTPS

## 许可证

MIT
