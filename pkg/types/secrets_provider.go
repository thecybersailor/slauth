package types

// SignAlgorithm JWT 签名算法
type SignAlgorithm string

const (
	SignAlgES256 SignAlgorithm = "ES256" // ECDSA P-256 (推荐)
	SignAlgRS256 SignAlgorithm = "RS256" // RSA 2048
)

// SigningKey 单个签名密钥
type SigningKey struct {
	Kid        string        // Key ID (e.g., "key-2024-01-15-v1")
	Algorithm  SignAlgorithm // ES256 or RS256
	PrivateKey string        // PEM format (签名用，为空则此密钥仅供验证)
	PublicKey  string        // PEM format (验证用，必填)
}

// InstanceSecrets 实例的所有密钥
type InstanceSecrets struct {
	// 主密钥 ID（用于签名）
	PrimaryKeyId string

	// 所有密钥（主密钥 + 轮换中的旧密钥）
	Keys map[string]*SigningKey // kid -> SigningKey

	// App 密钥（用于 HashID / RateLimit，对称密钥）
	AppSecret string
}

// InstanceSecretsProvider 由调用方实现
// slauth 通过此接口获取租户密钥
type InstanceSecretsProvider interface {
	// GetSecrets 获取指定实例的密钥
	// 返回的密钥均为明文（PEM 格式）
	GetSecrets(instanceId string) (*InstanceSecrets, error)
}